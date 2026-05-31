"""PERF001 fixer — wrap unwrapped auth calls in `(SELECT …)` and
emit an `ALTER POLICY` statement.

The rewrite walks the policy's USING expression AST. Each FuncCall
matching the rule's auth_functions set is replaced with a SubLink
wrapping it — `auth.uid()` becomes `(SELECT auth.uid())`. SubLinks
already in the tree are skipped so already-wrapped calls stay as
they are.

`SQLValueFunction` nodes (`current_user`, `session_user`) are
intentionally NOT wrapped: see `_funccall_matches` for the
rationale. PERF001's *check* walks them; the fixer does not.

The new SQL is round-tripped via `pglast.stream.RawStream`. Output:

    ALTER POLICY <name> ON <schema>.<table>
        USING (<new expression>)
        [WITH CHECK (<original with-check>)];

WITH CHECK is preserved verbatim — PERF001's scope is USING-only,
matching the rule's check shape. Unwrapped auth calls in WITH CHECK
are left alone because PERF001's check doesn't fire on them either
(see `tests/rules/test_perf001.py::test_perf001_does_not_fire_on_with_check_only`).
A future PERF003 (or a wider PERF001 scope) could fix WITH CHECK
too; today, this fixer mirrors the rule's USING-only scope so the
"fixer fixes exactly what the rule reports" contract holds.

Identifiers are double-quoted via `_idents.quote_ident` /
`_idents.quote_qualified` when Postgres syntax requires it (mixed
case, embedded special chars). Plain `snake_case` names are emitted
bare for readability.
"""
from __future__ import annotations

import copy
from typing import Any

from pglast.ast import FuncCall, Node, ResTarget, SelectStmt, String, SubLink
from pglast.enums import LimitOption, SetOperation, SubLinkType
from pglast.stream import RawStream

from pgrls.fixers import Fix
from pgrls.fixers._idents import quote_ident, quote_qualified
from pgrls.model import Schema, policy_id
from pgrls.rules._allowlist import parse_policy_id_allowlist
# Single source of truth for the default auth-function set —
# imported from the rule so a future addition (e.g.
# `app.current_user_id`) to the rule's defaults can't silently
# miss the fixer. The fixer fixes exactly what the rule reports.
from pgrls.rules.perf001 import _DEFAULT_AUTH_FUNCTIONS

def _parse_auth_functions(options: dict[str, Any]) -> set[str]:
    raw = options.get("auth_functions")
    if raw is None:
        return set(_DEFAULT_AUTH_FUNCTIONS)
    if not isinstance(raw, list) or not all(isinstance(s, str) for s in raw):
        # Match PERF001's check; fall back to default rather than fix.
        return set(_DEFAULT_AUTH_FUNCTIONS)
    return set(raw)


def _funccall_matches(node: Any, names: set[str]) -> bool:
    """True if `node` is a `FuncCall` whose name is in `names`.

    Deliberately ignores `SQLValueFunction` (Postgres's grammar
    special for `current_user`, `session_user`, etc.) — those
    aren't valid as the body of a `(SELECT …)` SubLink the way a
    regular `FuncCall` is, so the fixer can't safely wrap them.
    PERF001's *check* DOES walk SQLValueFunctions for completeness;
    a user who overrides `auth_functions = ["current_user"]` will
    see the rule fire but no fix emitted. Documented in the
    `pgrls fix` docstring; intentional asymmetry with the rule.
    """
    if not isinstance(node, FuncCall):
        return False
    parts: list[str] = []
    for f in node.funcname or ():
        if isinstance(f, String):
            parts.append(f.sval)
    if not parts:
        return False
    qualified = ".".join(parts)
    bare = parts[-1]
    return qualified in names or bare in names


def _wrap_funccall(funccall: FuncCall) -> SubLink:
    """Build a SubLink wrapping a FuncCall via direct construction.

    Three strategies were measured on a 10K-call benchmark:

      direct construction:   ~7 µs/call  (this code)
      parse_expr + replace:  ~20 µs/call
      deepcopy + replace:    ~35 µs/call (previous implementation)

    deepcopy on a 13-node pglast tree is more expensive than
    re-parsing four-token SQL, contrary to the intuition that
    drove the original cached-template optimization. Direct
    construction is ~5x faster than deepcopy and produces a
    SubLink with the same RawStream output: `(SELECT auth.uid())`.
    Pinned by `tests/test_fixers.py::test_wrap_funccall_emits_select_sublink`.
    """
    return SubLink(
        subLinkType=SubLinkType.EXPR_SUBLINK,
        subLinkId=0,
        subselect=SelectStmt(
            targetList=(ResTarget(val=funccall),),
            op=SetOperation.SETOP_NONE,
            all=False,
            limitOption=LimitOption.LIMIT_OPTION_DEFAULT,
        ),
    )


def _wrap_unwrapped_calls(node: Any, names: set[str]) -> tuple[Any, bool]:
    """Replace each matching FuncCall outside any SubLink with a
    SubLink wrapping it.

    Mutates `node` in place when descendants need wrapping (the
    parent's field is reassigned via `setattr`). The returned
    node is the SAME object — `did_change` is the caller's signal
    to re-emit the SQL, not an indication of replacement.
    """
    if node is None:
        return node, False
    if _funccall_matches(node, names):
        return _wrap_funccall(node), True
    if isinstance(node, SubLink):
        # Already wrapped — leave the inside alone.
        return node, False
    if not isinstance(node, Node):
        return node, False

    changed = False
    for field_name in node:
        value = getattr(node, field_name, None)
        if isinstance(value, (list, tuple)):
            new_items: list[Any] = []
            list_changed = False
            for item in value:
                new_item, item_changed = _wrap_unwrapped_calls(item, names)
                new_items.append(new_item)
                list_changed = list_changed or item_changed
            if list_changed:
                setattr(
                    node,
                    field_name,
                    type(value)(new_items),
                )
                changed = True
        elif isinstance(value, Node):
            new_v, v_changed = _wrap_unwrapped_calls(value, names)
            if v_changed:
                setattr(node, field_name, new_v)
                changed = True
    return node, changed


class PERF001Fixer:
    rule_id: str = "PERF001"

    def fix(
        self, schema: Schema, options: dict[str, Any]
    ) -> list[Fix]:
        names = _parse_auth_functions(options)
        # Strict allowlist parsing (the same parser PERF001 uses):
        # a malformed allowlist raises, surfaced by the `fix` CLI.
        skip = parse_policy_id_allowlist("PERF001", options)

        out: list[Fix] = []
        for table in schema.tables:
            for policy in table.policies:
                if policy.using_ast is None:
                    continue
                pid = policy_id(table, policy)
                if pid in skip:
                    continue

                # `_wrap_unwrapped_calls` mutates pglast Node
                # fields in place (setattr via setitem on tuple-
                # of-children parents). Policy is a frozen
                # dataclass but `frozen=True` does NOT freeze the
                # AST node graph it holds. Without the deepcopy
                # here, the fixer would visibly alter
                # `policy.using_ast` for any rule that re-walks
                # the Schema after `pgrls fix` runs (snapshot
                # tests, programmatic API, future
                # `pgrls fix && pgrls lint` chain). The
                # invariant is "fixer is read-only over Schema";
                # honor it by working on a copy.
                ast_copy = copy.deepcopy(policy.using_ast)
                new_using_ast, changed = _wrap_unwrapped_calls(
                    ast_copy, names
                )
                if not changed:
                    continue

                new_using_sql = RawStream()(new_using_ast)
                stmt = (
                    f"ALTER POLICY {quote_ident(policy.name)} "
                    f"ON {quote_qualified(table.schema, table.name)}\n"
                    f"    USING ({new_using_sql})"
                )
                if policy.with_check_ast is not None:
                    # Round-trip WITH CHECK through RawStream too so
                    # the emission uses pglast's escaping consistently
                    # — symmetric with USING. A future change that
                    # sources `with_check_sql` from somewhere other
                    # than `pg_get_expr` (config override, snapshot
                    # file, hand-edited fixture) doesn't bypass the
                    # round-trip and become an injection vector.
                    new_with_check_sql = RawStream()(policy.with_check_ast)
                    stmt += f"\n    WITH CHECK ({new_with_check_sql})"
                stmt += ";"

                out.append(
                    Fix(
                        rule_id="PERF001",
                        location=pid,
                        sql=stmt,
                        description=(
                            f"Wrap auth function call(s) in policy "
                            f"{policy.name!r} on "
                            f"{table.qualified_name} so Postgres can "
                            "cache the result for the whole statement "
                            "instead of re-evaluating per row."
                        ),
                    )
                )
        return out
