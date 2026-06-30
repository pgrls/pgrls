"""PERF001 fixer — wrap unwrapped auth calls in `(SELECT …)` and
emit an `ALTER POLICY` statement.

The rewrite walks the policy's USING expression AST. Each FuncCall
matching the rule's auth_functions set is replaced with a SubLink
wrapping it — `auth.uid()` becomes `(SELECT auth.uid())`. The
SubLink's `testexpr` (the LHS of `x IN (SELECT …)` / `ANY` / `ALL`)
IS walked — an unwrapped auth call there re-evaluates per row. An
UNCORRELATED subselect is skipped (a call inside it already runs
once), but a CORRELATED subselect IS descended into — an unwrapped
auth call inside `EXISTS (SELECT … WHERE … = t.col AND … =
auth.uid())` re-evaluates per outer row, so PERF001's rule flags it
and the fixer must wrap it. This mirrors
`ast_utils.find_func_calls(descend_correlated_sublinks=True)`, which
the rule uses.

`SQLValueFunction` nodes (`current_user`, `session_user`) are
intentionally NOT wrapped: see `_funccall_matches` for the
rationale. PERF001's *check* walks them; the fixer does not.

The new SQL is round-tripped via `pglast.stream.RawStream`. Output
emits only the clause(s) actually rewritten:

    ALTER POLICY <name> ON <schema>.<table>
        [USING (<new USING>)]
        [WITH CHECK (<new WITH CHECK>)];

Both USING and WITH CHECK are in scope — the rule fires on an
unwrapped auth call in either, so the fixer rewrites either. A bare
`auth.uid()` in WITH CHECK is re-evaluated per written row exactly
like USING (see `pgrls.rules.perf001`'s module docstring for the
empirical confirmation). A clause with no unwrapped call is omitted,
never re-emitted: `ALTER POLICY ... USING (x)` replaces just that
clause, so re-emitting an unchanged one would clobber — silently
revert — a fix another fixer made on it in the same migration
(SEC020's mirror, SEC011's strip). `Fix.clauses` records exactly
which clauses this emits, and `generate_fixes` keeps one writer per
(policy, clause): a narrowing fixer (SEC011/SEC020) rewriting the
same clause wins, and PERF001's wrap re-fires on the next run.

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

from pgrls.ast_utils import subselect_is_correlated
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
        # The SubLink's `testexpr` (the LHS of `x IN (SELECT …)` /
        # `ANY` / `ALL`) is the policy's own expression, NOT inside the
        # subquery: an unwrapped `auth.uid() IN (SELECT …)` re-evaluates
        # the auth call per row, so rewrite it. The subselect is a
        # `(SELECT …)`: a call inside an UNCORRELATED one already runs
        # once and is left alone, but a CORRELATED subselect re-executes
        # per outer row — an unwrapped auth call inside
        # `EXISTS (SELECT … WHERE … = t.col AND … = auth.uid())`
        # re-evaluates per row and must be wrapped too. Mirrors
        # `ast_utils.find_func_calls(descend_correlated_sublinks=True)`,
        # which the rule uses. A freshly-wrapped `(SELECT auth.uid())`
        # is uncorrelated, so re-running the fixer is idempotent.
        changed = False
        if node.testexpr is not None:
            new_testexpr, t_changed = _wrap_unwrapped_calls(
                node.testexpr, names
            )
            if t_changed:
                node.testexpr = new_testexpr
                changed = True
        if node.subselect is not None and subselect_is_correlated(
            node.subselect
        ):
            new_sub, s_changed = _wrap_unwrapped_calls(node.subselect, names)
            if s_changed:
                node.subselect = new_sub
                changed = True
        return node, changed
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
                pid = policy_id(table, policy)
                if pid in skip:
                    continue

                # `_wrap_unwrapped_calls` mutates pglast Node fields in
                # place (setattr via setitem on tuple-of-children
                # parents). Policy is a frozen dataclass but
                # `frozen=True` does NOT freeze the AST node graph it
                # holds — so work on a deepcopy per clause. Without it
                # the fixer would visibly alter `policy.using_ast` /
                # `with_check_ast` for any rule that re-walks the Schema
                # after `pgrls fix` runs (snapshot tests, programmatic
                # API, the `pgrls fix && pgrls lint` chain). The invariant
                # is "fixer is read-only over Schema"; honor it.
                new_clauses: dict[str, str] = {}
                for key, ast in (
                    ("using", policy.using_ast),
                    ("with_check", policy.with_check_ast),
                ):
                    if ast is None:
                        continue
                    new_ast, changed = _wrap_unwrapped_calls(
                        copy.deepcopy(ast), names
                    )
                    if changed:
                        new_clauses[key] = RawStream()(new_ast)
                if not new_clauses:
                    continue

                # Emit ONLY the clause(s) actually rewritten. An
                # `ALTER POLICY ... USING (x)` replaces just that clause
                # and leaves the other untouched, so re-emitting an
                # unchanged clause would gain nothing AND clobber —
                # silently reverting — a fix another fixer made on it in
                # the same migration (SEC020's mirror, SEC011's strip).
                # `Fix.clauses` lets `generate_fixes` keep one writer per
                # (policy, clause); see that module's docstring.
                lines = [
                    f"ALTER POLICY {quote_ident(policy.name)} "
                    f"ON {quote_qualified(table.schema, table.name)}"
                ]
                if "using" in new_clauses:
                    lines.append(f"    USING ({new_clauses['using']})")
                if "with_check" in new_clauses:
                    lines.append(
                        f"    WITH CHECK ({new_clauses['with_check']})"
                    )
                stmt = "\n".join(lines) + ";"

                out.append(
                    Fix(
                        rule_id="PERF001",
                        location=pid,
                        sql=stmt,
                        clauses=frozenset(new_clauses),
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
