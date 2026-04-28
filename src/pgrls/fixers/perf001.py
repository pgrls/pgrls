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

from typing import Any

from pglast.ast import FuncCall, Node, String, SubLink
from pglast.stream import RawStream

from pgrls.ast_utils import parse_expr
from pgrls.fixers import Fix
from pgrls.fixers._idents import quote_ident, quote_qualified
from pgrls.model import Schema

_DEFAULT_AUTH_FUNCTIONS: tuple[str, ...] = (
    "auth.uid",
    "auth.role",
    "auth.jwt",
    "current_setting",
)


def _parse_auth_functions(options: dict[str, Any]) -> set[str]:
    raw = options.get("auth_functions")
    if raw is None:
        return set(_DEFAULT_AUTH_FUNCTIONS)
    if not isinstance(raw, list) or not all(isinstance(s, str) for s in raw):
        # Match PERF001's check; fall back to default rather than fix.
        return set(_DEFAULT_AUTH_FUNCTIONS)
    return set(raw)


def _allowlist(options: dict[str, Any]) -> set[str]:
    raw = options.get("allowlist", [])
    if not isinstance(raw, list):
        return set()
    return {s for s in raw if isinstance(s, str)}


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
    """Build a SubLink wrapping a FuncCall by reusing a parsed
    template. Cheaper and safer than constructing the SubLink /
    SelectStmt fields by hand."""
    template = parse_expr("(SELECT NULL)")
    template.subselect.targetList[0].val = funccall
    return template


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
        skip = _allowlist(options)

        out: list[Fix] = []
        for table in schema.tables:
            for policy in table.policies:
                if policy.using_ast is None:
                    continue
                policy_id = (
                    f"{table.schema}.{table.name}.{policy.name}"
                )
                if policy_id in skip:
                    continue

                new_using_ast, changed = _wrap_unwrapped_calls(
                    policy.using_ast, names
                )
                if not changed:
                    continue

                new_using_sql = RawStream()(new_using_ast)
                stmt = (
                    f"ALTER POLICY {quote_ident(policy.name)} "
                    f"ON {quote_qualified(table.schema, table.name)}\n"
                    f"    USING ({new_using_sql})"
                )
                if policy.with_check_sql is not None:
                    stmt += f"\n    WITH CHECK ({policy.with_check_sql})"
                stmt += ";"

                out.append(
                    Fix(
                        rule_id="PERF001",
                        location=policy_id,
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
