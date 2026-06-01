"""SEC037 — Policy compares `auth.role()` to an unknown role name.

In the Supabase / PostgREST auth model, `auth.role()` returns one of
a small, fixed set of role names from the JWT — by default `anon`,
`authenticated`, or `service_role`. A policy that compares
`auth.role()` to a string outside that set silently denies every
row, because the equality never holds:

    USING (auth.role() = 'admin')       -- never matches → policy denies
    USING (auth.role() = 'authorized')  -- typo / wrong constant
    USING (auth.role() = 'authenticted') -- one-character typo, silent deny

The failure mode is a 100% empty result set. That masks the broken
policy because tests that seed admin data see no rows, devs assume
the policy works, the table becomes inaccessible in production.

Severity is `warning`: not a CVE-class exploit, but a silent-deny
footgun that's worth surfacing in CI. The fix is usually to gate on
`app_metadata.role` (Supabase's admin-only custom-role channel)
instead of redefining `auth.role()`'s contract:

    -- intended pattern for an "admin" custom role:
    USING (auth.jwt() -> 'app_metadata' ->> 'role' = 'admin')

Detection: walks policy USING / WITH CHECK ASTs for binary `=`
A_Expr comparisons where one side is a `FuncCall` to `auth.role`
(configurable) and the other is a string literal not in the
configured known-role set (default `{anon, authenticated,
service_role}`). Fires once per *distinct* unknown literal in the policy. Two
comparisons in the same policy with the *same* unknown literal
collapse to a single finding (same fix). Two comparisons with
*different* unknown literals yield two findings (the fix for each
is usually distinct — they were typos for different intended roles).
A literal that appears in both USING and WITH CHECK clauses also
dedupes to one finding.

Configuration: `[lint.rules.SEC037]` accepts:

  - `known_roles` (list[str]) — string literals to consider valid
    when on the RHS/LHS of `auth.role() = '…'`. Replaces the
    default `["anon", "authenticated", "service_role"]`. Add any
    project-specific role values you've documented (`["anon",
    "authenticated", "service_role", "guest", "premium"]`).
  - `role_functions` (list[str]) — function names whose call
    counts as a `auth.role()` reference. Replaces the default
    `["auth.role"]`. Add `current_user` if you want to flag the
    same shape against the session-role check (a different rule,
    SEC018, also covers `current_user` as a tenant key).
  - `allowlist` (list[str]) — `schema.table.policy` IDs to exempt
    (audit-policy fallbacks, etc.).
"""
from __future__ import annotations

from typing import Any

from pglast.ast import (
    A_Const,
    A_Expr,
    FuncCall,
    Node,
    SQLValueFunction,
    String,
    TypeCast,
)
from pglast.enums import A_Expr_Kind, SQLValueFunctionOp

from pgrls.model import Schema
from pgrls.rules._allowlist import parse_policy_id_allowlist
from pgrls.violations import Severity, Violation


_DEFAULT_KNOWN_ROLES: frozenset[str] = frozenset({
    "anon",
    "authenticated",
    "service_role",
})

_DEFAULT_ROLE_FUNCTIONS: frozenset[str] = frozenset({"auth.role"})


def _parse_known_roles(options: dict[str, Any]) -> set[str]:
    raw = options.get("known_roles")
    if raw is None:
        return set(_DEFAULT_KNOWN_ROLES)
    if not isinstance(raw, list) or not all(isinstance(s, str) for s in raw):
        raise TypeError(
            "[lint.rules.SEC037].known_roles must be a list of role-name "
            'strings, e.g. ["anon", "authenticated", "service_role"]'
        )
    # Role-name comparison is case-sensitive — JWT claim values are
    # not folded. `'admin'` and `'Admin'` are distinct values.
    return set(raw)


def _parse_role_functions(options: dict[str, Any]) -> set[str]:
    raw = options.get("role_functions")
    if raw is None:
        return set(_DEFAULT_ROLE_FUNCTIONS)
    if not isinstance(raw, list) or not all(isinstance(s, str) for s in raw):
        raise TypeError(
            "[lint.rules.SEC037].role_functions must be a list of "
            "function names (qualified or bare), e.g. "
            '["auth.role"]'
        )
    return set(raw)


def _is_equality(node: A_Expr) -> bool:
    """True if `node` is a plain binary `=` operator expression."""
    name = node.name
    return (
        node.kind == A_Expr_Kind.AEXPR_OP
        and name is not None
        and len(name) == 1
        and isinstance(name[0], String)
        and name[0].sval == "="
    )


def _is_in_list(node: A_Expr) -> bool:
    """True if `node` is an `IN (...)` / `NOT IN (...)` list expression.

    Postgres parses `x IN (a, b)` as an `A_Expr` of kind `AEXPR_IN`
    whose `name` is `=` (and `<>` for `NOT IN`); `lexpr` is the tested
    value and `rexpr` is the tuple of list elements. `auth.role() IN
    ('admin', 'editor')` is the same always-false silent-deny shape as
    `auth.role() = 'admin' OR auth.role() = 'editor'` when every listed
    value is an unknown role, so it needs the same treatment.
    """
    # `A_Expr.kind` is typed `Any` by pglast — wrap in bool() so
    # mypy --strict doesn't flag a `no-any-return`.
    return bool(node.kind == A_Expr_Kind.AEXPR_IN)


# Mirror of `_SQL_VALUE_FUNCTION_NAMES` in `pgrls.ast_utils` —
# Postgres parses `current_user`, `session_user`, etc. as
# `SQLValueFunction` nodes (a separate AST node class from `FuncCall`),
# so the role-call check has to recognize both shapes.
_SVFOP_NAMES: dict[Any, str] = {
    SQLValueFunctionOp.SVFOP_CURRENT_USER: "current_user",
    SQLValueFunctionOp.SVFOP_SESSION_USER: "session_user",
    SQLValueFunctionOp.SVFOP_USER: "user",
    SQLValueFunctionOp.SVFOP_CURRENT_ROLE: "current_role",
}


def _qualified_func_name(func: FuncCall) -> str:
    """Return `auth.role` or `auth` etc. — qualified-or-bare form.

    Mirrors the convention used by `find_func_calls` in ast_utils:
    a `FuncCall` whose `funcname` is `(String('auth'), String('role'))`
    renders to `auth.role`; a bare `current_user` renders to
    `current_user`.
    """
    if func.funcname is None:
        return ""
    parts = [n.sval for n in func.funcname if isinstance(n, String)]
    return ".".join(parts)


def _is_role_call(node: Any, role_functions: set[str]) -> bool:
    """True if `node` is a role-context function reference.

    Recognizes two AST shapes:
    - `FuncCall` for explicit calls like `auth.role()`.
    - `SQLValueFunction` for the SQL keyword forms `current_user`,
      `session_user`, `user`, `current_role` — Postgres parses
      these without parentheses into a separate node class.
    """
    if isinstance(node, SQLValueFunction):
        name = _SVFOP_NAMES.get(node.op)
        return name is not None and name in role_functions
    if not isinstance(node, FuncCall):
        return False
    qual = _qualified_func_name(node)
    if qual in role_functions:
        return True
    # Match bare last-component too — `auth.role` config also matches
    # an unqualified `role()` call (uncommon but valid).
    bare = qual.split(".")[-1] if "." in qual else qual
    return bare in role_functions


def _unwrap_typecast(node: Any) -> Any:
    """Strip surrounding `TypeCast` wrappers.

    Postgres normalizes `'admin'` to `'admin'::text` when storing
    policy expressions in `pg_policy.polqual` — what
    `pg_get_expr(polqual, …)` and pglast re-parse as a
    `TypeCast(arg=A_Const(String))`, not a bare `A_Const`. Strip
    any number of nested casts so the inner `A_Const` is reachable.
    """
    while isinstance(node, TypeCast):
        node = node.arg
    return node


def _is_string_const(node: Any) -> str | None:
    """Return the string value if `node` is a string literal, else None.

    Accepts both bare `A_Const(String)` (what a hand-written test
    fixture parses to) and `TypeCast(arg=A_Const(String))` (what the
    introspection round-trip via `pg_get_expr` produces).
    """
    unwrapped = _unwrap_typecast(node)
    if isinstance(unwrapped, A_Const) and isinstance(unwrapped.val, String):
        # `String.sval` is typed `Any` by pglast — cast explicitly so
        # mypy --strict doesn't flag the return as `Any`.
        return str(unwrapped.val.sval)
    return None


def _find_unknown_role_comparisons(
    tree: Any,
    *,
    role_functions: set[str],
    known_roles: set[str],
) -> list[str]:
    """Find every `auth.role() = '<unknown>'` (or reversed / `IN`) comparison.

    Returns the unknown-role literals encountered (one entry per
    offending literal; same literal may appear twice for two distinct
    comparisons in the same policy). Covers both the binary `=`/`<>`
    shape and the `auth.role() IN ('a', 'b')` list shape — each unknown
    list element is reported just like a standalone `= 'unknown'`.
    """
    hits: list[str] = []

    def walk(n: Any) -> None:
        if n is None:
            return
        if isinstance(n, (list, tuple)):
            for item in n:
                walk(item)
            return
        if isinstance(n, A_Expr) and _is_equality(n):
            lhs, rhs = n.lexpr, n.rexpr
            # Either side might be the role-call; the other side
            # is the string literal we're testing for membership.
            for role_side, lit_side in ((lhs, rhs), (rhs, lhs)):
                if _is_role_call(role_side, role_functions):
                    sval = _is_string_const(lit_side)
                    if sval is not None and sval not in known_roles:
                        hits.append(sval)
                    # Don't double-count if the comparison happens to
                    # be `auth.role() = auth.role()` — neither side
                    # has a literal so `_is_string_const` returns
                    # None and we don't append.
                    break
        elif isinstance(n, A_Expr) and _is_in_list(n):
            # `auth.role() IN ('admin', 'editor')`: the tested value is
            # `lexpr`, the list is `rexpr`. Only the value side can be
            # the role call (the list holds the candidate literals).
            # Each list element outside the known set is its own
            # unknown-role hit, mirroring the per-disjunct `=` path.
            if _is_role_call(n.lexpr, role_functions):
                elements = n.rexpr if isinstance(n.rexpr, (list, tuple)) else ()
                for element in elements:
                    sval = _is_string_const(element)
                    if sval is not None and sval not in known_roles:
                        hits.append(sval)
        if isinstance(n, Node):
            for field_name in n:
                walk(getattr(n, field_name, None))

    walk(tree)
    return hits


class SEC037:
    id: str = "SEC037"
    severity: Severity = "warning"
    title: str = (
        "Policy compares auth.role() to an unknown role name (silent deny)"
    )

    def check(
        self, schema: Schema, options: dict[str, Any]
    ) -> list[Violation]:
        known_roles = _parse_known_roles(options)
        role_functions = _parse_role_functions(options)
        allowlist = parse_policy_id_allowlist("SEC037", options)

        out: list[Violation] = []
        for table in schema.tables:
            for policy in table.policies:
                policy_id = f"{table.schema}.{table.name}.{policy.name}"
                if policy_id in allowlist:
                    continue
                trees = [
                    t
                    for t in (policy.using_ast, policy.with_check_ast)
                    if t is not None
                ]
                # De-duplicate by literal: if the same `'admin'`
                # appears in both USING and WITH CHECK clauses of
                # the same policy, that's still one mistake.
                seen: set[str] = set()
                for tree in trees:
                    for unknown in _find_unknown_role_comparisons(
                        tree,
                        role_functions=role_functions,
                        known_roles=known_roles,
                    ):
                        if unknown in seen:
                            continue
                        seen.add(unknown)
                        out.append(
                            Violation(
                                rule_id="SEC037",
                                severity="warning",
                                title=self.title,
                                message=(
                                    f"Policy {policy.name!r} on "
                                    f"{table.qualified_name} compares "
                                    f"auth.role() to the unknown "
                                    f"value {unknown!r}. The known set "
                                    "is {anon, authenticated, "
                                    "service_role} (configurable via "
                                    "[lint.rules.SEC037].known_roles). "
                                    "An auth.role() check against "
                                    "anything outside that set never "
                                    "matches and silently denies every "
                                    "row — masking the broken policy "
                                    "because tests that seed data see "
                                    "no rows. To gate on a project-"
                                    "specific role, use the "
                                    "service-role-set app_metadata "
                                    "channel instead "
                                    "(auth.jwt() -> 'app_metadata' "
                                    "->> 'role'), or extend "
                                    "known_roles if you have an "
                                    "intentional override."
                                ),
                                location=policy_id,
                            )
                        )
        return out
