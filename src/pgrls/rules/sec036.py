"""SEC036 — Policy EXISTS sub-select against auth.users with no user binding.

The exploit is a one-line omission. The correct shape:

    USING (EXISTS (SELECT 1 FROM auth.users
                   WHERE id = auth.uid()
                     AND raw_app_meta_data ->> 'role' = 'admin'))

— a per-user admin check. The buggy variant drops the
`id = auth.uid()` clause:

    USING (EXISTS (SELECT 1 FROM auth.users
                   WHERE raw_app_meta_data ->> 'role' = 'admin'))

— which evaluates to "is there ANY admin in the system?" rather than
"is the CALLING user an admin." If there's any admin at all, every
authenticated user passes. The SQL still parses, the test passes
when an admin is present in the test DB, the production exploit is
silent.

Severity is `error` because the bypass is deterministic and bypasses
the policy for every authenticated user as soon as the sub-select's
condition is met for any single user-table row.

Detection walks policy USING / WITH CHECK ASTs for `SubLink` nodes
whose `subLinkType` is `EXISTS_SUBLINK`. For each, it inspects the
sub-select's `fromClause` for `RangeVar`s matching the configured
target tables (default: `auth.users`). If any match, the
sub-select's `whereClause` is searched for a reference to a
caller-binding signal — by default any FuncCall whose name is
`auth.uid`, `auth.role`, `auth.jwt`, `current_user`, `session_user`,
or `current_setting`. Absent any such reference, the rule fires.

The `IN (SELECT ...)` / `ANY (SELECT ...)` variant against
`auth.users` is a related but distinct hazard class (the outer
`testexpr` already binds an outer-row column to the sub-result, so
the failure mode is different — "show rows whose owner is any
admin" vs "show all rows if any admin exists"). It's deferred to a
separate rule; SEC036 only covers `EXISTS`.

Configuration: `[lint.rules.SEC036]` accepts:

  - `target_tables` (list[str]) — `schema.table` references whose
    use in an EXISTS sub-select triggers the user-binding check.
    Replaces the default `["auth.users"]`. Add project-specific
    user tables (e.g. `["auth.users", "public.profiles"]`).
  - `binding_functions` (list[str]) — function names whose presence
    in the sub-select's WHERE clause counts as a caller-binding
    signal. Replaces the default
    `{auth.uid, auth.role, auth.jwt, current_user, session_user,
    current_setting}`.
  - `allowlist` (list[str]) — `schema.table.policy` IDs to exempt
    (e.g. an audit-write policy that genuinely wants to assert "any
    admin exists" rather than "this caller is an admin").

No auto-fix. The mechanical rewrite would be "add
`id = auth.uid() AND` to the WHERE clause", but `id` is not always
the user-key column name (some auth schemas use `user_id`,
`sub`, etc.), and prepending to an arbitrary BoolExpr risks
re-associating operator precedence. The finding message tells the
operator what to add; the edit is a single line.
"""
from __future__ import annotations

from typing import Any

from pglast.ast import (
    JoinExpr,
    Node,
    RangeSubselect,
    RangeVar,
    SelectStmt,
    SubLink,
)
from pglast.enums import SubLinkType

from pgrls.ast_utils import find_func_calls
from pgrls.model import Schema, policy_id
from pgrls.rules._allowlist import parse_policy_id_allowlist
from pgrls.violations import Severity, Violation


_DEFAULT_TARGET_TABLES: frozenset[tuple[str, str]] = frozenset({
    ("auth", "users"),
})

_DEFAULT_BINDING_FUNCTIONS: frozenset[str] = frozenset({
    "auth.uid",
    "auth.role",
    "auth.jwt",
    "current_user",
    "session_user",
    "current_setting",
})


def _parse_target_tables(options: dict[str, Any]) -> set[tuple[str, str]]:
    raw = options.get("target_tables")
    if raw is None:
        return set(_DEFAULT_TARGET_TABLES)
    if not isinstance(raw, list) or not all(isinstance(s, str) for s in raw):
        raise TypeError(
            "[lint.rules.SEC036].target_tables must be a list of "
            '"schema.table" strings, e.g. ["auth.users", "public.profiles"]'
        )
    out: set[tuple[str, str]] = set()
    for entry in raw:
        parts = entry.split(".")
        if len(parts) != 2 or not all(parts):
            raise TypeError(
                "[lint.rules.SEC036].target_tables entries must be "
                f'"schema.table" (got {entry!r}); use the canonical '
                "schema-qualified form, not a bare table name"
            )
        # Postgres lowercases unquoted identifiers; the RangeVar's
        # schemaname / relname come from the parser in their stored
        # case, which matches the input here. Lowercase both sides
        # so case differences in user config don't silently miss.
        out.add((parts[0].lower(), parts[1].lower()))
    return out


def _parse_binding_functions(options: dict[str, Any]) -> set[str]:
    raw = options.get("binding_functions")
    if raw is None:
        return set(_DEFAULT_BINDING_FUNCTIONS)
    if not isinstance(raw, list) or not all(isinstance(s, str) for s in raw):
        raise TypeError(
            "[lint.rules.SEC036].binding_functions must be a list of "
            "function names (qualified or bare), e.g. "
            '["auth.uid", "current_setting"]'
        )
    return set(raw)


def _from_item_range_vars(from_item: Any) -> list[RangeVar]:
    """RangeVars reachable from a single FROM-clause item.

    A bare `FROM auth.users` is a `RangeVar`; `FROM a JOIN b ON …` is a
    `JoinExpr` whose `larg` / `rarg` hold the (possibly further-nested)
    operands. The original walk inspected only top-level `RangeVar`s,
    so an `auth.users` reached through a JOIN was invisible and the
    binding-free EXISTS bypass slipped through. Recurse into `JoinExpr`
    arms so the target table is found however it's joined in.
    """
    out: list[RangeVar] = []

    def walk(item: Any) -> None:
        if isinstance(item, RangeVar):
            out.append(item)
        elif isinstance(item, JoinExpr):
            walk(item.larg)
            walk(item.rarg)
        elif isinstance(item, RangeSubselect):
            # `FROM (SELECT ... FROM auth.users) sub` — the target
            # table is one level down in the sub-select's own FROM.
            # Recurse its fromClause so an EXISTS that reaches the
            # target through a derived table is still detected.
            sub = item.subquery
            if isinstance(sub, SelectStmt):
                for fc in sub.fromClause or ():
                    walk(fc)

    walk(from_item)
    return out


def _matches_target(
    rv: RangeVar, target_tables: set[tuple[str, str]]
) -> bool:
    # `schemaname` is None for unqualified references (`FROM users`) —
    # those default to whatever's on the caller's `search_path`. We
    # can't statically tell whether an unqualified `users` resolves to
    # `auth.users` or `public.users`, so we require an explicit
    # `auth.users` qualification. (Users who want bare-`users` matching
    # can add `["public.users"]` etc. to target_tables.)
    return (
        rv.schemaname is not None
        and (rv.schemaname.lower(), rv.relname.lower()) in target_tables
    )


def _from_clause_targets(
    sel: Any, target_tables: set[tuple[str, str]]
) -> list[RangeVar]:
    """Target RangeVars in a sub-select's FROM clause (JOINs included)."""
    if sel is None or sel.fromClause is None:
        return []
    out: list[RangeVar] = []
    for from_item in sel.fromClause:
        for rv in _from_item_range_vars(from_item):
            if _matches_target(rv, target_tables):
                out.append(rv)
    return out


def _from_clause_binding_quals(sel: Any) -> list[Any]:
    """Every qual in `sel`'s FROM clause where a caller binding can live.

    JOIN `ON` clauses (`JOIN auth.users u ON u.id = auth.uid()`), AND —
    because target detection recurses into derived tables
    (`_from_item_range_vars` handles RangeSubselect) — the WHERE and JOIN
    ONs of those derived tables too, recursively. Without the
    derived-table descent a policy that binds the caller INSIDE a derived
    table (`FROM (SELECT id FROM auth.users WHERE id = auth.uid()) sub`)
    false-fires: the target is found one level down but the binding there
    is never inspected (asymmetry with target detection).
    """
    quals: list[Any] = []

    def walk_select(s: Any) -> None:
        if s is None:
            return
        if s.whereClause is not None:
            quals.append(s.whereClause)
        for from_item in s.fromClause or ():
            walk_item(from_item)

    def walk_item(item: Any) -> None:
        if isinstance(item, JoinExpr):
            if item.quals is not None:
                quals.append(item.quals)
            walk_item(item.larg)
            walk_item(item.rarg)
        elif isinstance(item, RangeSubselect):
            sub = item.subquery
            if isinstance(sub, SelectStmt):
                walk_select(sub)

    if sel is not None:
        for from_item in sel.fromClause or ():
            walk_item(from_item)
    return quals


def _exists_sublinks_against_target(
    node: Any, target_tables: set[tuple[str, str]]
) -> list[SubLink]:
    """Find every EXISTS_SUBLINK whose sub-select reads a target table.

    Walk depth-first; collect — don't short-circuit — so a policy
    with two offending EXISTS clauses surfaces both. (One finding
    per policy below; we still want the walk to be exhaustive in
    case a future variant wants per-sub-link reporting.)

    The target table is matched whether it appears as a top-level FROM
    item or through a JOIN (`FROM a JOIN auth.users …`) — see
    `_from_clause_targets`.
    """
    out: list[SubLink] = []

    def walk(n: Any) -> None:
        if n is None:
            return
        if isinstance(n, (list, tuple)):
            for item in n:
                walk(item)
            return
        if isinstance(n, SubLink) and n.subLinkType == SubLinkType.EXISTS_SUBLINK:
            if _from_clause_targets(n.subselect, target_tables):
                out.append(n)
        # Walk into Node fields regardless — nested SubLinks happen.
        try:
            field_names = list(n)
        except TypeError:
            return
        for field_name in field_names:
            walk(getattr(n, field_name, None))

    walk(node)
    return out


def _scalar_value_subselects(qual: Any) -> list[Any]:
    """Sub-selects of SCALAR (EXPR_SUBLINK) sub-links reachable in
    `qual` without crossing a non-scalar (EXISTS/ANY/ALL) sub-link.

    A scalar `(SELECT auth.uid())` used as a value genuinely binds the
    caller (the PERF001-recommended wrap). A nested EXISTS/ANY/ALL is a
    SEPARATE existence test, not a binding of the outer EXISTS, so we
    must not look inside it — else an admin-any bypass whose WHERE
    merely contains an unrelated nested auth call (e.g. a correlated
    audit sub-select) would be treated as caller-bound and the real
    leak suppressed (the SEC036 false negative).
    """
    out: list[Any] = []

    def walk(n: Any) -> None:
        if n is None:
            return
        if isinstance(n, (list, tuple)):
            for item in n:
                walk(item)
            return
        if isinstance(n, SubLink):
            walk(n.testexpr)
            if (
                n.subLinkType == SubLinkType.EXPR_SUBLINK
                and n.subselect is not None
            ):
                out.append(n.subselect)
                walk(n.subselect)
            return
        if isinstance(n, Node):
            for field_name in n:
                walk(getattr(n, field_name, None))

    walk(qual)
    return out


def _qual_binds_caller(qual: Any, binding_functions: set[str]) -> bool:
    """True if a binding auth call in `qual` constrains the EXISTS to
    the calling user.

    A binding call counts when it is (1) directly in the qual or in an
    IN/ANY/ALL testexpr — `exclude_sublinks=True` stops the search at
    every sub-select boundary; or (2) inside a scalar value sub-select
    (`col = (SELECT auth.uid())`). A call inside a nested EXISTS/ANY/ALL
    body is deliberately NOT counted (see `_scalar_value_subselects`).
    """
    if find_func_calls(qual, binding_functions, exclude_sublinks=True):
        return True
    return any(
        find_func_calls(sub, binding_functions)
        for sub in _scalar_value_subselects(qual)
    )


def _has_binding_reference(
    sublink: SubLink, binding_functions: set[str]
) -> bool:
    """True if the sub-select binds the caller anywhere it can.

    Checks the sub-select's top-level WHERE *and* every JOIN `ON`
    clause — a binding predicate (`u.id = auth.uid()`) is equally
    valid in either position. The search descends into scalar
    `(SELECT …)` value sub-selects (the PERF001 wrap) but NOT into a
    nested EXISTS/ANY/ALL body, so an unrelated auth call in a deeper
    existence sub-select cannot mask an unbound admin-any check.
    """
    sel = sublink.subselect
    if sel is None:
        return False
    candidates = [sel.whereClause, *_from_clause_binding_quals(sel)]
    return any(
        c is not None and _qual_binds_caller(c, binding_functions)
        for c in candidates
    )


class SEC036:
    id: str = "SEC036"
    severity: Severity = "error"
    title: str = (
        "Policy EXISTS sub-select against auth.users has no caller binding"
    )

    def check(
        self, schema: Schema, options: dict[str, Any]
    ) -> list[Violation]:
        target_tables = _parse_target_tables(options)
        binding_functions = _parse_binding_functions(options)
        allowlist = parse_policy_id_allowlist("SEC036", options)

        out: list[Violation] = []
        for table in schema.tables:
            for policy in table.policies:
                pid = policy_id(table, policy)
                if pid in allowlist:
                    continue
                trees = [
                    t
                    for t in (policy.using_ast, policy.with_check_ast)
                    if t is not None
                ]
                # Aggregate sub-links across both clauses; emit at
                # most one finding per policy. The message names the
                # FIRST offending sub-link (every additional one in
                # the same policy points at the same fix — adding the
                # caller binding).
                fired = False
                for tree in trees:
                    if fired:
                        break
                    sublinks = _exists_sublinks_against_target(
                        tree, target_tables
                    )
                    for sublink in sublinks:
                        if _has_binding_reference(sublink, binding_functions):
                            continue
                        # Identify which target table the offending
                        # sub-link reads — useful in the finding
                        # message when target_tables has more than
                        # one entry. Matches through a JOIN too.
                        target = "auth.users"
                        matched = _from_clause_targets(
                            sublink.subselect, target_tables
                        )
                        if matched:
                            rv = matched[0]
                            target = f"{rv.schemaname}.{rv.relname}"
                        out.append(
                            Violation(
                                rule_id="SEC036",
                                severity="error",
                                title=self.title,
                                message=(
                                    f"Policy {policy.name!r} on "
                                    f"{table.qualified_name} has an "
                                    f"`EXISTS (SELECT ... FROM "
                                    f"{target} WHERE ...)` clause whose "
                                    "WHERE body doesn't bind the "
                                    "calling user — no reference to "
                                    "auth.uid() / current_user / "
                                    "current_setting('request.jwt....', "
                                    "...) etc. As written the clause "
                                    "asks 'does any row in "
                                    f"{target} match these criteria', "
                                    "not 'does THIS user match' — so "
                                    "the policy passes for every "
                                    "authenticated user as soon as a "
                                    "single matching row exists in "
                                    f"{target}. Add `id = auth.uid()` "
                                    "(or your project's caller-binding "
                                    "predicate) to the sub-select's "
                                    "WHERE clause."
                                ),
                                location=pid,
                            )
                        )
                        fired = True
                        break
        return out
