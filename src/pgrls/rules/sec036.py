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

The target-detection and caller-binding primitives live in
`pgrls.rules._auth_binding` (shared with SEC052, which asks the same
"reads auth.users without binding the caller" question of a *view body*);
this module keeps only the EXISTS-sublink-specific glue.

The `IN (SELECT ...)` / `ANY (SELECT ...)` variant against
`auth.users` is a related but distinct hazard class (the outer
`testexpr` already binds an outer-row column to the sub-result, so
the failure mode is different — "show rows whose owner is any
admin" vs "show all rows if any admin exists"). It's deferred to a
separate rule; SEC036 only covers `EXISTS`.

Deferred limitation (deliberate, conservative under-flag): the
target-table scan inspects the EXISTS sub-select's `fromClause` only,
not its `withClause`. An `EXISTS (WITH u AS (SELECT * FROM auth.users)
SELECT 1 FROM u WHERE …)` reaches `auth.users` through a CTE, so the
sub-select's `fromClause` holds the bare CTE-name range var and the
target is not seen — the EXISTS is not examined and SEC036 does not
fire. Resolving it correctly means making BOTH the target scan and the
caller-binding scan CTE-aware in lockstep (else a correctly-bound CTE
policy would begin to false-fire); since CTEs inside policy EXISTS
sub-queries are rare and the failure mode here is a missed flag rather
than a false positive, the rule keeps its conservative stance rather
than risk a new FP. Inline the table reference instead of wrapping it
in a CTE to get the check.

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

from pglast.ast import SubLink
from pglast.enums import SubLinkType

from pgrls.model import Schema, policy_id
from pgrls.rules._allowlist import parse_policy_id_allowlist
from pgrls.rules._auth_binding import (
    DEFAULT_BINDING_FUNCTIONS as _DEFAULT_BINDING_FUNCTIONS,
)
from pgrls.rules._auth_binding import (
    from_clause_targets as _from_clause_targets,
)
from pgrls.rules._auth_binding import (
    select_binds_caller as _select_binds_caller,
)
from pgrls.violations import Severity, Violation


_DEFAULT_TARGET_TABLES: frozenset[tuple[str, str]] = frozenset({
    ("auth", "users"),
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
    `from_clause_targets`.
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
                        if _select_binds_caller(
                            sublink.subselect, binding_functions
                        ):
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
