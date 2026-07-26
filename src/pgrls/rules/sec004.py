"""SEC004 — Inverted auth check (Lovable CVE pattern).

The pattern: a policy with USING (auth_func() IS NULL OR <real check>).
auth_func() returns NULL for anonymous connections, so the IS NULL
disjunct is true and the OR is satisfied without ever evaluating the
real check. Anonymous clients see all rows.

The same inversion in **WITH CHECK** is the write-side twin: the disjunct
is true for a token-less session, so the policy accepts any row that
session writes — including rows stamped for another tenant. Both clauses
are inspected. A policy that carries the hole in both is one finding
naming both clauses (baseline identity is `(rule_id, location)`, so a
second violation on the same policy would be indistinguishable from the
first).

Only an **explicit** WITH CHECK is inspected separately: Postgres reuses
USING as the implicit WITH CHECK on UPDATE/ALL when WITH CHECK is
omitted, so an absent clause adds no hole the USING report doesn't
already cover. A `FOR INSERT` policy has no USING at all, which is why
the WITH CHECK scan is the only thing that can see its hole.

Detection flattens the OR disjuncts of each clause — including disjuncts
nested by explicit parenthesization, since OR is associative
(`A OR (B OR auth() IS NULL)` is the same hole as the flat form) — and
flags any disjunct shaped as `auth_func() IS NULL` for one of a
configurable set of auth-context functions. It does not flatten through
AND / NOT / subqueries: an `IS NULL` gated by an AND is not a standalone
anonymous-access hole.
"""
from __future__ import annotations

from typing import Any

from pgrls.ast_utils import (
    find_func_calls,
    flatten_or_disjuncts,
    is_never_null_current_setting,
    match_is_null,
)
from pgrls.model import Schema
from pgrls.violations import Severity, Violation


def _has_nullable_auth_call(inner: Any, auth_functions: set[str]) -> bool:
    """True if `inner` contains an auth call that can actually be NULL.

    `find_func_calls` matches every configured auth function in `inner`;
    a never-NULL ``current_setting`` among them (the one-arg form, or the
    two-arg ``current_setting(name, false)`` — both raise on an unset GUC
    rather than returning NULL) does not make the ``IS NULL`` disjunct an
    anonymous-read hole. Any OTHER match (auth.uid/role/jwt, or the
    two-arg ``current_setting(name, true)``) is genuinely NULLable.
    """
    matches = find_func_calls(inner, auth_functions)
    return any(not is_never_null_current_setting(m) for m in matches)


# Only functions that genuinely return NULL for an unauthenticated
# request belong here: an `IS NULL` disjunct is a real anonymous-read
# hole only if the function can actually be NULL. auth.uid/role/jwt read
# JWT claims (NULL when no token); current_setting(name, true) returns
# NULL when the GUC is unset.
#
# NOT included: current_user / session_user / current_role / user. These
# SQLValueFunctions ALWAYS return the session role name — Postgres has no
# unauthenticated backend (PostgREST's "anon" is itself a real role), so
# `current_user IS NULL` is the constant FALSE and a disjunct gated on it
# is dead, not a leak. Flagging it is a false positive. The role-identity
# hazard for these functions is a column COMPARISON (`owner = current_user`),
# which is SEC018's / SEC026's job, not an IS-NULL anonymous-read hole.
_DEFAULT_AUTH_FUNCTIONS: frozenset[str] = frozenset({
    "auth.uid",
    "auth.role",
    "auth.jwt",
    "current_setting",
})

# Roles a token-less / unauthenticated session can act as. A policy whose role
# list intersects this set is reachable by anonymous callers (so an IS-NULL auth
# disjunct is a live anonymous-read hole); a policy restricted to other roles
# (e.g. ``authenticated``) is not reachable that way. ``PUBLIC`` covers the
# no-``TO`` case, which introspection resolves to ``("PUBLIC",)``. Configurable
# per project via ``[lint.rules.SEC004].anon_roles`` — same convention as
# SEC039 / SEC042 — so a project whose anonymous role is named e.g. ``web_anon``
# is still reported as an error rather than downgraded to a warning.
_DEFAULT_ANON_ROLES: tuple[str, ...] = ("anon", "PUBLIC")


def _parse_anon_roles(options: dict[str, Any]) -> set[str]:
    raw = options.get("anon_roles")
    if raw is None:
        return set(_DEFAULT_ANON_ROLES)
    if not isinstance(raw, list) or not all(isinstance(s, str) for s in raw):
        raise TypeError(
            "[lint.rules.SEC004].anon_roles must be a list of role-name "
            "strings (e.g. ['anon', 'PUBLIC'])."
        )
    # Normalize the public pseudo-role so a config entry of "public"/"Public"
    # still matches the stored "PUBLIC" form (PUBLIC is a keyword, not a real
    # role, so this is safe; real role names stay case-sensitive).
    return {"PUBLIC" if s.lower() == "public" else s for s in raw}


def _parse_auth_functions(options: dict[str, Any]) -> set[str]:
    raw = options.get("auth_functions")
    if raw is None:
        return set(_DEFAULT_AUTH_FUNCTIONS)
    if not isinstance(raw, list) or not all(isinstance(s, str) for s in raw):
        raise TypeError(
            "[lint.rules.SEC004].auth_functions must be a list of "
            "function names (qualified or bare), e.g. "
            '["auth.uid", "current_setting"]'
        )
    return set(raw)


def _clause_has_inverted_auth(ast: Any, auth_functions: set[str]) -> bool:
    """True iff `ast` carries a top-level `<nullable-auth>() IS NULL`
    OR-disjunct — the exact shape SEC004 flags, in either clause."""
    if ast is None:
        return False
    for disjunct in flatten_or_disjuncts(ast):
        matched = match_is_null(disjunct)
        if matched is None:
            continue
        inner, is_null = matched
        if not is_null:
            continue
        if _has_nullable_auth_call(inner, auth_functions):
            return True
    return False


class SEC004:
    id: str = "SEC004"
    severity: Severity = "error"
    title: str = "Inverted auth check (permits anonymous access)"

    def check(
        self, schema: Schema, options: dict[str, Any]
    ) -> list[Violation]:
        auth_functions = _parse_auth_functions(options)
        anon_roles = _parse_anon_roles(options)
        out: list[Violation] = []
        for table in schema.tables:
            for policy in table.policies:
                in_using = _clause_has_inverted_auth(
                    policy.using_ast, auth_functions
                )
                # Only an EXPLICIT WITH CHECK is a distinct hole. When it is
                # omitted on UPDATE/ALL Postgres reuses USING as the implicit
                # write check, so `with_check_ast is None` adds nothing the
                # USING branch hasn't already reported.
                in_check = _clause_has_inverted_auth(
                    policy.with_check_ast, auth_functions
                )
                if not in_using and not in_check:
                    continue

                if in_using and in_check:
                    clauses = "USING and WITH CHECK"
                    plural = "s"
                    anon_impact = (
                        "exposing every row and accepting every row it writes"
                    )
                    role_impact = (
                        "admits every row to — and accepts every row written "
                        "by — any session in those roles"
                    )
                elif in_using:
                    clauses = "USING"
                    plural = ""
                    anon_impact = "exposing every row"
                    role_impact = "admits every row to any session in those roles"
                else:
                    clauses = "WITH CHECK"
                    plural = ""
                    anon_impact = (
                        "accepting every row it writes, including rows "
                        "stamped for another tenant"
                    )
                    role_impact = (
                        "accepts every row written by any session in those "
                        "roles"
                    )

                # Only a policy reachable by an anonymous (token-less)
                # session is a live anon hole. One restricted to
                # non-anon roles (e.g. `authenticated`) can't be reached
                # that way, so the disjunct is a latent defect, not an
                # anonymous leak — report it, but don't over-claim.
                if anon_roles & set(policy.roles):
                    severity: Severity = "error"
                    message = (
                        f"Policy {policy.name!r} on "
                        f"{table.qualified_name} has a top-level "
                        f"`auth_func() IS NULL` disjunct in its {clauses} "
                        f"clause{plural}, and the policy applies to anon / "
                        "PUBLIC. For token-less connections that "
                        "disjunct is true, satisfying the policy and "
                        f"{anon_impact}. Remove the IS NULL "
                        "disjunct or replace with an explicit deny."
                    )
                else:
                    severity = "warning"
                    roles_disp = ", ".join(sorted(policy.roles)) or "no role"
                    message = (
                        f"Policy {policy.name!r} on "
                        f"{table.qualified_name} has a top-level "
                        f"`auth_func() IS NULL` disjunct in its {clauses} "
                        f"clause{plural}. It is restricted to {roles_disp} "
                        "(not anon / PUBLIC), so a token-less request "
                        f"cannot reach it — but the disjunct still "
                        f"{role_impact} whose auth context is NULL (e.g. an "
                        "authenticated token with no `sub`), and "
                        "becomes a full anonymous hole if the "
                        "role restriction is loosened. Remove the IS "
                        "NULL disjunct or replace with an explicit "
                        "deny."
                    )
                out.append(
                    Violation(
                        rule_id="SEC004",
                        severity=severity,
                        title=self.title,
                        message=message,
                        location=(
                            f"{table.schema}.{table.name}."
                            f"{policy.name}"
                        ),
                    )
                )
        return out
