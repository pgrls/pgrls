"""SEC004 — Inverted auth check (Lovable CVE pattern).

The pattern: a policy with USING (auth_func() IS NULL OR <real check>).
auth_func() returns NULL for anonymous connections, so the IS NULL
disjunct is true and the OR is satisfied without ever evaluating the
real check. Anonymous clients see all rows.

Detection flattens the OR disjuncts of the USING expression — including
disjuncts nested by explicit parenthesization, since OR is associative
(`A OR (B OR auth() IS NULL)` is the same hole as the flat form) — and
flags any disjunct shaped as `auth_func() IS NULL` for one of a
configurable set of auth-context functions. It does not flatten through
AND / NOT / subqueries: an `IS NULL` gated by an AND is not a standalone
anonymous-access hole.
"""
from __future__ import annotations

from typing import Any

from pgrls.ast_utils import find_func_calls, flatten_or_disjuncts, match_is_null
from pgrls.model import Schema
from pgrls.violations import Severity, Violation


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


class SEC004:
    id: str = "SEC004"
    severity: Severity = "error"
    title: str = "Inverted auth check (USING permits anonymous)"

    def check(
        self, schema: Schema, options: dict[str, Any]
    ) -> list[Violation]:
        auth_functions = _parse_auth_functions(options)
        out: list[Violation] = []
        for table in schema.tables:
            for policy in table.policies:
                if policy.using_ast is None:
                    continue
                for disjunct in flatten_or_disjuncts(policy.using_ast):
                    matched = match_is_null(disjunct)
                    if matched is None:
                        continue
                    inner, is_null = matched
                    if not is_null:
                        continue
                    if not find_func_calls(inner, auth_functions):
                        continue
                    out.append(
                        Violation(
                            rule_id="SEC004",
                            severity="error",
                            title=self.title,
                            message=(
                                f"Policy {policy.name!r} on "
                                f"{table.qualified_name} contains a "
                                "top-level `auth_func() IS NULL` "
                                "disjunct in its USING clause. For "
                                "anonymous connections that disjunct "
                                "evaluates to true, satisfying the "
                                "policy and exposing every row. Remove "
                                "the IS NULL disjunct or replace with "
                                "an explicit deny."
                            ),
                            location=(
                                f"{table.schema}.{table.name}."
                                f"{policy.name}"
                            ),
                        )
                    )
                    break  # one violation per policy
        return out
