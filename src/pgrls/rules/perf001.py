"""PERF001 — Unwrapped auth function in a policy predicate.

Calls like `auth.uid()` and `current_setting('app.user')` in a policy's
USING or WITH CHECK clause are evaluated for every row Postgres
processes — every candidate row scanned (USING) and every row written
(WITH CHECK). Wrapping the call in `(SELECT auth.uid())` forces
evaluation once per statement; the planner caches the result. The
benefit is material on large scans and bulk writes, and the rewrite is
mechanical.

Both clauses are in scope. A 1000-row INSERT or UPDATE re-evaluates a
bare `auth.uid()` in WITH CHECK once per row; the `(SELECT …)` wrap
collapses that to a single InitPlan call — identical to USING. (This was
verified empirically with a call-counting STABLE function: bare WITH
CHECK = 1000 calls, wrapped = 1, for both bulk INSERT and bulk UPDATE.
An earlier belief that "Postgres optimizes WITH CHECK differently" was
wrong.)

Detection: walk the USING and WITH CHECK ASTs and look for FuncCall /
SQLValueFunction nodes whose name is in the configured set. A call in an
UNCORRELATED SubLink — `user_id IN (SELECT auth.uid())` — already runs
once and is skipped. But a call inside a CORRELATED subselect — e.g.
`EXISTS (SELECT 1 FROM members m WHERE m.org_id = t.org_id AND m.user_id
= auth.uid())` — re-evaluates per outer row exactly like a top-level
call, so it is flagged too (the SubLink's `testexpr` is always walked).
One violation per policy, naming the clause(s) where an unwrapped call
was found.
"""
from __future__ import annotations

from typing import Any

from pgrls.ast_utils import find_func_calls
from pgrls.model import Schema, policy_id
from pgrls.rules._allowlist import parse_policy_id_allowlist
from pgrls.violations import Severity, Violation


_DEFAULT_AUTH_FUNCTIONS: frozenset[str] = frozenset({
    "auth.uid",
    "auth.role",
    "auth.jwt",
    "current_setting",
})


def _parse_allowlist(options: dict[str, Any]) -> set[str]:
    return parse_policy_id_allowlist('PERF001', options)


def _parse_auth_functions(options: dict[str, Any]) -> set[str]:
    raw = options.get("auth_functions")
    if raw is None:
        return set(_DEFAULT_AUTH_FUNCTIONS)
    if not isinstance(raw, list) or not all(isinstance(s, str) for s in raw):
        raise TypeError(
            "[lint.rules.PERF001].auth_functions must be a list of "
            "function names (qualified or bare), e.g. "
            '["auth.uid", "current_setting"]'
        )
    return set(raw)


class PERF001:
    id: str = "PERF001"
    severity: Severity = "warning"
    title: str = "Auth function called per-row in policy USING/WITH CHECK"

    def check(
        self, schema: Schema, options: dict[str, Any]
    ) -> list[Violation]:
        allowlist = _parse_allowlist(options)
        auth_functions = _parse_auth_functions(options)
        out: list[Violation] = []
        for table in schema.tables:
            for policy in table.policies:
                clauses: list[str] = []
                if policy.using_ast is not None and find_func_calls(
                    policy.using_ast,
                    auth_functions,
                    exclude_sublinks=True,
                    descend_correlated_sublinks=True,
                ):
                    clauses.append("USING")
                if policy.with_check_ast is not None and find_func_calls(
                    policy.with_check_ast,
                    auth_functions,
                    exclude_sublinks=True,
                    descend_correlated_sublinks=True,
                ):
                    clauses.append("WITH CHECK")
                if not clauses:
                    continue
                pid = policy_id(table, policy)
                if pid in allowlist:
                    continue
                where = " and ".join(clauses)
                out.append(
                    Violation(
                        rule_id="PERF001",
                        severity="warning",
                        title=self.title,
                        message=(
                            f"Policy {policy.name!r} on "
                            f"{table.qualified_name} calls an auth "
                            f"function in {where} without wrapping it in "
                            "a subquery. Postgres re-evaluates the call "
                            "per row. Wrap as e.g. "
                            "(SELECT auth.uid()) so the planner caches "
                            "the result for the whole statement."
                        ),
                        location=pid,
                    )
                )
        return out
