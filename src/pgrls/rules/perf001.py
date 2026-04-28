"""PERF001 — Unwrapped auth function in policy USING.

Calls like `auth.uid()` and `current_setting('app.user')` in a policy's
USING clause are evaluated for every candidate row Postgres scans.
Wrapping the call in `(SELECT auth.uid())` forces evaluation once per
statement; the planner caches the result. The benefit is material on
large tables and the rewrite is mechanical.

Detection: walk the USING AST and look for FuncCall / SQLValueFunction
nodes whose name is in the configured set, but skip anything reached via
a SubLink — calls inside `(SELECT ...)`, `IN (SELECT ...)`, etc. are
already wrapped.
"""
from __future__ import annotations

from typing import Any

from pgrls.ast_utils import find_func_calls
from pgrls.model import Schema
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
    title: str = "Auth function called per-row in policy USING"

    def check(
        self, schema: Schema, options: dict[str, Any]
    ) -> list[Violation]:
        allowlist = _parse_allowlist(options)
        auth_functions = _parse_auth_functions(options)
        out: list[Violation] = []
        for table in schema.tables:
            for policy in table.policies:
                if policy.using_ast is None:
                    continue
                matches = find_func_calls(
                    policy.using_ast,
                    auth_functions,
                    exclude_sublinks=True,
                )
                if not matches:
                    continue
                policy_id = (
                    f"{table.schema}.{table.name}.{policy.name}"
                )
                if policy_id in allowlist:
                    continue
                out.append(
                    Violation(
                        rule_id="PERF001",
                        severity="warning",
                        title=self.title,
                        message=(
                            f"Policy {policy.name!r} on "
                            f"{table.qualified_name} calls an auth "
                            "function in USING without wrapping it in "
                            "a subquery. Postgres re-evaluates the call "
                            "per row. Wrap as e.g. "
                            "(SELECT auth.uid()) so the planner caches "
                            "the result for the whole statement."
                        ),
                        location=policy_id,
                    )
                )
        return out
