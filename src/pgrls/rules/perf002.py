"""PERF002 — Policy expression uses a VOLATILE function.

A VOLATILE function (`random()`, `clock_timestamp()`, `nextval(...)`,
`gen_random_uuid()`, `pg_backend_pid()`) returns a different result
on every call. Inside an RLS policy this is bad on two counts:

* **Non-determinism.** `random() < 0.5` admits some rows and denies
  others *unpredictably*. The predicate's truth value depends on
  call timing, not on the row data — almost never the intended
  semantics, often a security hazard.
* **No caching.** The optimizer cannot fold or cache a VOLATILE call;
  it re-runs per row regardless of `(SELECT ...)` wrapping. Even
  read-only-looking volatiles like `clock_timestamp()` add per-row
  syscall cost.

STABLE functions (`now()`, `current_setting`, `auth.uid` and the
other Supabase auth helpers) are NOT in this rule's set — they have
their own treatment via PERF001 for the per-row evaluation cost.

**SubLink scope.** Unlike SEC011 (which deliberately stops at
`SubLink.subselect` to avoid false-firing on subqueries' own WHERE
clauses), PERF002 *does* walk subselects. Reason: a VOLATILE call
inside a correlated subquery still re-runs per outer row, and even
in an uncorrelated subquery the non-determinism leaks ("rows
admitted depend on the random() draw at scan time"). Both shapes
are real footguns, so PERF002 errs on the side of catching them.

Default volatile set: `random`, `clock_timestamp`, `nextval`,
`gen_random_uuid`, `pg_backend_pid`. Override with
`[lint.rules.PERF002].volatile_functions = [...]` (the list
REPLACES the default — match SEC004's `auth_functions` convention).

Severity: warning. Allowlist by qualified policy ID.
"""
from __future__ import annotations

from typing import Any

from pgrls.ast_utils import find_func_calls
from pgrls.model import Schema
from pgrls.violations import Severity, Violation

_DEFAULT_VOLATILE_FUNCTIONS: tuple[str, ...] = (
    "random",
    "clock_timestamp",
    "nextval",
    "gen_random_uuid",
    "pg_backend_pid",
)


def _parse_allowlist(options: dict[str, Any]) -> set[str]:
    raw = options.get("allowlist", [])
    if not isinstance(raw, list) or not all(isinstance(s, str) for s in raw):
        raise TypeError(
            "[lint.rules.PERF002].allowlist must be a list of policy IDs "
            "of the form 'schema.table.policy_name'"
        )
    return set(raw)


def _parse_volatile_functions(options: dict[str, Any]) -> set[str]:
    raw = options.get("volatile_functions")
    if raw is None:
        return set(_DEFAULT_VOLATILE_FUNCTIONS)
    if not isinstance(raw, list) or not all(isinstance(s, str) for s in raw):
        raise TypeError(
            "[lint.rules.PERF002].volatile_functions must be a list "
            "of strings (override REPLACES the default list)"
        )
    return set(raw)


class PERF002:
    id: str = "PERF002"
    severity: Severity = "warning"
    title: str = "Policy expression uses a VOLATILE function"

    def check(
        self, schema: Schema, options: dict[str, Any]
    ) -> list[Violation]:
        allowlist = _parse_allowlist(options)
        volatile_set = _parse_volatile_functions(options)
        if not volatile_set:
            return []

        out: list[Violation] = []
        for table in schema.tables:
            for policy in table.policies:
                hits: list[Any] = []
                if policy.using_ast is not None:
                    hits.extend(find_func_calls(policy.using_ast, volatile_set))
                if policy.with_check_ast is not None:
                    hits.extend(
                        find_func_calls(policy.with_check_ast, volatile_set)
                    )
                if not hits:
                    continue
                policy_id = (
                    f"{table.schema}.{table.name}.{policy.name}"
                )
                if policy_id in allowlist:
                    continue
                out.append(
                    Violation(
                        rule_id="PERF002",
                        severity="warning",
                        title=self.title,
                        message=(
                            f"Policy {policy.name!r} on "
                            f"{table.qualified_name} calls a VOLATILE "
                            "function in its predicate. Postgres "
                            "evaluates VOLATILE calls per row, and the "
                            "result varies between calls — predicates "
                            "like `random() < 0.5` admit/deny rows "
                            "unpredictably. Move the volatility outside "
                            "the policy, use a STABLE alternative "
                            "(`now()` instead of `clock_timestamp()`, "
                            "etc.), or rethink the design."
                        ),
                        location=policy_id,
                    )
                )
        return out
