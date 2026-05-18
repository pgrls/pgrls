"""SEC008 — Policy USING clause is constant true.

`USING (true)` admits every row to every caller in the policy's role
list. Common during scaffolding and almost always a leftover.

Detection is intentionally narrow: only literal `true` matches. Semantic
tautologies like `1 = 1` are out of scope — a real tautology checker is
significant infrastructure for marginal real-world value, and most
disguised tautologies are SEC005 findings (no own-column ref) anyway.
"""
from __future__ import annotations

from typing import Any

from pgrls.ast_utils import is_literal_true
from pgrls.model import Schema
from pgrls.rules._allowlist import parse_policy_id_allowlist
from pgrls.violations import Severity, Violation


def _parse_allowlist(options: dict[str, Any]) -> set[str]:
    return parse_policy_id_allowlist('SEC008', options)


class SEC008:
    id: str = "SEC008"
    severity: Severity = "warning"
    title: str = "Policy USING clause is constant true"

    def check(
        self, schema: Schema, options: dict[str, Any]
    ) -> list[Violation]:
        allowlist = _parse_allowlist(options)
        out: list[Violation] = []
        for table in schema.tables:
            for policy in table.policies:
                if policy.using_ast is None:
                    continue
                if not is_literal_true(policy.using_ast):
                    continue
                policy_id = (
                    f"{table.schema}.{table.name}.{policy.name}"
                )
                if policy_id in allowlist:
                    continue
                out.append(
                    Violation(
                        rule_id="SEC008",
                        severity="warning",
                        title=self.title,
                        message=(
                            f"Policy {policy.name!r} on "
                            f"{table.qualified_name} has USING (true), "
                            "which admits every row to every caller in "
                            "the role list. Replace with a real "
                            "predicate or remove the policy."
                        ),
                        location=policy_id,
                    )
                )
        return out
