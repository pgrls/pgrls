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

from pglast.ast import A_Const, Boolean

from pgrls.model import Schema
from pgrls.violations import Violation


def _parse_allowlist(options: dict[str, Any]) -> set[str]:
    raw = options.get("allowlist", [])
    if not isinstance(raw, list) or not all(isinstance(s, str) for s in raw):
        raise TypeError(
            "[lint.rules.SEC008].allowlist must be a list of policy IDs "
            "of the form 'schema.table.policy_name'"
        )
    return set(raw)


def _is_literal_true(node: Any) -> bool:
    return (
        isinstance(node, A_Const)
        and isinstance(node.val, Boolean)
        and node.val.boolval is True
    )


class SEC008:
    id = "SEC008"
    severity = "warning"
    title = "Policy USING clause is constant true"

    def check(
        self, schema: Schema, options: dict[str, Any]
    ) -> list[Violation]:
        allowlist = _parse_allowlist(options)
        out: list[Violation] = []
        for table in schema.tables:
            for policy in table.policies:
                if policy.using_ast is None:
                    continue
                if not _is_literal_true(policy.using_ast):
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
