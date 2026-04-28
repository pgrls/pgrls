"""SEC005 — Policy expression has no own-column reference.

A policy whose USING and WITH CHECK clauses never reference any column
of the table they're on is a "session-state-only" predicate — it admits
or denies whole sets of rows based on configuration alone, not on row
attributes. Almost always a mistake: the author meant to gate by role,
not gate per row.

Detection walks the entire expression tree, including inside subqueries.
That's deliberate: correlated subqueries (e.g. `EXISTS (SELECT 1 FROM
members m WHERE m.tenant_id = tenant_id)`) reference the policy's own
column via correlation, and SEC005 must not falsely fire on the
membership-table pattern. The trade-off is a rare false negative when
a subquery references a column with the same bare name as one on the
policy's table (`x IN (SELECT id FROM other)` where the policy's table
also has an `id` column) — uncommon enough to take the simpler walk.
"""
from __future__ import annotations

from typing import Any

from pgrls.ast_utils import extract_column_refs
from pgrls.model import Schema, Table
from pgrls.rules._allowlist import parse_policy_id_allowlist
from pgrls.violations import Severity, Violation


def _parse_allowlist(options: dict[str, Any]) -> set[str]:
    return parse_policy_id_allowlist('SEC005', options)


def _is_own_column_ref(ref: tuple[str, ...], table: Table) -> bool:
    if len(ref) == 1:
        return ref[0] in table.columns
    if len(ref) == 2:
        return ref[0] == table.name and ref[1] in table.columns
    if len(ref) == 3:
        return (
            ref[0] == table.schema
            and ref[1] == table.name
            and ref[2] in table.columns
        )
    return False


class SEC005:
    id: str = "SEC005"
    severity: Severity = "warning"
    title: str = "Policy expression does not reference any column of the table"

    def check(
        self, schema: Schema, options: dict[str, Any]
    ) -> list[Violation]:
        allowlist = _parse_allowlist(options)
        out: list[Violation] = []
        for table in schema.tables:
            if not table.columns:
                continue
            for policy in table.policies:
                if policy.using_ast is None and policy.with_check_ast is None:
                    continue
                refs: set[tuple[str, ...]] = set()
                if policy.using_ast is not None:
                    refs |= extract_column_refs(policy.using_ast)
                if policy.with_check_ast is not None:
                    refs |= extract_column_refs(policy.with_check_ast)
                if any(_is_own_column_ref(r, table) for r in refs):
                    continue
                policy_id = (
                    f"{table.schema}.{table.name}.{policy.name}"
                )
                if policy_id in allowlist:
                    continue
                out.append(
                    Violation(
                        rule_id="SEC005",
                        severity="warning",
                        title=self.title,
                        message=(
                            f"Policy {policy.name!r} on "
                            f"{table.qualified_name} does not reference "
                            "any column of the table. The predicate is "
                            "purely session-state — every row is admitted "
                            "or denied based on configuration alone. "
                            "Add a row-level condition (e.g. "
                            "tenant_id = current_setting('app.tenant'))."
                        ),
                        location=policy_id,
                    )
                )
        return out
