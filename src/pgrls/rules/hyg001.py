"""HYG001 — Policy references a column that doesn't exist on its table.

Postgres allows `ALTER TABLE ... DROP COLUMN` even when a policy references
that column; the policy text persists with a phantom reference and errors
at evaluation time. Detect statically.

Heuristic: only unqualified ColumnRef nodes are checked, and refs inside
SubLink (subqueries) are skipped, because both shapes commonly point at
something other than the host table.
"""
from __future__ import annotations

from typing import Any

from pgrls.ast_utils import extract_column_refs
from pgrls.model import Schema
from pgrls.violations import Severity, Violation


class HYG001:
    id: str = "HYG001"
    severity: Severity = "error"
    title: str = "Policy references a column that doesn't exist on the table"

    def check(
        self, schema: Schema, options: dict[str, Any]
    ) -> list[Violation]:
        out: list[Violation] = []
        for table in schema.tables:
            existing = set(table.columns)
            for policy in table.policies:
                refs: set[tuple[str, ...]] = set()
                if policy.using_ast is not None:
                    refs |= extract_column_refs(
                        policy.using_ast, exclude_sublinks=True
                    )
                if policy.with_check_ast is not None:
                    refs |= extract_column_refs(
                        policy.with_check_ast, exclude_sublinks=True
                    )
                # Only single-element (unqualified) refs are checked.
                unqualified = {r[0] for r in refs if len(r) == 1}
                missing = unqualified - existing
                if not missing:
                    continue
                for col in sorted(missing):
                    out.append(
                        Violation(
                            rule_id="HYG001",
                            severity="error",
                            title=self.title,
                            message=(
                                f"Policy {policy.name!r} on "
                                f"{table.qualified_name} references "
                                f"column {col!r}, which does not exist "
                                "on the table. Drop the policy, add the "
                                "missing column, or rewrite the predicate."
                            ),
                            location=(
                                f"{table.schema}.{table.name}."
                                f"{policy.name}"
                            ),
                        )
                    )
        return out
