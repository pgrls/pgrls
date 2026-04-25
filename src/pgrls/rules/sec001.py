"""SEC001 — RLS not enabled on a public-schema table.

DESIGN.md §4 detection: `pg_class.relrowsecurity = false` in the configured
schemas, minus the per-rule `allowlist`. Allowlist entries can be unqualified
(`countries`) or schema-qualified (`tenant.things`).
"""
from __future__ import annotations

from typing import Any

from pgrls.model import Schema, Table
from pgrls.violations import Severity, Violation


class SEC001:
    id: str = "SEC001"
    severity: Severity = "error"
    title: str = "RLS not enabled on table"

    def check(self, schema: Schema, options: dict[str, Any]) -> list[Violation]:
        allowlist = self._parse_allowlist(options)
        return [
            self._violation(t)
            for t in schema.tables
            if not t.rls_enabled and not self._is_allowlisted(t, allowlist)
        ]

    def _parse_allowlist(self, options: dict[str, Any]) -> set[str]:
        raw = options.get("allowlist", [])
        if not isinstance(raw, list) or not all(isinstance(s, str) for s in raw):
            raise TypeError(
                "SEC001 option 'allowlist' must be a list of strings"
            )
        return set(raw)

    def _is_allowlisted(self, table: Table, allowlist: set[str]) -> bool:
        return table.name in allowlist or table.qualified_name in allowlist

    def _violation(self, table: Table) -> Violation:
        return Violation(
            rule_id=self.id,
            severity=self.severity,
            title=self.title,
            message=(
                f"Table {table.qualified_name} does not have row-level "
                "security enabled. Add ENABLE ROW LEVEL SECURITY or include the "
                "table in [lint.rules.SEC001].allowlist if it is a public reference table."
            ),
            location=table.qualified_name,
        )
