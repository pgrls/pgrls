"""SEC009 — RLS enabled but no policies defined.

A table with `relrowsecurity = true` and zero rows in `pg_policy`
acts as deny-all for every role RLS applies to: such a query returns
no rows. The table OWNER is not one of them — it still reads every
row unless `FORCE ROW LEVEL SECURITY` is set (SEC002) — and neither
is a `BYPASSRLS` role or a superuser (measured on PG16: 0 rows for a
grantee, 3 for each of those three). That asymmetry is exactly why
the "intentional" shape below works. That is
sometimes intentional — an audit log read only by superusers, a
soft-deleted "tombstone" table — but far more often it's a forgotten
step. The migration enabled RLS planning to add policies, then the
policy work was deferred and forgotten. Without SEC009 the table
silently rejects everything, which can take an embarrassingly long
time to notice in dev because the only symptom is "the table looks
empty."

Severity: warning. Allowlist by qualified or unqualified table name
when the deny-all is genuinely the goal.
"""
from __future__ import annotations

from typing import Any

from pgrls.model import Schema, Table
from pgrls.rules._allowlist import parse_table_ref_allowlist, table_in_allowlist
from pgrls.violations import Severity, Violation


def _parse_allowlist(options: dict[str, Any]) -> set[str]:
    return parse_table_ref_allowlist('SEC009', options)


class SEC009:
    id: str = "SEC009"
    severity: Severity = "warning"
    title: str = "RLS enabled but no policies defined"

    def check(
        self, schema: Schema, options: dict[str, Any]
    ) -> list[Violation]:
        allowlist = _parse_allowlist(options)
        out: list[Violation] = []
        for table in schema.tables:
            if not table.rls_enabled:
                continue
            if table.policies:
                continue
            if table_in_allowlist(table, allowlist):
                continue
            out.append(self._violation(table))
        return out

    def _violation(self, table: Table) -> Violation:
        return Violation(
            rule_id=self.id,
            severity=self.severity,
            title=self.title,
            message=(
                f"Table {table.qualified_name} has RLS enabled but "
                "no policies defined. Postgres treats this as deny-all "
                "for every role RLS applies to — such a query returns zero "
                "rows. The table owner still reads every row unless FORCE "
                "ROW LEVEL SECURITY is set, and a BYPASSRLS role or "
                "superuser reads it regardless. "
                "If that's intentional (e.g., a deny-by-default audit "
                "table), allowlist it in [lint.rules.SEC009]; otherwise "
                "add the policies the migration was meant to include."
            ),
            location=table.qualified_name,
        )
