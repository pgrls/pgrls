"""SEC012 — Table has only RESTRICTIVE policies (silent deny-all).

Postgres composes RLS policies as `permissive_or | (restrictive_and
& restrictive_and ...)`: a row is visible iff at least one PERMISSIVE
policy matches AND every RESTRICTIVE policy matches. With zero
PERMISSIVE policies, the disjunction is empty — no row passes,
regardless of how many RESTRICTIVE policies you've added or what
they say.

Common mistake: a developer adds a RESTRICTIVE policy thinking it
"layers on top of" an implicit permissive default. There is no
implicit default. Without a PERMISSIVE policy granting access,
RESTRICTIVE policies are constraining nothing — the table is silently
deny-all from the moment RLS is enabled.

This is the same effective shape as SEC009 (RLS enabled, zero
policies) and SEC010 (`USING (false)` deny-all anti-pattern), just
achieved through a different mechanism. SEC009 catches the explicit
"no policies at all" case; SEC010 catches the explicit `false`
literal; SEC012 catches the silent "only RESTRICTIVE" case where
the user intended access but composed the policies wrong.

Detection is structural — does the table have RLS on, at least
one policy, and zero PERMISSIVE policies. No AST inspection needed;
the rule reads the existing model fields directly.

Severity: warning. Allowlist by qualified or unqualified table name
when the deny-all is genuinely the goal — e.g., a "shadow" table
that exists only to be queried via a SECURITY DEFINER function and
should never be visible through direct SELECT.
"""
from __future__ import annotations

from typing import Any

from pgrls.model import Schema, Table
from pgrls.rules._allowlist import parse_table_ref_allowlist, table_in_allowlist
from pgrls.violations import Severity, Violation


def _parse_allowlist(options: dict[str, Any]) -> set[str]:
    return parse_table_ref_allowlist('SEC012', options)


class SEC012:
    id: str = "SEC012"
    severity: Severity = "warning"
    title: str = "Table has only RESTRICTIVE policies (silent deny-all)"

    def check(
        self, schema: Schema, options: dict[str, Any]
    ) -> list[Violation]:
        allowlist = _parse_allowlist(options)
        out: list[Violation] = []
        for table in schema.tables:
            if not table.rls_enabled:
                continue
            if not table.policies:
                # Empty-policies case is SEC009's territory; don't
                # double-fire.
                continue
            if any(policy.permissive for policy in table.policies):
                continue
            if table_in_allowlist(table, allowlist):
                continue
            out.append(self._violation(table))
        return out

    def _violation(self, table: Table) -> Violation:
        n = len(table.policies)
        plural = "policies" if n != 1 else "policy"
        return Violation(
            rule_id=self.id,
            severity=self.severity,
            title=self.title,
            message=(
                f"Table {table.qualified_name} has {n} RESTRICTIVE "
                f"{plural} and no PERMISSIVE policy. Postgres requires "
                "at least one PERMISSIVE policy to grant access; "
                "without one, RESTRICTIVE policies are constraining "
                "nothing and the table is silently deny-all. Add a "
                "PERMISSIVE policy that describes who CAN see rows "
                "(the RESTRICTIVE policies will narrow it further), "
                "or allowlist this table in [lint.rules.SEC012] if "
                "the deny-all is intentional."
            ),
            location=table.qualified_name,
        )
