"""SEC001 — RLS not enabled on a table in a configured schema.

Detection: `pg_class.relrowsecurity = false` in the configured schemas,
minus the per-rule `allowlist`. Allowlist entries can be unqualified
(`countries`) or schema-qualified (`tenant.things`).

Declarative partitioning: Postgres does not propagate `relrowsecurity` from
a partitioned parent down to its children, but queries through the parent
DO apply the parent's policies. SEC001 skips a child when any ancestor in
its `partition_of` chain has `rls_enabled = True`. When the chain leaves
the introspected schema set before reaching anyone with RLS, the rule
fires with a different message — telling the user pgrls cannot verify
ancestor coverage rather than telling them to enable RLS on a table that
may already be covered upstream.

Direct queries against a child bypass the parent's policies — a security
caveat documented in `AGENTS.md`. Push a policy onto every child when
direct access is part of the application's threat model.
"""
from __future__ import annotations

from typing import Any

from pgrls.model import Schema, Table
from pgrls.rules._allowlist import parse_table_ref_allowlist
from pgrls.violations import Severity, Violation


class SEC001:
    id: str = "SEC001"
    severity: Severity = "error"
    title: str = "RLS not enabled on table"

    def check(self, schema: Schema, options: dict[str, Any]) -> list[Violation]:
        allowlist = self._parse_allowlist(options)
        out: list[Violation] = []
        for table in schema.tables:
            if table.rls_enabled:
                continue
            if table.policies:
                # A table with policies but RLS off has *dormant*
                # policies — a higher-confidence, more specific finding
                # than the generic "RLS off". Cede it to SEC032 so the
                # two don't double-fire; a bare RLS-off table (no
                # policies) stays SEC001's.
                continue
            if self._is_allowlisted(table, allowlist):
                continue
            ancestors = list(schema.ancestors_of(table))
            if any(a.rls_enabled for a in ancestors):
                continue
            out.append(self._violation(table, ancestors))
        return out

    def _parse_allowlist(self, options: dict[str, Any]) -> set[str]:
        return parse_table_ref_allowlist("SEC001", options)

    def _is_allowlisted(self, table: Table, allowlist: set[str]) -> bool:
        return table.name in allowlist or table.qualified_name in allowlist

    def _violation(
        self, table: Table, ancestors: list[Table]
    ) -> Violation:
        if self._chain_exits_introspected_scope(table, ancestors):
            message = (
                f"Table {table.qualified_name} is a partition whose "
                "ancestor chain leaves the scanned schemas before pgrls "
                "could verify RLS coverage. Add the parent's schema to "
                "`database.schemas` (or `--schemas`) so pgrls can "
                "confirm RLS is enabled upstream, or push a policy "
                f"directly onto this table via "
                f"`CREATE POLICY ... ON {table.qualified_name}`."
            )
        elif ancestors:
            # Partition child whose chain reaches the root inside scope,
            # but no ancestor has RLS — point at the root rather than
            # advising the user to enable RLS on the leaf. Enabling on
            # the parent covers query-through-parent paths for every
            # sibling; enabling on this leaf alone leaves siblings
            # exposed and direct queries on this child still bypass
            # the parent's policies (if any are added later).
            root = ancestors[-1]
            message = (
                f"Table {table.qualified_name} is a partition of "
                f"{root.qualified_name}, which also lacks row-level "
                "security. Enable RLS on the parent (covers queries "
                "routed through the parent for every partition), or "
                "push policies onto each child if direct partition "
                "access is part of your threat model."
            )
        else:
            message = (
                f"Table {table.qualified_name} does not have row-level "
                "security enabled. Add ENABLE ROW LEVEL SECURITY or "
                "include the table in [lint.rules.SEC001].allowlist if "
                "it is a public reference table."
            )
        return Violation(
            rule_id=self.id,
            severity=self.severity,
            title=self.title,
            message=message,
            location=table.qualified_name,
        )

    def _chain_exits_introspected_scope(
        self, table: Table, ancestors: list[Table]
    ) -> bool:
        # The walk reaches the root iff the last visited node has no
        # `partition_of` link. A truncated walk means the next ancestor
        # is in an unintrospected schema — pgrls can't see whether RLS
        # is enabled upstream, so the violation message changes shape.
        if table.partition_of is None:
            return False
        if not ancestors:
            return True
        return ancestors[-1].partition_of is not None
