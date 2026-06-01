"""SEC032 — table has policies but row-level security is not enabled.

Postgres keeps `CREATE POLICY` rows in `pg_policy` independently of
whether the table has RLS turned on. A policy only takes effect once
the table is switched on with `ALTER TABLE ... ENABLE ROW LEVEL
SECURITY`. Until then the policies are **dormant** — they sit in the
catalog doing nothing, and the table is wide open to every role that
holds the table-level privilege:

```sql
CREATE TABLE documents (id uuid, tenant_id int, body text);
CREATE POLICY tenant_isolation ON documents
    USING (tenant_id = current_setting('app.tenant')::int);
-- ⚠ no `ALTER TABLE documents ENABLE ROW LEVEL SECURITY;`
-- → the policy is inert; every row is readable by everyone.
```

This is a high-confidence footgun. A table with RLS simply *off* and
no policies might be intentional (public reference data — SEC001's
allowlist case). But a table that carries hand-written policies
**clearly intends** to enforce RLS; the missing `ENABLE` is almost
certainly a forgotten step, and the result is a table that *looks*
RLS-managed in code review while enforcing nothing.

SEC032 fires for a table with `rls_enabled = false` that has at least
one policy. It is the policy-bearing complement of **SEC001** (RLS off
with no policies): SEC001 now cedes any table that has policies to
SEC032, so the two are disjoint and a table trips exactly one, each
with the message that fits. Like SEC001 it skips a partition child
whose ancestor chain already has RLS enabled (the child is covered for
parent-routed queries upstream, so its own dormant policies are dead
weight, not a security hole).

Severity: error — the table is unprotected. The fix is `ALTER TABLE
... ENABLE ROW LEVEL SECURITY` (add `FORCE` if owner access must also
be governed), or dropping the policies if RLS was never intended.
Allowlist by table name (bare or `schema.table`) when an
RLS-off-with-policies table is deliberate.
"""
from __future__ import annotations

from typing import Any

from pgrls.model import Schema
from pgrls.rules._allowlist import parse_table_ref_allowlist, table_in_allowlist
from pgrls.violations import Severity, Violation


class SEC032:
    id: str = "SEC032"
    severity: Severity = "error"
    title: str = "Table has policies but RLS is not enabled"

    def check(
        self, schema: Schema, options: dict[str, Any]
    ) -> list[Violation]:
        allowlist = parse_table_ref_allowlist("SEC032", options)
        out: list[Violation] = []
        for table in schema.tables:
            if table.rls_enabled:
                continue
            if not table.policies:
                continue  # RLS off with no policies is SEC001's
            if table_in_allowlist(table, allowlist):
                continue
            # A partition child whose ancestor has RLS is covered for
            # parent-routed queries; its dormant policies aren't a hole.
            if any(a.rls_enabled for a in schema.ancestors_of(table)):
                continue
            count = len(table.policies)
            plural = "policy" if count == 1 else "policies"
            out.append(
                Violation(
                    rule_id="SEC032",
                    severity=self.severity,
                    title=self.title,
                    message=(
                        f"Table {table.qualified_name} has {count} "
                        f"{plural} but row-level security is not enabled, "
                        "so the policies are dormant — Postgres ignores "
                        "them until the table is switched on, and the "
                        "table is readable by every role with the "
                        "table-level privilege. Run `ALTER TABLE "
                        f"{table.qualified_name} ENABLE ROW LEVEL "
                        "SECURITY` (add FORCE if owner access must also "
                        "be governed), or drop the policies if RLS was "
                        f"not intended. Allowlist {table.qualified_name} "
                        "in [lint.rules.SEC032] if this is deliberate."
                    ),
                    location=table.qualified_name,
                )
            )
        return out
