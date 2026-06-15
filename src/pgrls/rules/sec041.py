"""SEC041 — Partition child bypasses the partitioned parent's RLS.

Postgres does **not** propagate row-level security from a declarative
partitioned parent down to its children: `relrowsecurity` is per-table.
Queries routed *through the parent* apply the parent's policies (rows are
read from the partitions under the parent's RLS), but a query that names a
**partition child directly** is governed by the *child's* own RLS — and if
the child has none, it returns every row, ignoring the parent entirely:

```sql
CREATE TABLE events (tenant_id int, body text) PARTITION BY LIST (tenant_id);
CREATE TABLE events_t1 PARTITION OF events FOR VALUES IN (1);   -- no RLS!
ALTER TABLE events ENABLE ROW LEVEL SECURITY;
ALTER TABLE events FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON events
    USING (tenant_id = current_setting('app.tenant_id', true)::int);

-- as tenant 2:
SELECT * FROM events;       -- only tenant 2's rows (parent RLS applies)
SELECT * FROM events_t1;    -- ALL of tenant 1's rows — RLS bypassed
```

This is verified Postgres behaviour, not a theory: the child's
`relrowsecurity` stays `false`, and a direct read of the child skips the
parent's policy. It matters wherever partition children are reachable by
name — notably PostgREST/Supabase, which expose every granted table in the
schema (`GET /events_t1`), and ORMs or jobs that target a partition
directly.

**Relationship to SEC001.** SEC001 ("RLS not enabled") deliberately
*skips* a partition child when any ancestor has RLS enabled — it assumes
the parent covers query-through-parent access and avoids a false "enable
RLS" error on the common parent-only pattern. SEC041 covers the other half
of that caveat: the child is still directly bypassable. The two are
mutually exclusive on a partition child — SEC001 fires when **no** ancestor
has RLS, SEC041 when **an** ancestor does — so they never double-report. A
child that has RLS off but carries its own (dormant) policies is ceded to
SEC032, exactly as SEC001 cedes it.

SEC041 fires when a table has RLS **disabled**, has **no** policies of its
own, has an ancestor in its `partition_of` chain with RLS **enabled**, and
carries a direct **row-access grant** to a non-owner role — a table-level or
column-level `SELECT`/`INSERT`/`UPDATE`/`DELETE` (a `GRANT SELECT (col)` on
the child is enough to read the whole partition by name). That grant is what
makes the bypass *reachable*: a privilege grant on the partitioned parent
does **not** cascade to a child for direct access (Postgres does not inherit
privileges to partitions — a parent-granted role gets "permission denied" on
the child), so a child with no grant of its own can only be reached *through*
the parent, where the parent's RLS applies. A grant of only a non-row-access
privilege (`REFERENCES`/`TRIGGER`/`TRUNCATE`) does not count — it neither
reads nor writes rows. This is also why `pgrls generate` lints clean: it
secures the parent and does not grant the children, so they are not directly
reachable. (The introspector excludes the owner's own ACL row, so any
captured grant is a real non-owner grant.)

Remediate by enabling RLS and adding a policy on the child
(`ALTER TABLE <child> ENABLE ROW LEVEL SECURITY` + `CREATE POLICY … ON
<child> …`) — typically the same policy the parent carries — by revoking
the direct grant so the child is reached only through the parent, or by
allowlisting it:

```toml
[lint.rules.SEC041]
allowlist = ["public.events_t1"]
```

Severity: warning — like the other "RLS can be bypassed via X" rules
(SEC013 triggers, SEC014/SEC016 SECURITY DEFINER / BYPASSRLS, SEC025
RLS-disabled referenced table). No auto-fix: the right policy is the
application's own scoping predicate (often the parent's), which pgrls does
not synthesize.
"""
from __future__ import annotations

from typing import Any

from pgrls.model import Schema, Table
from pgrls.rules._allowlist import parse_table_ref_allowlist, table_in_allowlist
from pgrls.violations import Severity, Violation

# RLS governs only these commands, so a grant of one of them on the child is
# what makes the partition's missing RLS *exploitable* by a direct query: a
# SELECT leaks rows, and INSERT/UPDATE/DELETE skip the parent's WITH CHECK /
# USING. A grant of only REFERENCES / TRIGGER / TRUNCATE / MAINTAIN neither
# reads nor writes row contents, so it is not a bypass (a REFERENCES grantee
# is still "permission denied" on a plain SELECT). DELETE/TRUNCATE/TRIGGER are
# table-only; column grants only ever carry SELECT/INSERT/UPDATE/REFERENCES.
_ROW_ACCESS_PRIVILEGES: frozenset[str] = frozenset(
    {"SELECT", "INSERT", "UPDATE", "DELETE"}
)


def _is_directly_reachable(table: Table) -> bool:
    """True if a non-owner role can name ``table`` in a row-access query.

    Reachability comes from a direct grant of a row-access privilege — either
    table-level (``pg_class.relacl`` → ``Table.grants``) or column-level
    (``pg_attribute.attacl`` → ``Table.column_grants``; a ``GRANT SELECT (col)``
    is enough to read the whole partition by name). A grant on the partitioned
    *parent* does not cascade to a child for direct access, so only the child's
    own grants count. The introspector already excludes the owner's own ACL
    row, so any captured grant is a real non-owner grant.
    """
    if any(
        p.upper() in _ROW_ACCESS_PRIVILEGES
        for grant in table.grants
        for p in grant.privileges
    ):
        return True
    return any(
        p.upper() in _ROW_ACCESS_PRIVILEGES
        for cgrant in table.column_grants
        for p in cgrant.privileges
    )


class SEC041:
    id: str = "SEC041"
    severity: Severity = "warning"
    title: str = "Partition child bypasses the partitioned parent's RLS"

    def check(self, schema: Schema, options: dict[str, Any]) -> list[Violation]:
        allowlist = parse_table_ref_allowlist("SEC041", options)
        out: list[Violation] = []
        for table in schema.tables:
            if table.rls_enabled:
                continue
            if table.policies:
                # RLS off but the child carries its own policies → dormant
                # policies, SEC032's higher-confidence finding. Cede it so
                # the two don't double-fire (mirrors SEC001's SEC032 cede);
                # SEC032's "enable RLS" remedy closes the bypass anyway.
                continue
            if not _is_directly_reachable(table):
                # The child is not directly reachable by a row-access query.
                # A grant on the PARTITIONED PARENT does NOT cascade to a child
                # for direct access (Postgres does not inherit privileges to
                # partitions — a parent-granted role gets "permission denied"
                # on the child), and a child granted only a non-row-access
                # privilege (REFERENCES/TRIGGER/TRUNCATE) cannot read or write
                # its rows. With no row-access grant the only path is *through*
                # the parent, which applies the parent's RLS — so there is no
                # bypass to flag. This is also why `pgrls generate`, which
                # secures the parent and does not grant the children, lints
                # clean.
                continue
            if table_in_allowlist(table, allowlist):
                continue
            rls_ancestor = next(
                (a for a in schema.ancestors_of(table) if a.rls_enabled),
                None,
            )
            if rls_ancestor is None:
                # No RLS-enforcing ancestor: either a standalone table or a
                # partition whose chain has no RLS anywhere — SEC001's case,
                # not SEC041's.
                continue
            out.append(
                Violation(
                    rule_id=self.id,
                    severity=self.severity,
                    title=self.title,
                    message=(
                        f"Table {table.qualified_name} is a partition of "
                        f"{rls_ancestor.qualified_name}, which enforces "
                        "row-level security, but the partition itself has "
                        "RLS disabled and is granted to a non-owner role. "
                        "Postgres does not inherit RLS to partitions, so a "
                        f"query that names {table.qualified_name} directly "
                        "(e.g. a PostgREST request on it, or a direct SELECT) "
                        f"bypasses {rls_ancestor.qualified_name}'s policies "
                        "and returns every row. Enable RLS and add a policy "
                        f"on {table.qualified_name} (usually the parent's), "
                        "revoke the direct (table- or column-level) grant so "
                        "it is reached only through the parent, or allowlist "
                        "it in [lint.rules.SEC041]."
                    ),
                    location=table.qualified_name,
                )
            )
        return out
