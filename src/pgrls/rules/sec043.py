"""SEC043 — legacy-inheritance child bypasses the parent's RLS.

This is the classic-``INHERITS`` analogue of SEC041 (which covers declarative
partitions). Postgres does **not** propagate row-level security from a table
down to a child that inherits from it via ``CREATE TABLE child () INHERITS
(parent)``: ``relrowsecurity`` is per-table. Queries routed *through the
parent* apply the parent's policies (the child's rows are read under the
parent's RLS), but a query that names a **child directly** is governed by the
*child's* own RLS — and if the child has none, it returns every row, ignoring
the parent entirely:

```sql
CREATE TABLE events (tenant_id int, body text);
ALTER TABLE events ENABLE ROW LEVEL SECURITY;
ALTER TABLE events FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON events
    USING (tenant_id = current_setting('app.tenant_id', true)::int);
CREATE TABLE events_legacy () INHERITS (events);   -- no RLS!

-- as tenant 2:
SELECT * FROM events;           -- only tenant 2's rows (parent RLS applies)
SELECT * FROM events_legacy;    -- ALL of tenant 1's rows — RLS bypassed
SELECT * FROM ONLY events;      -- (parent's own rows, still scoped)
```

This is verified Postgres behaviour, not a theory: the child's
``relrowsecurity`` stays ``false``, and a direct read of the child skips the
parent's policy. It matters wherever such children are reachable by name —
notably PostgREST/Supabase, which expose every granted table in the schema
(``GET /events_legacy``), and ORMs or jobs that target the child directly.

**Relationship to SEC041.** SEC043 and SEC041 are the two halves of the same
inheritance-bypass: SEC041 fires on a **declarative partition** child
(``pg_inherits`` with ``relispartition = true``, modeled as
``Table.partition_of``), SEC043 on a **classic-``INHERITS``** child
(``relispartition = false``, modeled as ``Table.inherits``). Postgres records
both edge kinds in ``pg_inherits`` but a table is one or the other, never
both — a partition child XOR a classic-inheritance child — so the two rules
are mutually exclusive and never double-report the same table. The shared
mechanism (RLS and privileges do not inherit to children; a direct query on
the child is governed by the child's own, absent, RLS) is identical. Unlike a
partition's single parent, a classic-inheritance child may inherit from
**multiple** parents (a DAG); ``Schema.inheritance_ancestors_of`` walks that
DAG, so a child fires if **any** ancestor enforces RLS.

**Relationship to SEC001 / SEC032 — this is an intentional over-report, not a
false negative.** SEC001 ("RLS not enabled") and SEC032 ("policies but RLS
not enabled") special-case declarative **partition** children: they walk
``Schema.ancestors_of`` (the ``partition_of`` chain) and skip a child when an
ancestor has RLS, to avoid a false "enable RLS" finding on the common
parent-only partitioning pattern. They do **not** walk classic inheritance
(``inherits``). So a classic-inheritance child with RLS off is **not** ceded
by SEC001 — SEC001 fires on it too ("enable RLS on this table"). SEC043 does
not suppress that: both findings are correct and point to the **same fix**
(enable RLS on the child). SEC001 says the table has no RLS; SEC043 adds the
bypass/reachability context — that an RLS-enforcing ancestor exists and the
child is directly bypassable. (A classic-inheritance child carrying its own
dormant policies is SEC032's case under the same logic: SEC032 fires because
it does not cede classic-inheritance children, and SEC043 co-fires with the
bypass context.) This deliberate double-report differs from the partition
case, where SEC041 is the *sole* finding because SEC001/SEC032 cede the
child; for classic inheritance pgrls reports both rather than teaching
SEC001/SEC032 a second inheritance axis.

SEC043 fires when a table has RLS **disabled**, has an ancestor in its
``inherits`` DAG with RLS **enabled**, and carries a direct **row-access
grant** to a non-owner role — a table-level or column-level
``SELECT``/``INSERT``/``UPDATE``/``DELETE`` (a ``GRANT SELECT (col)`` on the
child is enough to read the whole child by name). It fires **regardless of
whether the child carries its own policies**: those policies are dormant
while RLS is disabled, so the child still returns every row. That grant is
what makes the bypass *reachable*: a privilege grant on the parent does
**not** cascade to a child for direct access (Postgres does not inherit
privileges to inheritance children — a parent-granted role gets "permission
denied" on the child), so a child with no grant of its own can only be
reached *through* the parent, where the parent's RLS applies. A grant of only
a non-row-access privilege (``REFERENCES``/``TRIGGER``/``TRUNCATE``) does not
count — it neither reads nor writes rows. (The introspector excludes the
owner's own ACL row, so any captured grant is a real non-owner grant.)

Remediate by enabling RLS and adding a policy on the child
(``ALTER TABLE <child> ENABLE ROW LEVEL SECURITY`` + ``CREATE POLICY … ON
<child> …`` — typically the same policy the parent carries), by revoking the
direct grant so the child is reached only through the parent, or by
allowlisting it:

```toml
[lint.rules.SEC043]
allowlist = ["public.events_legacy"]
```

Severity: warning — like SEC041 and the other "RLS can be bypassed via X"
rules. No auto-fix: the right policy is the application's own scoping
predicate (often the parent's), which pgrls does not synthesize.
"""
from __future__ import annotations

from typing import Any

from pgrls.model import Schema
from pgrls.rules._allowlist import parse_table_ref_allowlist, table_in_allowlist
from pgrls.rules.sec041 import _is_directly_reachable
from pgrls.violations import Severity, Violation


class SEC043:
    id: str = "SEC043"
    severity: Severity = "warning"
    title: str = "Legacy-inheritance child bypasses the parent's RLS"

    def check(self, schema: Schema, options: dict[str, Any]) -> list[Violation]:
        allowlist = parse_table_ref_allowlist("SEC043", options)
        out: list[Violation] = []
        for table in schema.tables:
            if table.rls_enabled:
                continue
            if not _is_directly_reachable(table):
                # The child is not directly reachable by a row-access query.
                # A grant on the PARENT does NOT cascade to a classic-
                # inheritance child for direct access (Postgres does not
                # inherit privileges to children — a parent-granted role gets
                # "permission denied" on the child), and a child granted only
                # a non-row-access privilege (REFERENCES/TRIGGER/TRUNCATE)
                # cannot read or write its rows. With no row-access grant the
                # only path is *through* the parent, which applies the
                # parent's RLS — so there is no bypass to flag.
                continue
            if table_in_allowlist(table, allowlist):
                continue
            rls_ancestor = next(
                (
                    a
                    for a in schema.inheritance_ancestors_of(table)
                    if a.rls_enabled
                ),
                None,
            )
            if rls_ancestor is None:
                # No RLS-enforcing classic-inheritance ancestor: nothing
                # upstream to bypass. A standalone RLS-off table (or one whose
                # ancestors also lack RLS) is SEC001's / SEC032's case, not a
                # classic-inheritance bypass — SEC043 stays silent.
                continue
            # rls_ancestor is not None → the child is directly bypassable.
            # This holds even if the child carries its OWN policies: they are
            # dormant while RLS is disabled, so the child still returns every
            # row. NOTE: unlike the partition case (where SEC001/SEC032 cede
            # the child via ancestors_of), SEC001 — and SEC032 if the child
            # has dormant policies — ALSO fires on this child, because those
            # rules do not walk classic inheritance. Both findings are correct
            # and point to the same fix (enable RLS on the child); SEC043 adds
            # the bypass/reachability context. This is a deliberate
            # over-report, not a false negative.
            out.append(
                Violation(
                    rule_id=self.id,
                    severity=self.severity,
                    title=self.title,
                    message=(
                        f"Table {table.qualified_name} inherits (classic "
                        f"INHERITS) from {rls_ancestor.qualified_name}, which "
                        "enforces row-level security, but the child itself has "
                        "RLS disabled and is granted to a non-owner role. "
                        "Postgres does not inherit RLS to inheritance "
                        "children, so a query that names "
                        f"{table.qualified_name} directly (e.g. a PostgREST "
                        "request on it, or a direct SELECT) bypasses "
                        f"{rls_ancestor.qualified_name}'s policies and returns "
                        f"every row. Enable RLS on {table.qualified_name} "
                        "(adding a scoping policy, usually the parent's, if it "
                        "has none — any policy it already carries is dormant "
                        "while RLS is off), revoke the direct (table- or "
                        "column-level) grant so it is reached only through the "
                        "parent, or allowlist it in [lint.rules.SEC043]."
                    ),
                    location=table.qualified_name,
                )
            )
        return out
