"""SEC032 fixer — emit `ALTER TABLE … ENABLE ROW LEVEL SECURITY`.

SEC032 flags a table with `rls_enabled = false` that has at least
one policy — the policies are sitting in `pg_policy` doing nothing.
The mechanical fix is the missing `ENABLE`:

    ALTER TABLE <schema>.<table> ENABLE ROW LEVEL SECURITY;

Same DDL the SEC001 fixer emits — the difference is the prior
state. SEC001 flags an RLS-off table with no policies (where adding
a policy is also necessary); SEC032 flags an RLS-off table that
*already has* policies waiting to enforce. Enabling RLS activates
the existing policies immediately, so the fix delivers the
intended posture in one statement.

`FORCE` is NOT toggled — the user has not yet expressed an intent
to govern owner access, and forcing it could surprise migrations
that run as the table's owner. SEC002 carries the FORCE follow-up
when wanted (the operator runs `pgrls fix --rule SEC002` after).

Partition children are skipped on the same grounds as SEC001's
fixer: a child whose ancestor is RLS-enabled is already covered
for queries through the parent — its dormant policies are dead
weight, not a security hole — so SEC032 itself skips that case
in its `check` and the fixer mirrors. A child whose ancestor is
out of the scanned schemas is also skipped: there's no in-scope
table to remediate, and forcing RLS on the child alone would
change cross-partition routing semantics. Both cases land in the
"human review" bucket SEC001's fixer documents.
"""
from __future__ import annotations

from typing import Any

from pgrls.fixers import Fix
from pgrls.fixers._idents import quote_qualified
from pgrls.model import Schema
from pgrls.rules._allowlist import parse_table_ref_allowlist, table_in_allowlist


class SEC032Fixer:
    rule_id: str = "SEC032"

    def fix(
        self, schema: Schema, options: dict[str, Any]
    ) -> list[Fix]:
        # Strict allowlist parsing (the same parser SEC032 uses):
        # a malformed allowlist raises, surfaced by the `fix` CLI.
        allowlist = parse_table_ref_allowlist("SEC032", options)
        out: list[Fix] = []
        for table in schema.tables:
            # Mirror SEC032's detection precisely.
            if table.rls_enabled:
                continue
            if not table.policies:
                continue  # RLS off with no policies is SEC001's
            if table_in_allowlist(table, allowlist):
                continue
            # A partition child whose ancestor has RLS is already
            # covered for parent-routed queries; SEC032 itself
            # skips this case and so do we.
            if any(a.rls_enabled for a in schema.ancestors_of(table)):
                continue
            sql = (
                "ALTER TABLE "
                f"{quote_qualified(table.schema, table.name)} "
                "ENABLE ROW LEVEL SECURITY;"
            )
            count = len(table.policies)
            plural = "policy" if count == 1 else "policies"
            out.append(
                Fix(
                    rule_id="SEC032",
                    location=table.qualified_name,
                    sql=sql,
                    description=(
                        f"Enable row-level security on "
                        f"{table.qualified_name} — its {count} "
                        f"existing {plural} are dormant until RLS "
                        "is switched on. The policies activate "
                        "immediately; review them with `pgrls "
                        "lint` afterward. Run SEC002's fix next "
                        "if owner access must also be governed."
                    ),
                )
            )
        return out
