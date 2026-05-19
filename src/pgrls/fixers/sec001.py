"""SEC001 fixer — emit `ALTER TABLE … ENABLE ROW LEVEL SECURITY`."""
from __future__ import annotations

from typing import Any

from pgrls.fixers import Fix
from pgrls.fixers._idents import quote_qualified
from pgrls.model import Schema, Table
from pgrls.rules._allowlist import parse_table_ref_allowlist


def _is_allowlisted(table: Table, allowlist: set[str]) -> bool:
    return table.name in allowlist or table.qualified_name in allowlist


class SEC001Fixer:
    rule_id: str = "SEC001"

    def fix(
        self, schema: Schema, options: dict[str, Any]
    ) -> list[Fix]:
        # Strict allowlist parsing (the same parser SEC001 uses):
        # a malformed allowlist raises, surfaced by the `fix` CLI.
        allowlist = parse_table_ref_allowlist("SEC001", options)
        out: list[Fix] = []
        for table in schema.tables:
            # Mirror SEC001's detection: RLS off, not allowlisted.
            if table.rls_enabled:
                continue
            if _is_allowlisted(table, allowlist):
                continue
            # Skip partition children. SEC001 flags a child only
            # because an ancestor lacks RLS — or, when the parent
            # is in an unscanned schema, has RLS that pgrls cannot
            # verify. Neither case has one mechanical fix. When the
            # parent is in scope the right move is to enable RLS on
            # the parent (this fixer emits that — a single ALTER
            # covers the whole family via query-through-parent).
            # When the parent is out of scan there is no in-scope
            # table to fix: the remediation is to widen `--schemas`
            # or design a child policy. So emit only the standalone
            # and partitioned-parent cases (`partition_of is None`)
            # and leave every child for human review.
            if table.partition_of is not None:
                continue
            sql = (
                "ALTER TABLE "
                f"{quote_qualified(table.schema, table.name)} "
                "ENABLE ROW LEVEL SECURITY;"
            )
            out.append(
                Fix(
                    rule_id="SEC001",
                    location=table.qualified_name,
                    sql=sql,
                    description=(
                        f"Enable row-level security on "
                        f"{table.qualified_name}. Add a policy "
                        "afterward — a table with RLS enabled and "
                        "no policy denies all rows to non-owner "
                        "roles."
                    ),
                )
            )
        return out
