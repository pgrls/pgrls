"""SEC002 fixer — emit `ALTER TABLE … FORCE ROW LEVEL SECURITY`."""
from __future__ import annotations

from typing import Any

from pgrls.fixers import Fix
from pgrls.fixers._idents import force_rls_sql, quote_qualified
from pgrls.model import Schema
from pgrls.rules._allowlist import parse_table_ref_allowlist, table_in_allowlist


class SEC002Fixer:
    rule_id: str = "SEC002"

    def fix(
        self, schema: Schema, options: dict[str, Any]
    ) -> list[Fix]:
        # Strict allowlist parsing (the same parser SEC002 uses):
        # a malformed allowlist raises, surfaced by the `fix` CLI.
        allowlist = parse_table_ref_allowlist("SEC002", options)
        out: list[Fix] = []
        for table in schema.tables:
            # Mirror SEC002's detection: rls enabled but force off,
            # not in allowlist.
            if not table.rls_enabled or table.force_rls:
                continue
            if table_in_allowlist(table, allowlist):
                continue
            sql = force_rls_sql(quote_qualified(table.schema, table.name))
            out.append(
                Fix(
                    rule_id="SEC002",
                    location=table.qualified_name,
                    sql=sql,
                    description=(
                        f"Enable FORCE ROW LEVEL SECURITY on "
                        f"{table.qualified_name} so the table owner "
                        "stops bypassing RLS."
                    ),
                )
            )
        return out
