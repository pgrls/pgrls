"""SEC002 fixer — emit `ALTER TABLE … FORCE ROW LEVEL SECURITY`."""
from __future__ import annotations

from typing import Any

from pgrls.fixers import Fix
from pgrls.model import Schema, Table


def _is_allowlisted(table: Table, options: dict[str, Any]) -> bool:
    raw = options.get("allowlist", [])
    if not isinstance(raw, list):
        return False
    return table.name in raw or table.qualified_name in raw


class SEC002Fixer:
    rule_id: str = "SEC002"

    def fix(
        self, schema: Schema, options: dict[str, Any]
    ) -> list[Fix]:
        out: list[Fix] = []
        for table in schema.tables:
            # Mirror SEC002's detection: rls enabled but force off,
            # not in allowlist.
            if not table.rls_enabled or table.force_rls:
                continue
            if _is_allowlisted(table, options):
                continue
            sql = (
                f"ALTER TABLE {table.qualified_name} "
                "FORCE ROW LEVEL SECURITY;"
            )
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
