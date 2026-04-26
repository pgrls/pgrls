"""SEC002 — Table has RLS enabled but FORCE ROW LEVEL SECURITY is off.

Without FORCE, the table owner role bypasses RLS. In development and CI
the migration role is often the owner, which can mask broken policies.
"""
from __future__ import annotations

from typing import Any

from pgrls.model import Schema
from pgrls.violations import Violation


def _parse_allowlist(options: dict[str, Any]) -> set[str]:
    raw = options.get("allowlist", [])
    if not isinstance(raw, list) or not all(isinstance(s, str) for s in raw):
        raise TypeError(
            "[lint.rules.SEC002].allowlist must be a list of table names"
        )
    return set(raw)


class SEC002:
    id = "SEC002"
    severity = "error"
    title = "FORCE ROW LEVEL SECURITY missing"

    def check(
        self, schema: Schema, options: dict[str, Any]
    ) -> list[Violation]:
        allowlist = _parse_allowlist(options)
        out: list[Violation] = []
        for table in schema.tables:
            if not table.rls_enabled or table.force_rls:
                continue
            if (
                table.name in allowlist
                or table.qualified_name in allowlist
            ):
                continue
            out.append(
                Violation(
                    rule_id="SEC002",
                    severity="error",
                    title=self.title,
                    message=(
                        f"Table {table.qualified_name} has RLS enabled "
                        "but not FORCE ROW LEVEL SECURITY. The table "
                        "owner role still bypasses RLS, which often masks "
                        "broken policies in development and CI. Run "
                        f"`ALTER TABLE {table.qualified_name} FORCE ROW "
                        "LEVEL SECURITY;`."
                    ),
                    location=table.qualified_name,
                )
            )
        return out
