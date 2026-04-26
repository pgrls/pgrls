"""SEC007 — Every policy on the table is permissive.

Permissive policies combine with OR; restrictive policies combine with
AND. Tables that need a hard tenant boundary plus a per-tenant rule
typically benefit from one restrictive policy as the floor — without
one, a subtle OR branch can open access the author didn't intend.
Info-severity advisory: many simple tables are correct without
restrictives.
"""
from __future__ import annotations

from typing import Any

from pgrls.model import Schema
from pgrls.violations import Violation


def _parse_allowlist(options: dict[str, Any]) -> set[str]:
    raw = options.get("allowlist", [])
    if not isinstance(raw, list) or not all(isinstance(s, str) for s in raw):
        raise TypeError(
            "[lint.rules.SEC007].allowlist must be a list of table IDs "
            "of the form 'schema.table'"
        )
    return set(raw)


class SEC007:
    id = "SEC007"
    severity = "info"
    title = "All policies on table are permissive"

    def check(
        self, schema: Schema, options: dict[str, Any]
    ) -> list[Violation]:
        allowlist = _parse_allowlist(options)
        out: list[Violation] = []
        for table in schema.tables:
            if not table.rls_enabled:
                continue
            if not table.policies:
                continue
            if not all(p.permissive for p in table.policies):
                continue
            table_id = f"{table.schema}.{table.name}"
            if table_id in allowlist:
                continue
            out.append(
                Violation(
                    rule_id="SEC007",
                    severity="info",
                    title=self.title,
                    message=(
                        f"Every policy on {table.qualified_name} is "
                        "permissive. Permissive policies combine with "
                        "OR — adding one RESTRICTIVE policy gives a "
                        "hard floor (e.g. tenant scoping) that no OR "
                        "branch can bypass."
                    ),
                    location=table_id,
                )
            )
        return out
