"""VIEW003 — materialized view over RLS-protected table.

A materialized view captures rows by running its body at REFRESH
time, with the privileges of whoever issued the `REFRESH MATERIALIZED
VIEW` (typically a privileged migration / cron / admin role). The
captured rows are written to the matview's own physical heap, and
queries against the matview read from that heap directly — they do
NOT re-evaluate the underlying body and therefore do NOT honor RLS
policies on the source tables.

This is structurally different from a regular view (VIEW001 /
VIEW002 territory): for a regular view, RLS at least *can* be
enforced on the calling user's behalf by setting `security_invoker
= true`. For a matview, there is no per-query evaluation hook —
RLS is bypassed by construction, regardless of any flag.

Operators have two architectural choices, neither of which pgrls
can pick on their behalf:

* Run `REFRESH MATERIALIZED VIEW` as a per-tenant role so the
  captured rows are already filtered to that tenant's view.

* Replicate the matview per-tenant (separate physical heap per
  tenant) and route queries to the right one.

Hence: severity `warning`, no auto-fix. The rule's job is to flag
the architectural gap so the operator chooses one of the above
explicitly.
"""
from __future__ import annotations

from typing import Any

from pgrls.model import Schema
from pgrls.rules._allowlist import parse_qualified_view_allowlist
from pgrls.violations import Severity, Violation


def _parse_allowlist(options: dict[str, Any]) -> set[str]:
    return parse_qualified_view_allowlist('VIEW003', options)


class VIEW003:
    id: str = "VIEW003"
    severity: Severity = "warning"
    title: str = "Materialized view captures RLS-protected data at refresh time"

    def check(
        self, schema: Schema, options: dict[str, Any]
    ) -> list[Violation]:
        allowlist = _parse_allowlist(options)
        rls_tables: set[tuple[str, str]] = {
            (t.schema, t.name) for t in schema.tables if t.rls_enabled
        }
        out: list[Violation] = []
        for v in schema.views:
            if not v.is_materialized:
                # Regular views are VIEW001 / VIEW002 territory.
                continue
            if v.qualified_name in allowlist:
                continue
            leaked = sorted(
                ref for ref in v.references if ref in rls_tables
            )
            if not leaked:
                continue
            referenced_qname = ", ".join(
                f"{s}.{n}" for s, n in leaked
            )
            out.append(
                Violation(
                    rule_id="VIEW003",
                    severity="warning",
                    title=self.title,
                    message=(
                        f"Materialized view {v.qualified_name} "
                        f"captures data from {referenced_qname} at "
                        "REFRESH time per the refresher's privileges. "
                        "RLS is NOT applied to queries against the "
                        "matview. Verify REFRESH is run as a "
                        "per-tenant user, or replicate the matview "
                        "per-tenant."
                    ),
                    location=v.qualified_name,
                )
            )
        return out
