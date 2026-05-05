"""VIEW001 — non-`security_invoker` view over RLS-protected table.

A view defined without `WITH (security_invoker = true)` runs queries
with the view owner's privileges, NOT the calling user's. RLS policies
are evaluated against the view owner — typically a privileged migration
or admin role — so referenced rows leak past the policy boundary.

PG15+ defaults `security_invoker` to false, matching the historical
"DEFINER-style" semantics. Modern views should opt in to invoker mode
explicitly so the calling user's RLS context is the one that filters
results.
"""
from __future__ import annotations

from typing import Any

from pgrls.model import Schema
from pgrls.rules._allowlist import parse_qualified_view_allowlist
from pgrls.violations import Severity, Violation


def _parse_allowlist(options: dict[str, Any]) -> set[str]:
    return parse_qualified_view_allowlist('VIEW001', options)


class VIEW001:
    id: str = "VIEW001"
    severity: Severity = "error"
    title: str = "View bypasses RLS without security_invoker"

    def check(
        self, schema: Schema, options: dict[str, Any]
    ) -> list[Violation]:
        allowlist = _parse_allowlist(options)
        rls_tables: set[tuple[str, str]] = {
            (t.schema, t.name) for t in schema.tables if t.rls_enabled
        }
        out: list[Violation] = []
        for v in schema.views:
            if v.is_materialized:
                # Matviews are VIEW003's domain — they capture data
                # at REFRESH time and don't honor RLS regardless of
                # the security_invoker flag.
                continue
            if v.qualified_name in allowlist:
                continue
            if v.security_invoker:
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
                    rule_id="VIEW001",
                    severity="error",
                    title=self.title,
                    message=(
                        f"View {v.qualified_name} runs queries with "
                        "the view owner's privileges, bypassing RLS "
                        f"on {referenced_qname}. Re-create the view "
                        "with WITH (security_invoker = true), or "
                        "apply the auto-fix."
                    ),
                    location=v.qualified_name,
                )
            )
        return out
