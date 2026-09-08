"""VIEW001 — non-`security_invoker` view over RLS-protected table.

A view defined without `WITH (security_invoker = true)` runs queries
with the view owner's privileges, NOT the calling user's — so the base
table's RLS is evaluated against the view OWNER rather than the caller.

Whether that returns rows the caller should not see depends on the
owner. Measured on PG16: a definer view over a `FORCE`'d table owned by
an ordinary (non-exempt) role handed the caller exactly its own tenant's
row — RLS applied, nothing leaked. Drop the `FORCE` and the same view
returned every row. So the bypass is real when the owner is RLS-exempt
(superuser / `BYPASSRLS`) or owns a table that is not `FORCE`'d;
otherwise the caller is still handed the *owner's* row set rather than
its own, which is a different answer than it would get directly.

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
                        "the view owner's privileges, so "
                        f"{referenced_qname}'s RLS is evaluated as the view "
                        "owner rather than the caller. Re-create the view "
                        "with WITH (security_invoker = true), or "
                        "apply the auto-fix."
                    ),
                    location=v.qualified_name,
                )
            )
        return out
