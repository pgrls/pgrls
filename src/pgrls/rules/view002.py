"""VIEW002 — non-`security_barrier` view over RLS-protected table.

A view defined without `WITH (security_barrier = true)` lets the
planner push user-supplied predicates *under* the view's RLS-derived
filter. The classic exploit: the user runs

    SELECT * FROM v WHERE leak(secret_column);

against a view `v` that exposes a join over an RLS-protected table.
If `v` is not a security barrier, the planner is free to evaluate the
volatile / side-effecting `leak(...)` BEFORE the underlying RLS
predicates restrict the row set — leaking rows the calling user
should never have seen.

`security_barrier = true` tells the planner the view is a privilege
boundary: predicates the user adds in the outer query MUST NOT be
pushed below the view's own qualifications. RLS still applies; the
flag closes the orthogonal "WHERE-clause function as oracle" leak.

`security_invoker` (VIEW001) and `security_barrier` (this rule) are
*independent* defenses against *different* leak vectors. A view that
references RLS-protected tables and lacks both flags fires both
rules — neither subsumes the other.
"""
from __future__ import annotations

from typing import Any

from pgrls.model import Schema
from pgrls.rules._allowlist import parse_qualified_view_allowlist
from pgrls.violations import Severity, Violation


def _parse_allowlist(options: dict[str, Any]) -> set[str]:
    return parse_qualified_view_allowlist('VIEW002', options)


class VIEW002:
    id: str = "VIEW002"
    severity: Severity = "warning"
    title: str = "View is not a security barrier"

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
                # the security_barrier flag.
                continue
            if v.qualified_name in allowlist:
                continue
            if v.security_barrier:
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
                    rule_id="VIEW002",
                    severity="warning",
                    title=self.title,
                    message=(
                        f"View {v.qualified_name} is not a security "
                        "barrier; a function call in WHERE could leak "
                        f"rows from {referenced_qname} before RLS "
                        "predicates apply. Apply the auto-fix or "
                        "re-create with WITH (security_barrier = true)."
                    ),
                    location=v.qualified_name,
                )
            )
        return out
