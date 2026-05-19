"""VIEW002 fixer — emit `ALTER VIEW … SET (security_barrier = true)`.

A view defined without `WITH (security_barrier = true)` lets the
planner push user-supplied predicates under the view's RLS filter,
opening the "WHERE-clause function as oracle" leak vector. The fix
is a single ALTER VIEW statement per offending view that flips the
reloption to true; future planner runs against the view will then
treat it as a privilege boundary and refuse the unsafe push-down.

The filter mirrors `pgrls.rules.view002.VIEW002.check`: skip
materialized views (VIEW003's domain), skip views already running
as security barriers, skip views whose `references` contain no
RLS-protected tables, and skip allowlisted views.

Identifiers are double-quoted via `_idents.quote_qualified` when
Postgres syntax requires it (mixed case, embedded special chars).
Plain `snake_case` names are emitted bare for readability.
"""
from __future__ import annotations

from typing import Any

from pgrls.fixers import Fix
from pgrls.fixers._idents import quote_qualified
from pgrls.model import Schema, View
from pgrls.rules._allowlist import parse_qualified_view_allowlist


def _is_allowlisted(view: View, allowlist: set[str]) -> bool:
    return view.qualified_name in allowlist


class VIEW002Fixer:
    rule_id: str = "VIEW002"

    def fix(
        self, schema: Schema, options: dict[str, Any]
    ) -> list[Fix]:
        # Strict allowlist parsing (the same parser VIEW002 uses):
        # a malformed allowlist raises, surfaced by the `fix` CLI.
        allowlist = parse_qualified_view_allowlist("VIEW002", options)
        rls_tables: set[tuple[str, str]] = {
            (t.schema, t.name) for t in schema.tables if t.rls_enabled
        }
        out: list[Fix] = []
        for view in schema.views:
            # Mirror VIEW002's detection in lockstep.
            if view.is_materialized:
                continue
            if view.security_barrier:
                continue
            if _is_allowlisted(view, allowlist):
                continue
            leaked = sorted(
                ref for ref in view.references if ref in rls_tables
            )
            if not leaked:
                continue
            qname = quote_qualified(view.schema, view.name)
            leaked_qnames = ", ".join(
                f"{s}.{n}" for s, n in leaked
            )
            sql = (
                f"ALTER VIEW {qname} "
                "SET (security_barrier = true);"
            )
            out.append(
                Fix(
                    rule_id="VIEW002",
                    location=view.qualified_name,
                    sql=sql,
                    description=(
                        f"Set security_barrier on {view.qualified_name} "
                        "so the planner cannot push user-supplied "
                        "predicates below the view's RLS qualifications "
                        f"on {leaked_qnames}."
                    ),
                )
            )
        return out
