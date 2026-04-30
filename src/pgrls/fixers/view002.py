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


def _is_allowlisted(view: View, options: dict[str, Any]) -> bool:
    # Mirror SEC002Fixer / VIEW001Fixer's pattern: trust the rule's
    # check() has already validated the allowlist shape (the rule
    # uses `parse_qualified_view_allowlist`, which raises on bad
    # input). If config is bad, we conservatively treat nothing as
    # allowlisted so the fixer still emits a Fix the user can act
    # on.
    raw = options.get("allowlist", [])
    if not isinstance(raw, list):
        return False
    return view.qualified_name in raw


class VIEW002Fixer:
    rule_id: str = "VIEW002"

    def fix(
        self, schema: Schema, options: dict[str, Any]
    ) -> list[Fix]:
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
            if _is_allowlisted(view, options):
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
