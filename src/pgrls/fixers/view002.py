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

The shared `ALTER VIEW … SET (<reloption> = true)` body lives in
`_views.alter_view_reloption_fixer` (VIEW001 differs only in the
reloption, the checked attribute, and the description); identifiers
are double-quoted via `_idents.quote_qualified` when Postgres syntax
requires it. Plain `snake_case` names are emitted bare for readability.
"""
from __future__ import annotations

from pgrls.fixers._views import alter_view_reloption_fixer


def _description(qualified_name: str, leaked_qnames: str) -> str:
    return (
        f"Set security_barrier on {qualified_name} "
        "so the planner cannot push user-supplied "
        "predicates below the view's RLS qualifications "
        f"on {leaked_qnames}."
    )


VIEW002Fixer = alter_view_reloption_fixer(
    rule_id="VIEW002",
    reloption="security_barrier",
    attr="security_barrier",
    description=_description,
)
VIEW002Fixer.__name__ = "VIEW002Fixer"
VIEW002Fixer.__qualname__ = "VIEW002Fixer"
