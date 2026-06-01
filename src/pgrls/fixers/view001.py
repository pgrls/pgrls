"""VIEW001 fixer — emit `ALTER VIEW … SET (security_invoker = true)`.

A view defined without `WITH (security_invoker = true)` runs queries
with the view owner's privileges, bypassing RLS on referenced tables.
The fix is a single ALTER VIEW statement per offending view that flips
the reloption to true; future queries against the view will then
evaluate RLS against the calling user's identity instead of the
view owner's.

The filter mirrors `pgrls.rules.view001.VIEW001.check`: skip
materialized views (VIEW003's domain), skip views already running in
invoker mode, skip views whose `references` contain no RLS-protected
tables, and skip allowlisted views.

The shared `ALTER VIEW … SET (<reloption> = true)` body lives in
`_views.alter_view_reloption_fixer` (VIEW002 differs only in the
reloption, the checked attribute, and the description); identifiers
are double-quoted via `_idents.quote_qualified` when Postgres syntax
requires it. Plain `snake_case` names are emitted bare for readability.
"""
from __future__ import annotations

from pgrls.fixers._views import alter_view_reloption_fixer


def _description(qualified_name: str, leaked_qnames: str) -> str:
    return (
        f"Set security_invoker on {qualified_name} "
        "so queries against the view enforce RLS on "
        f"{leaked_qnames} against the caller's "
        "privileges instead of the view owner's."
    )


VIEW001Fixer = alter_view_reloption_fixer(
    rule_id="VIEW001",
    reloption="security_invoker",
    attr="security_invoker",
    description=_description,
)
VIEW001Fixer.__name__ = "VIEW001Fixer"
VIEW001Fixer.__qualname__ = "VIEW001Fixer"
