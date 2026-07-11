"""SEC053 — Foreign table exposed in an API schema (Supabase advisor 0017).

A **foreign table** (``pg_class.relkind = 'f'``, e.g. a `postgres_fdw` /
`file_fdw` table or a Supabase *Wrapper* over Stripe / S3 / an external DB)
**cannot carry RLS** — Postgres rejects ``ALTER TABLE <ft> ENABLE ROW LEVEL
SECURITY`` outright ("not supported for foreign tables"). So a foreign table in
a PostgREST-exposed schema (default ``public``) that grants a row-reading
privilege to a low-trust role (``anon`` / ``authenticated`` / ``PUBLIC``) is
directly readable at ``GET /rest/v1/<ft>`` with **no** row filtering possible —
every remote row is returned to any (even unauthenticated) caller:

```sql
CREATE FOREIGN TABLE public.stripe_customers (...) SERVER stripe;
GRANT SELECT ON public.stripe_customers TO anon;   -- GET /rest/v1/stripe_customers → all rows
```

This is the foreign-table sibling of SEC049 (a table with no effective row
filter) and SEC052 (a view exposing ``auth.users``): the same "exposed schema +
low-trust grant = HTTP-reachable, unfiltered" conjunction, for the one relation
type that *structurally* cannot have RLS. Because a foreign table can never be
row-filtered by RLS, the check is a pure exposure test — no policy/predicate
analysis is needed or possible.

Severity: error — the exposed remote data is returned in full to the caller.

Detection: a `ForeignTable` (snapshot v24+) in an exposed schema that grants a
table-level ``SELECT`` to a configured low-trust grantee. Conservative, as with
SEC049: only a *direct* grant to a role in ``grantees`` counts — a grant to a
group role a low-trust role merely inherits is not expanded; a column-level
grant is a miss (foreign-table column grants are not modeled).

Configuration ``[lint.rules.SEC053]``:

* ``schemas`` — PostgREST-exposed schemas (default ``["public"]``).
* ``grantees`` — low-trust roles whose SELECT means "API-reachable" (default
  ``["anon", "authenticated", "PUBLIC"]``).
* ``allowlist`` — foreign-table ids (bare ``name`` or ``schema.name``)
  intentionally public, exempted from the rule.

No auto-fix: ``REVOKE`` the low-trust grant, move the foreign table out of the
exposed schema, or front it with a ``security_invoker`` view that filters rows —
the right choice depends on intent.
"""
from __future__ import annotations

from typing import Any

from pgrls.model import ForeignTable, Schema
from pgrls.rules._allowlist import (
    _list_of_strings,
    parse_table_ref_allowlist,
    table_in_allowlist,
)
from pgrls.violations import Severity, Violation

_DEFAULT_EXPOSED_SCHEMAS = ("public",)
# The low-trust grantees whose SELECT means the foreign table is reachable over
# the API — the same set SEC049 / SEC052 gate on.
_DEFAULT_GRANTEES = ("anon", "authenticated", "PUBLIC")


def _parse_exposed_schemas(options: dict[str, Any]) -> set[str]:
    raw = options.get("schemas")
    if raw is None:
        return set(_DEFAULT_EXPOSED_SCHEMAS)
    return set(
        _list_of_strings("SEC053", raw, "schema names", option="schemas")
    )


def _parse_grantees(options: dict[str, Any]) -> set[str]:
    raw = options.get("grantees")
    if raw is None:
        return set(_DEFAULT_GRANTEES)
    # Validate + normalize the public pseudo-role to the stored "PUBLIC" form
    # (mirrors SEC049 / SEC052).
    items = _list_of_strings("SEC053", raw, "role names", option="grantees")
    return {"PUBLIC" if s.lower() == "public" else s for s in items}


def _select_grantees(ft: ForeignTable, grantees: set[str]) -> list[str]:
    """Low-trust roles in `grantees` that hold table-level SELECT on `ft`."""
    return sorted(
        g.role
        for g in ft.grants
        if g.role in grantees and "SELECT" in g.privileges
    )


class SEC053:
    id: str = "SEC053"
    severity: Severity = "error"
    title: str = "Foreign table exposed in an API schema"

    def check(self, schema: Schema, options: dict[str, Any]) -> list[Violation]:
        exposed = _parse_exposed_schemas(options)
        grantees = _parse_grantees(options)
        allowlist = parse_table_ref_allowlist("SEC053", options)
        out: list[Violation] = []
        for ft in schema.foreign_tables:
            if ft.schema not in exposed:
                continue
            if table_in_allowlist(ft, allowlist):
                continue
            granted = _select_grantees(ft, grantees)
            if granted:
                out.append(self._violation(ft, granted))
        return out

    def _violation(self, ft: ForeignTable, roles: list[str]) -> Violation:
        grant_list = ", ".join(roles)
        return Violation(
            rule_id=self.id,
            severity=self.severity,
            title=self.title,
            message=(
                f"The foreign table {ft.qualified_name} is in the API-exposed "
                f"schema {ft.schema} and grants SELECT to {grant_list}. A "
                "foreign table cannot carry RLS (Postgres rejects ENABLE ROW "
                "LEVEL SECURITY on it), so every remote row is directly "
                f"readable at GET /rest/v1/{ft.name} by an unauthenticated or "
                "any-authenticated request, with no row filtering possible. "
                "Remedy: REVOKE the low-trust grant, move the foreign table out "
                "of the exposed schema, or front it with a security_invoker "
                f"view that filters rows. If it is intentionally public, "
                f"allowlist {ft.qualified_name!r} in [lint.rules.SEC053]."
            ),
            location=ft.qualified_name,
        )
