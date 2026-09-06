"""SEC054 — Materialized view exposed in an API schema (Supabase advisor 0016).

A **materialized view** captures its rows by running its body at ``REFRESH``
time, writing them to the matview's own physical heap. Queries against the
matview read that heap directly — they do **not** re-evaluate the body and so do
**not** honor RLS on the source tables. Unlike a regular view, there is no
``security_invoker`` hook that could scope the read to the caller; the bypass is
structural.

So a matview in a PostgREST-exposed schema (default ``public``) that grants a
row-reading privilege to a low-trust role (``anon`` / ``authenticated`` /
``PUBLIC``) and whose body reads at least one **RLS-enabled** table serves every
captured row — across every tenant — at ``GET /rest/v1/<matview>`` to any (even
unauthenticated) caller:

```sql
CREATE MATERIALIZED VIEW public.orders_summary AS SELECT * FROM public.orders;
GRANT SELECT ON public.orders_summary TO anon;   -- GET /rest/v1/orders_summary → every tenant's orders
```

This is the materialized-view sibling of SEC049 (a table with no effective row
filter), SEC052 (a view exposing ``auth.users``), and SEC053 (a foreign table):
the same "exposed schema + low-trust grant = HTTP-reachable, unfiltered"
conjunction, for the one *view-family* relation whose rows can never be
RLS-filtered.

**Relationship to VIEW003.** VIEW003 (``warning``) flags *any* matview reading
an RLS table — a broad architectural caution ("verify ``REFRESH`` runs
per-tenant, or replicate the matview per-tenant"), which may be perfectly fine
for an internal, un-exposed matview. SEC054 (``error``) is the sharpened,
confirmed-exposure subset: the matview is *actually reachable over the API* by a
low-trust role, so it is leaking now — ``anon`` cannot be "the per-tenant
refresher". The two intentionally co-fire on an anon-exposed matview (the
SEC049↔SEC001 precedent); keeping them separate lets a team allowlist an
internal matview from VIEW003 while still erroring on an exposed one here.

Severity: error — the captured, RLS-bypassing rows are served in full.

Detection: a `View` with ``is_materialized`` in an exposed schema that (a) grants
a table-level ``SELECT`` to a configured low-trust grantee, and (b) references at
least one RLS-enabled table in the scanned schema set. Conservative, as with
SEC049 / SEC052: only a *direct* table-level grant to a role in ``grantees``
counts — a matview exposed only via a column-level grant is a miss (view column
grants are not modeled). A matview whose body reads only non-RLS tables (public
reference data) is not flagged.

Configuration ``[lint.rules.SEC054]``:

* ``schemas`` — PostgREST-exposed schemas (default ``["public"]``).
* ``grantees`` — low-trust roles whose SELECT means "API-reachable" (default
  ``["anon", "authenticated", "PUBLIC"]``).
* ``allowlist`` — qualified matview ids (``schema.view``) intentionally public,
  exempted from the rule.

No auto-fix: ``REVOKE`` the low-trust grant, move the matview out of the exposed
schema, refresh it as a per-tenant role, or replicate it per-tenant — the right
choice depends on intent.
"""
from __future__ import annotations

from typing import Any

from pgrls.model import Schema, View
from pgrls.rules._allowlist import (
    _list_of_strings,
    parse_qualified_view_allowlist,
)
from pgrls.violations import Severity, Violation

_DEFAULT_EXPOSED_SCHEMAS = ("public",)
# The low-trust grantees whose SELECT means the matview is reachable over the
# API — the same set SEC049 / SEC052 / SEC053 gate on.
_DEFAULT_GRANTEES = ("anon", "authenticated", "PUBLIC")


def _parse_exposed_schemas(options: dict[str, Any]) -> set[str]:
    raw = options.get("schemas")
    if raw is None:
        return set(_DEFAULT_EXPOSED_SCHEMAS)
    return set(
        _list_of_strings("SEC054", raw, "schema names", option="schemas")
    )


def _parse_grantees(options: dict[str, Any]) -> set[str]:
    raw = options.get("grantees")
    if raw is None:
        return set(_DEFAULT_GRANTEES)
    # Validate + normalize the public pseudo-role to the stored "PUBLIC" form
    # (mirrors SEC049 / SEC052 / SEC053).
    items = _list_of_strings("SEC054", raw, "role names", option="grantees")
    return {"PUBLIC" if s.lower() == "public" else s for s in items}


def _view_reachable_by(view: View, grantees: set[str]) -> bool:
    """Whether a low-trust role in `grantees` holds SELECT on the matview.

    The true API-exposure signal (the same one SEC049 / SEC052 gate on): a
    matview granted only to a backend role, or REVOKE'd from
    anon/authenticated, is not reachable over the REST API and is not flagged
    even though it sits in the exposed schema.
    """
    return any(
        g.role in grantees and "SELECT" in g.privileges for g in view.grants
    )


class SEC054:
    id: str = "SEC054"
    severity: Severity = "error"
    title: str = "Materialized view exposed in an API schema"

    def check(self, schema: Schema, options: dict[str, Any]) -> list[Violation]:
        exposed = _parse_exposed_schemas(options)
        grantees = _parse_grantees(options)
        allowlist = parse_qualified_view_allowlist("SEC054", options)
        # The RLS-enabled tables the matview could be laundering (same gate as
        # VIEW003). A matview reading only non-RLS tables exposes no
        # RLS-protected data, so it is not flagged.
        rls_tables: set[tuple[str, str]] = {
            (t.schema, t.name) for t in schema.tables if t.rls_enabled
        }
        out: list[Violation] = []
        for v in schema.views:
            if not v.is_materialized:
                continue
            if v.schema not in exposed:
                continue
            if v.qualified_name in allowlist:
                continue
            if not _view_reachable_by(v, grantees):
                continue
            leaked = sorted(ref for ref in v.references if ref in rls_tables)
            if not leaked:
                continue
            out.append(self._violation(v, grantees, leaked))
        return out

    def _violation(
        self,
        view: View,
        grantees: set[str],
        leaked: list[tuple[str, str]],
    ) -> Violation:
        granted = sorted(
            g.role
            for g in view.grants
            if g.role in grantees and "SELECT" in g.privileges
        )
        grant_list = ", ".join(granted)
        source_list = ", ".join(f"{s}.{n}" for s, n in leaked)
        return Violation(
            rule_id=self.id,
            severity=self.severity,
            title=self.title,
            message=(
                f"The materialized view {view.qualified_name} is in the "
                f"API-exposed schema {view.schema}, grants SELECT to "
                f"{grant_list}, and captures rows from RLS-protected "
                f"{source_list}. A materialized view stores its rows physically "
                "and is read without re-evaluating its body, so RLS on the "
                "source tables is NOT applied — every captured row is directly "
                f"readable at GET /rest/v1/{view.name} by an unauthenticated or "
                "any-authenticated request. Remedy: REVOKE the low-trust grant, "
                "move the matview out of the exposed schema, give it a "
                "per-tenant OWNER (the body runs as the owner at REFRESH, "
                "not as whoever issues it), or replicate it per-tenant. If it is "
                f"intentionally public, allowlist {view.qualified_name!r} in "
                "[lint.rules.SEC054]."
            ),
            location=view.qualified_name,
        )
