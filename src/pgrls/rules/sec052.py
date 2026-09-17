"""SEC052 — Supabase auth user table exposed through an API-schema view.

The footgun (Supabase Security Advisor ``0002_auth_users_exposed``): a view in
a PostgREST-exposed schema (default ``public``) that selects from ``auth.users``
runs — unless it opts into ``security_invoker`` — with the **view owner's**
privileges, not the caller's. The owner (``postgres`` / a migration role) can
read ``auth.users``, so a low-trust REST caller who can ``GET /rest/v1/<view>``
reads every user's row — email, phone, ``encrypted_password``,
``raw_user_meta_data`` — straight out of the auth schema:

```sql
-- The classic leak: "expose the users to the frontend"
CREATE VIEW public.users AS SELECT * FROM auth.users;
--  GET /rest/v1/users  ->  every account's email + metadata.
```

The bypass is structural, not a policy question — ``auth.users`` is protected
by *grants* (``anon`` / ``authenticated`` hold no ``SELECT`` on it), and a
non-``security_invoker`` view launders exactly that grant boundary.

**Why this is not VIEW001:** VIEW001 flags a non-``security_invoker`` view over
a table with *RLS enabled*. ``auth.users`` has no RLS — it is grant-protected —
so VIEW001 never fires on it. SEC052 is the auth-schema-PII counterpart.

Detection (sound, reuses SEC036's caller-binding analysis via
``pgrls.rules._auth_binding``):

* the view is in an exposed schema (``schemas``, default ``["public"]``);
* a low-trust role holds a table-level ``SELECT`` on the view (``grantees``,
  default ``anon`` / ``authenticated`` / ``PUBLIC``) — the true API-reachability
  signal, read from the view's ``relacl`` (v23+). A view REVOKE'd from those
  roles (readable only by a backend role) is **not** flagged even though it sits
  in the exposed schema — like SEC049's table-level grant gate (view *column*
  grants are not modeled — see the conservative-miss note below);
* it is a regular view **without** ``security_invoker`` (an invoker view runs as
  the caller, who lacks ``SELECT`` on ``auth.users`` → the query errors, it does
  not leak), **or** a materialized view (matview data is physically captured and
  read with the reader's grant, so ``security_invoker`` is moot);
* its body **directly** reads a sensitive table (``tables``, default
  ``["auth.users"]``) as a FROM-clause source (top-level, through JOINs, or in a
  derived table — the columns can reach the output), **and**
* that read is **not** scoped to the calling user. A view filtered to the
  caller's own row — ``SELECT ... FROM auth.users WHERE id = auth.uid()`` — is a
  legitimate "my account" view and does **not** fire; only an *unfiltered* (or
  non-caller-bound) read of the whole table does.

Conservative by design (soundness over recall, no false positives):

* An **unparseable** view body → abstain (no finding).
* A **transitive** re-exposer (``CREATE VIEW public.a AS SELECT * FROM
  public.b`` where ``b`` reads ``auth.users``) is not flagged on ``a`` — its own
  body doesn't read the sensitive table, so the caller-binding of ``b`` can't be
  judged from ``a``. The **direct** reader ``b`` is flagged; fixing it fixes the
  chain.
* A view exposed **only** through a column-level ``GRANT SELECT (col) ON <view>``
  (with no table-level grant) is a conservative miss — view column grants are
  not captured (only ``relacl`` table-level grants), unlike SEC049 which reads a
  table's column grants too. The standard ``GRANT SELECT ON <view> TO anon`` is
  captured. A group-role grant a low-trust role merely *inherits* is likewise
  not expanded, mirroring SEC049.
* A read reached through a **CTE** (``WITH u AS (SELECT * FROM auth.users)
  SELECT * FROM u``) is not seen — the body scan inspects FROM items, not the
  ``WITH`` list (the same conservative stance SEC036 documents). Inline the
  reference to get the check.
* In a **set operation** (``UNION`` etc.) the caller-binding scan is any-arm: if
  one arm reads ``auth.users`` unbound but another arm binds the caller, the view
  is treated as bound and not flagged (inherited from SEC036's existence-test
  logic; a projection miss here, never a false positive). Bind (or drop) the
  ``auth.users`` read in its own arm to be safe.
* For a **materialized view** the ``WHERE`` runs once at ``REFRESH`` (as the
  matview's owner), not per caller, so a ``WHERE id = auth.uid()`` filter does
  *not* actually scope to the caller — a caller-bound matview over ``auth.users``
  is a conservative miss, not a "safe" view.
* Any caller-binding auth call (``auth.uid()`` etc.) present in the view's
  effective WHERE / JOIN-ON / derived-table quals is treated as scoping the read
  to the caller — the same presence-based binding signal SEC036 uses.

Severity: error — an unbound read of ``auth.users`` over the API discloses every
user's PII to any (even unauthenticated) caller.

Configuration ``[lint.rules.SEC052]``:

* ``schemas`` — PostgREST-exposed schemas (default ``["public"]``).
* ``grantees`` — low-trust roles whose SELECT on the view means "API-reachable"
  (default ``["anon", "authenticated", "PUBLIC"]``).
* ``tables`` — sensitive ``schema.table`` sources (default ``["auth.users"]``;
  add e.g. ``"auth.identities"`` if you treat it as equally sensitive).
* ``binding_functions`` — caller-binding signals (default the ``auth.uid`` /
  ``current_setting`` / … set shared with SEC036).
* ``allowlist`` — qualified view names (``schema.view``) that intentionally
  expose the table (rare) and should be exempt.

No auto-fix: the right remedy depends on intent — set
``security_invoker = on`` and re-grant, drop the sensitive columns, scope the
body to ``auth.uid()``, or move the view out of the exposed schema. The finding
message lays out the options; the edit is a judgment call, not mechanical.
"""
from __future__ import annotations

from typing import Any

import pglast
from pglast.ast import SelectStmt

from pgrls.model import Schema, View
from pgrls.rules._allowlist import (
    _list_of_strings,
    parse_qualified_view_allowlist,
)
from pgrls.rules._auth_binding import (
    DEFAULT_BINDING_FUNCTIONS,
    from_clause_targets,
    select_binds_caller,
)
from pgrls.violations import Severity, Violation

_DEFAULT_EXPOSED_SCHEMAS = ("public",)
_DEFAULT_SENSITIVE_TABLES: frozenset[tuple[str, str]] = frozenset({
    ("auth", "users"),
})
# Low-trust grantees whose SELECT on the view means "reachable over the API"
# — the same set SEC049 gates on. A view granted only to a backend role
# (service_role / postgres) or REVOKE'd from anon/authenticated is not
# API-reachable and is NOT flagged (the grant is the true exposure signal;
# schema membership alone is not).
_DEFAULT_GRANTEES = ("anon", "authenticated", "PUBLIC")


def _parse_exposed_schemas(options: dict[str, Any]) -> set[str]:
    raw = options.get("schemas")
    if raw is None:
        return set(_DEFAULT_EXPOSED_SCHEMAS)
    return set(
        _list_of_strings("SEC052", raw, "schema names", option="schemas")
    )


def _parse_sensitive_tables(options: dict[str, Any]) -> set[tuple[str, str]]:
    raw = options.get("tables")
    if raw is None:
        return set(_DEFAULT_SENSITIVE_TABLES)
    items = _list_of_strings(
        "SEC052", raw, '"schema.table" strings', option="tables"
    )
    out: set[tuple[str, str]] = set()
    for entry in items:
        parts = entry.split(".")
        if len(parts) != 2 or not all(parts):
            raise TypeError(
                "[lint.rules.SEC052].tables entries must be "
                f'"schema.table" (got {entry!r}); use the canonical '
                "schema-qualified form, not a bare table name"
            )
        # Lowercase both sides: Postgres folds unquoted identifiers and the
        # parsed RangeVar carries them in stored case, so config case must not
        # silently miss (mirrors SEC036._parse_target_tables).
        out.add((parts[0].lower(), parts[1].lower()))
    return out


def _parse_binding_functions(options: dict[str, Any]) -> set[str]:
    raw = options.get("binding_functions")
    if raw is None:
        return set(DEFAULT_BINDING_FUNCTIONS)
    if not isinstance(raw, list) or not all(isinstance(s, str) for s in raw):
        raise TypeError(
            "[lint.rules.SEC052].binding_functions must be a list of "
            "function names (qualified or bare), e.g. "
            '["auth.uid", "current_setting"]'
        )
    return set(raw)


def _parse_grantees(options: dict[str, Any]) -> set[str]:
    raw = options.get("grantees")
    if raw is None:
        return set(_DEFAULT_GRANTEES)
    # Validate + normalize the public pseudo-role to the stored "PUBLIC"
    # form (mirrors SEC049).
    items = _list_of_strings("SEC052", raw, "role names", option="grantees")
    return {"PUBLIC" if s.lower() == "public" else s for s in items}


def _view_reachable_by(view: View, grantees: set[str]) -> bool:
    """Whether a low-trust role in `grantees` holds SELECT on the view.

    This is the true API-exposure signal (the same one SEC049 gates a table
    on): a view granted only to a backend role, or REVOKE'd from
    anon/authenticated, is not reachable over the REST API and must not be
    flagged even though it sits in the exposed schema.
    """
    return any(
        g.role in grantees and "SELECT" in g.privileges for g in view.grants
    )


def _view_selects(definition: str) -> list[SelectStmt]:
    """The top-level SELECT statement(s) of a view's stored definition.

    ``pg_get_viewdef`` yields the bare query, so this is normally a single
    ``SelectStmt``. Returns [] on a parse error — the caller then abstains
    (an unparseable body is judged as "can't confirm a leak", not a leak).
    """
    try:
        parsed = pglast.parse_sql(definition)
    except pglast.parser.ParseError:
        return []
    out: list[SelectStmt] = []
    for raw in parsed:
        stmt = raw.stmt
        if isinstance(stmt, SelectStmt):
            out.append(stmt)
    return out


def _unbound_sensitive_reads(
    selects: list[SelectStmt],
    sensitive: set[tuple[str, str]],
    binding_functions: set[str],
) -> list[str]:
    """Qualified names of sensitive tables read *unbound* by any of `selects`.

    A select reads a sensitive table unbound when the table is a FROM-clause
    source (`from_clause_targets`: top-level, through JOINs, or in a derived
    table) AND the select does not bind the read to the caller
    (`select_binds_caller`). Returns the sorted, de-duplicated ``schema.table``
    names — empty if every sensitive read is caller-scoped (or there is none).
    """
    leaked: set[str] = set()
    for sel in selects:
        targets = from_clause_targets(sel, sensitive)
        if not targets:
            continue
        if select_binds_caller(sel, binding_functions):
            continue
        for rv in targets:
            leaked.add(f"{rv.schemaname.lower()}.{rv.relname.lower()}")
    return sorted(leaked)


class SEC052:
    id: str = "SEC052"
    severity: Severity = "error"
    title: str = "Auth user table exposed through an API-schema view"

    def check(self, schema: Schema, options: dict[str, Any]) -> list[Violation]:
        exposed = _parse_exposed_schemas(options)
        sensitive = _parse_sensitive_tables(options)
        binding_functions = _parse_binding_functions(options)
        grantees = _parse_grantees(options)
        allowlist = parse_qualified_view_allowlist("SEC052", options)

        out: list[Violation] = []
        for v in schema.views:
            if v.schema not in exposed:
                continue
            if v.qualified_name in allowlist:
                continue
            # The view is only an exposure if a low-trust role can actually
            # read it — a view REVOKE'd from anon/authenticated (readable only
            # by a backend role) is not reachable over the API. Gate on the
            # grant, exactly as SEC049 does for a table.
            if not _view_reachable_by(v, grantees):
                continue
            # A regular view WITH security_invoker runs as the caller, who has
            # no SELECT on auth.users → the query errors, it does not leak.
            # A matview has no invoker semantics (its rows are materialized and
            # read with the reader's own grant), so it is always in scope.
            if not v.is_materialized and v.security_invoker:
                continue
            # Cheap pre-filter: skip views that don't reach a sensitive table
            # at all. `references` is transitive (over-approximates), so this
            # never skips a view whose own body directly reads the table; the
            # body parse below is authoritative for the firing decision.
            if not any(
                (s.lower(), n.lower()) in sensitive for s, n in v.references
            ):
                continue
            selects = _view_selects(v.definition)
            if not selects:
                continue  # unparseable → abstain (soundness over recall)
            leaked = _unbound_sensitive_reads(
                selects, sensitive, binding_functions
            )
            if leaked:
                out.append(self._violation(v, leaked))
        return out

    def _violation(self, view: View, leaked: list[str]) -> Violation:
        kind = "materialized view" if view.is_materialized else "view"
        tables = ", ".join(leaked)
        if view.is_materialized:
            # A matview's WHERE runs once at REFRESH (as the matview's owner),
            # not per caller, so neither `security_invoker` nor an `id =
            # auth.uid()` filter scopes it — and adding such a filter would only
            # SILENCE this finding while the capture still leaks. Offer only
            # remedies that actually work for a matview (the "printed
            # remediation must work" discipline).
            remedy = (
                "REVOKE the low-trust SELECT grant, restrict the selected "
                "columns, or drop the matview / move it out of the exposed "
                "schema (a matview's WHERE runs at REFRESH, not per caller, so "
                "a security_invoker option or an `id = auth.uid()` filter does "
                "not scope it)"
            )
            # A matview is not a definer-view at query time: its rows are
            # captured at REFRESH and served with the reader's own grant.
            mechanism = "so its materialized rows expose"
        else:
            remedy = (
                "set `WITH (security_invoker = on)` so it runs as the caller "
                "(who cannot read auth.users), restrict the selected columns, "
                "add a `WHERE id = auth.uid()` caller filter, or move the view "
                "out of the exposed schema"
            )
            mechanism = "so it runs with the view owner's privileges and exposes"
        return Violation(
            rule_id=self.id,
            severity=self.severity,
            title=self.title,
            message=(
                f"The {kind} {view.qualified_name} is in the API-exposed "
                f"schema {view.schema}, grants a low-trust role SELECT, and "
                f"reads {tables} without scoping the read to the calling user, "
                f"{mechanism} "
                f"{tables} rows the caller is not scoped to (typically email, "
                "phone, encrypted_password, metadata) to any REST caller at "
                f"GET /rest/v1/{view.name}. Remedy: {remedy}. If the exposure "
                f"is intentional, allowlist {view.qualified_name!r} in "
                "[lint.rules.SEC052]."
            ),
            location=view.qualified_name,
        )
