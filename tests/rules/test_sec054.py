"""Unit tests for SEC054 — materialized view exposed in an API schema.

SEC054 (error) fires when a materialized view in a PostgREST-exposed schema
(default ``public``) grants a table-level ``SELECT`` to a low-trust role
(``anon`` / ``authenticated`` / ``PUBLIC``) and its body reads at least one
RLS-enabled table. A matview stores its rows physically, so RLS on the source
tables is never applied to a read — every captured row is served at
``GET /rest/v1/<matview>``. It is the matview sibling of SEC049 (table) /
SEC052 (auth-users view) / SEC053 (foreign table), and the confirmed-exposure
sharpening of VIEW003 (which warns on any matview over an RLS table).
"""
from __future__ import annotations

import pytest

from pgrls.model import Grant, Schema, Table, View
from pgrls.rules.sec054 import SEC054

# Default: granted SELECT to anon — the API-reachability signal SEC054 gates on.
_ANON_SELECT: tuple[Grant, ...] = (Grant(role="anon", privileges=("SELECT",)),)


def _mv(
    *,
    schema: str = "public",
    name: str = "mv",
    is_materialized: bool = True,
    references: tuple[tuple[str, str], ...] = (("public", "orders"),),
    grants: tuple[Grant, ...] = _ANON_SELECT,
) -> View:
    return View(
        schema=schema,
        name=name,
        is_materialized=is_materialized,
        security_invoker=False,
        security_barrier=False,
        definition="SELECT * FROM public.orders",
        references=references,
        security_definer_calls=(),
        grants=grants,
    )


def _rls_table(schema: str = "public", name: str = "orders") -> Table:
    return Table(
        schema=schema, name=name, rls_enabled=True, force_rls=False, policies=()
    )


def _plain_table(schema: str = "public", name: str = "cats") -> Table:
    return Table(
        schema=schema, name=name, rls_enabled=False, force_rls=False, policies=()
    )


def _check(
    view: View,
    *tables: Table,
    **options: object,
) -> list[str]:
    tabs = tables or (_rls_table(),)
    schema = Schema(views=(view,), tables=tabs)
    return [v.location for v in SEC054().check(schema, options)]


# --- fires -----------------------------------------------------------------


def test_fires_on_exposed_matview_over_rls_table() -> None:
    v = _mv(name="orders_summary")
    violations = SEC054().check(
        Schema(views=(v,), tables=(_rls_table(),)), {}
    )
    assert len(violations) == 1
    out = violations[0]
    assert out.rule_id == "SEC054"
    assert out.severity == "error"
    assert out.location == "public.orders_summary"
    assert "materialized view" in out.message.lower()
    assert "public.orders" in out.message
    assert "GET /rest/v1/orders_summary" in out.message
    assert "anon" in out.message


def test_fires_on_public_pseudo_role_grant() -> None:
    v = _mv(name="mv", grants=(Grant(role="PUBLIC", privileges=("SELECT",)),))
    assert _check(v) == ["public.mv"]


def test_fires_on_authenticated_grant() -> None:
    v = _mv(
        name="mv", grants=(Grant(role="authenticated", privileges=("SELECT",)),)
    )
    assert _check(v) == ["public.mv"]


def test_fires_when_any_referenced_table_has_rls() -> None:
    # Mixed sources: one RLS table + one plain table → still fires (the RLS
    # rows leak), and the message names only the RLS source.
    v = _mv(references=(("public", "cats"), ("public", "orders")))
    (out,) = SEC054().check(
        Schema(views=(v,), tables=(_rls_table(), _plain_table())), {}
    )
    assert "public.orders" in out.message
    assert "public.cats" not in out.message


# --- does not fire (soundness / zero-FP) -----------------------------------


def test_no_fire_on_regular_view() -> None:
    # A non-materialized view is VIEW001/SEC052 territory — its RLS handling is
    # a security_invoker question, not the physical-heap bypass SEC054 covers.
    v = _mv(name="v", is_materialized=False)
    assert _check(v) == []


def test_no_fire_on_matview_over_non_rls_tables_only() -> None:
    # A matview of genuinely public reference data (no RLS source) exposes
    # nothing RLS-protected — not flagged (the zero-FP gate that distinguishes
    # SEC054 from the raw Supabase 0016 "any exposed matview" heuristic).
    v = _mv(name="cat_summary", references=(("public", "cats"),))
    assert _check(v, _plain_table()) == []


def test_no_fire_when_granted_only_to_backend_role() -> None:
    v = _mv(
        name="internal",
        grants=(Grant(role="service_role", privileges=("SELECT",)),),
    )
    assert _check(v) == []


def test_no_fire_when_low_trust_grant_lacks_select() -> None:
    v = _mv(name="mv", grants=(Grant(role="anon", privileges=("TRIGGER",)),))
    assert _check(v) == []


def test_no_fire_when_ungranted() -> None:
    v = _mv(name="mv", grants=())
    assert _check(v) == []


def test_no_fire_outside_exposed_schema() -> None:
    # Default exposed schema is public; a matview in a private schema over an
    # RLS table granted to anon is not API-exposed.
    v = _mv(schema="private", name="mv")
    assert SEC054().check(
        Schema(views=(v,), tables=(_rls_table(),)), {}
    ) == []


# --- co-firing with VIEW003 (not mutually exclusive) -----------------------


def test_cofires_with_view003_on_exposed_matview() -> None:
    # SEC054 (error, API-exposed subset) and VIEW003 (warning, any matview over
    # an RLS table) intentionally BOTH fire on an anon-exposed matview — the
    # SEC049<->SEC001 precedent. Pin that they are not mutually exclusive.
    from pgrls.rules.view003 import VIEW003

    v = _mv(name="orders_summary")
    schema = Schema(views=(v,), tables=(_rls_table(),))
    assert [x.location for x in SEC054().check(schema, {})] == [
        "public.orders_summary"
    ]
    assert [x.location for x in VIEW003().check(schema, {})] == [
        "public.orders_summary"
    ]


# --- configuration ---------------------------------------------------------


def test_config_grantees_custom_excludes_default() -> None:
    v = _mv(name="mv")
    assert _check(v) == ["public.mv"]
    # A deployment declaring only PUBLIC as low-trust no longer flags an
    # anon-only grant.
    assert _check(v, grantees=["PUBLIC"]) == []


def test_config_grantees_custom_role() -> None:
    v = _mv(name="mv", grants=(Grant(role="reporting", privileges=("SELECT",)),))
    assert _check(v) == []
    assert _check(v, grantees=["reporting"]) == ["public.mv"]


def test_config_schemas_extends_exposure() -> None:
    v = _mv(schema="api", name="mv")
    tables = (_rls_table(),)
    assert SEC054().check(Schema(views=(v,), tables=tables), {}) == []
    hits = SEC054().check(
        Schema(views=(v,), tables=tables), {"schemas": ["api"]}
    )
    assert [h.location for h in hits] == ["api.mv"]


def test_config_allowlist_exempts_matview() -> None:
    v = _mv(name="mv")
    assert _check(v, allowlist=["public.mv"]) == []


@pytest.mark.parametrize(
    "bad",
    [
        {"schemas": "public"},  # not a list
        {"schemas": [123]},  # not strings
        {"grantees": "anon"},  # not a list
        {"allowlist": "public.mv"},  # not a list
        {"allowlist": ["mv"]},  # bare name — qualified view id required
        {"allowlist": ["a.b.c"]},  # three parts
    ],
)
def test_config_validation_errors(bad: dict[str, object]) -> None:
    v = _mv(name="mv")
    with pytest.raises(TypeError):
        SEC054().check(Schema(views=(v,), tables=(_rls_table(),)), bad)


# --- registry / catalog ----------------------------------------------------


def test_sec054_is_registered() -> None:
    from pgrls.rules import all_rules

    ids = {r.id for r in all_rules()}
    assert "SEC054" in ids
