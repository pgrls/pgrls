"""Unit tests for SEC053 — foreign table exposed in an API schema.

SEC053 (error) fires when a foreign table (``pg_class.relkind = 'f'``) in a
PostgREST-exposed schema (default ``public``) grants a table-level ``SELECT`` to
a low-trust role (``anon`` / ``authenticated`` / ``PUBLIC``). A foreign table
*structurally* cannot carry RLS, so the read is unfilterable — every remote row
is returned at ``GET /rest/v1/<ft>``. This is the foreign-table sibling of
SEC049 (unfiltered table) and SEC052 (auth-user-exposing view): the same
"exposed schema + low-trust grant = HTTP-reachable" conjunction, with no
policy/predicate analysis (there are no policies to analyze).
"""
from __future__ import annotations

import pytest

from pgrls.model import ForeignTable, Grant, Schema
from pgrls.rules.sec053 import SEC053

# The default API-reachability signal SEC053 gates on: SELECT to anon. The
# grant-gate tests below override this to pin the REVOKE'd / backend-only cases.
_ANON_SELECT: tuple[Grant, ...] = (Grant(role="anon", privileges=("SELECT",)),)


def _ft(
    *,
    schema: str = "public",
    name: str = "ft",
    grants: tuple[Grant, ...] = _ANON_SELECT,
) -> ForeignTable:
    return ForeignTable(schema=schema, name=name, grants=grants)


def _check(ft: ForeignTable, **options: object) -> list[str]:
    return [v.location for v in SEC053().check(Schema(foreign_tables=(ft,)), options)]


# --- fires -----------------------------------------------------------------


def test_fires_on_anon_select_in_public() -> None:
    ft = _ft(name="stripe_customers")
    violations = SEC053().check(Schema(foreign_tables=(ft,)), {})
    assert len(violations) == 1
    out = violations[0]
    assert out.rule_id == "SEC053"
    assert out.severity == "error"
    assert out.location == "public.stripe_customers"
    assert "cannot carry RLS" in out.message
    assert "GET /rest/v1/stripe_customers" in out.message
    assert "anon" in out.message


def test_fires_on_public_pseudo_role_grant() -> None:
    assert _check(_ft(name="t", grants=(Grant(role="PUBLIC", privileges=("SELECT",)),))) == [
        "public.t"
    ]


def test_fires_on_authenticated_grant() -> None:
    assert _check(
        _ft(name="t", grants=(Grant(role="authenticated", privileges=("SELECT",)),))
    ) == ["public.t"]


def test_fires_when_select_among_other_privileges() -> None:
    # A grant bundling SELECT with others still exposes rows.
    ft = _ft(
        name="t",
        grants=(Grant(role="anon", privileges=("SELECT", "INSERT")),),
    )
    assert _check(ft) == ["public.t"]


def test_lists_multiple_low_trust_grantees() -> None:
    ft = _ft(
        name="t",
        grants=(
            Grant(role="anon", privileges=("SELECT",)),
            Grant(role="authenticated", privileges=("SELECT",)),
        ),
    )
    (out,) = SEC053().check(Schema(foreign_tables=(ft,)), {})
    # Both low-trust grantees are named, sorted, in the message.
    assert "anon, authenticated" in out.message


# --- does not fire (soundness / zero-FP) -----------------------------------


def test_no_fire_when_granted_only_to_backend_role() -> None:
    ft = _ft(
        name="internal_ledger",
        grants=(Grant(role="service_role", privileges=("SELECT",)),),
    )
    assert _check(ft) == []


def test_no_fire_when_low_trust_grant_lacks_select() -> None:
    # A non-SELECT grant (e.g. an oddly-granted INSERT) does not expose rows to
    # a read.
    ft = _ft(name="t", grants=(Grant(role="anon", privileges=("INSERT",)),))
    assert _check(ft) == []


def test_no_fire_when_ungranted() -> None:
    ft = _ft(name="t", grants=())
    assert _check(ft) == []


def test_no_fire_outside_exposed_schema() -> None:
    # Default exposed schema is public; a private-schema foreign table is not
    # API-exposed even when granted to anon.
    ft = _ft(schema="private", name="secrets")
    assert SEC053().check(Schema(foreign_tables=(ft,)), {}) == []


# --- grant gate (API-reachability; the true exposure signal) ---------------


def test_fires_when_granted_to_anon() -> None:
    ft = _ft(name="t", grants=(Grant(role="anon", privileges=("SELECT",)),))
    assert _check(ft) == ["public.t"]


def test_config_grantees_custom_excludes_default() -> None:
    ft = _ft(name="t", grants=(Grant(role="anon", privileges=("SELECT",)),))
    # anon is a default low-trust grantee → fires by default.
    assert _check(ft) == ["public.t"]
    # A deployment declaring only PUBLIC as low-trust no longer flags an
    # anon-only grant.
    assert _check(ft, grantees=["PUBLIC"]) == []


def test_config_grantees_custom_role() -> None:
    ft = _ft(name="t", grants=(Grant(role="reporting", privileges=("SELECT",)),))
    # `reporting` isn't a default low-trust grantee → no fire.
    assert _check(ft) == []
    # Declaring it makes the foreign table API-reachable in this deployment.
    assert _check(ft, grantees=["reporting"]) == ["public.t"]


def test_config_grantees_public_case_insensitive() -> None:
    # The `public` pseudo-role normalizes to the stored "PUBLIC" form, so a
    # lowercase config entry still matches a PUBLIC grant.
    ft = _ft(name="t", grants=(Grant(role="PUBLIC", privileges=("SELECT",)),))
    assert _check(ft, grantees=["public"]) == ["public.t"]


# --- configuration ---------------------------------------------------------


def test_config_schemas_extends_exposure() -> None:
    ft = _ft(schema="api", name="t")
    # Default exposed schema is public only → an api-schema foreign table is not
    # flagged.
    assert SEC053().check(Schema(foreign_tables=(ft,)), {}) == []
    # Declaring api as exposed → fires.
    hits = SEC053().check(Schema(foreign_tables=(ft,)), {"schemas": ["api"]})
    assert [h.location for h in hits] == ["api.t"]


def test_config_allowlist_bare_name_exempts() -> None:
    ft = _ft(name="pub")
    assert _check(ft, allowlist=["pub"]) == []


def test_config_allowlist_qualified_exempts() -> None:
    ft = _ft(name="pub")
    assert _check(ft, allowlist=["public.pub"]) == []


def test_config_allowlist_qualified_does_not_overmatch() -> None:
    # A qualified allowlist entry for a different schema does not exempt.
    ft = _ft(name="pub")
    assert _check(ft, allowlist=["other.pub"]) == ["public.pub"]


@pytest.mark.parametrize(
    "bad",
    [
        {"schemas": "public"},  # not a list
        {"schemas": [123]},  # not strings
        {"grantees": "anon"},  # not a list
        {"grantees": [123]},  # not strings
        {"allowlist": "public.t"},  # not a list
        {"allowlist": ["a.b.c"]},  # three parts — not a table ref
    ],
)
def test_config_validation_errors(bad: dict[str, object]) -> None:
    ft = _ft(name="t")
    with pytest.raises(TypeError):
        SEC053().check(Schema(foreign_tables=(ft,)), bad)


# --- registry / catalog ----------------------------------------------------


def test_sec053_is_registered() -> None:
    from pgrls.rules import all_rules

    ids = {r.id for r in all_rules()}
    assert "SEC053" in ids
