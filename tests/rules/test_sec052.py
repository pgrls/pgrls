"""Unit tests for SEC052 — auth user table exposed through an API-schema view.

SEC052 (error) fires when a view (or matview) in a PostgREST-exposed schema
(default ``public``) reads a sensitive auth table (default ``auth.users``) as a
FROM-clause source *without* scoping the read to the calling user, and — for a
regular view — without ``security_invoker``. The caller-binding analysis is the
same one SEC036 uses (shared via ``pgrls.rules._auth_binding``): a view filtered
to ``id = auth.uid()`` is a legitimate "my account" view and must not fire.
"""
from __future__ import annotations

import pytest

from pgrls.model import Grant, Schema, View
from pgrls.rules.sec052 import SEC052

# Default: granted SELECT to PUBLIC — the API-reachability signal SEC052 gates
# on. The grant-gate tests below override this to pin the REVOKE'd / backend-
# only cases.
_PUBLIC_SELECT: tuple[Grant, ...] = (Grant(role="PUBLIC", privileges=("SELECT",)),)


def _view(
    *,
    schema: str = "public",
    name: str = "v",
    definition: str,
    is_materialized: bool = False,
    security_invoker: bool = False,
    references: tuple[tuple[str, str], ...] = (("auth", "users"),),
    grants: tuple[Grant, ...] = _PUBLIC_SELECT,
) -> View:
    return View(
        schema=schema,
        name=name,
        is_materialized=is_materialized,
        security_invoker=security_invoker,
        security_barrier=False,
        definition=definition,
        references=references,
        security_definer_calls=(),
        grants=grants,
    )


def _check(view: View, **options: object) -> list[str]:
    return [v.location for v in SEC052().check(Schema(views=(view,)), options)]


# --- fires -----------------------------------------------------------------


def test_fires_on_unfiltered_auth_users_view() -> None:
    v = _view(name="users", definition="SELECT id, email FROM auth.users")
    violations = SEC052().check(Schema(views=(v,)), {})
    assert len(violations) == 1
    out = violations[0]
    assert out.rule_id == "SEC052"
    assert out.severity == "error"
    assert out.location == "public.users"
    assert "auth.users" in out.message
    assert "GET /rest/v1/users" in out.message
    assert "security_invoker" in out.message


def test_fires_on_select_star() -> None:
    assert _check(_view(name="u", definition="SELECT * FROM auth.users")) == [
        "public.u"
    ]


def test_fires_on_non_caller_where_filter() -> None:
    # A WHERE that does not bind the caller (deleted_at IS NULL still exposes
    # every non-deleted user) is not a caller scope.
    v = _view(
        name="active",
        definition="SELECT email FROM auth.users WHERE deleted_at IS NULL",
    )
    assert _check(v) == ["public.active"]


def test_fires_on_join_exposing_auth_users() -> None:
    # auth.users reached through a JOIN, no caller binding → the emails of every
    # order-owner leak.
    v = _view(
        name="order_users",
        definition=(
            "SELECT o.id, u.email FROM public.orders o "
            "JOIN auth.users u ON u.id = o.owner_id"
        ),
        references=(("auth", "users"), ("public", "orders")),
    )
    assert _check(v) == ["public.order_users"]


def test_fires_on_materialized_view_even_with_invoker_flag() -> None:
    # A matview physically stores the rows and is read with the reader's grant,
    # so security_invoker is moot — it is always in scope.
    v = _view(
        name="users_mv",
        definition="SELECT * FROM auth.users",
        is_materialized=True,
        security_invoker=True,
    )
    assert _check(v) == ["public.users_mv"]


def test_fires_on_derived_table_exposure() -> None:
    v = _view(
        name="d",
        definition="SELECT s.email FROM (SELECT id, email FROM auth.users) s",
    )
    assert _check(v) == ["public.d"]


# --- does not fire (soundness / zero-FP) -----------------------------------


def test_no_fire_when_security_invoker() -> None:
    # An invoker view runs as the caller, who has no SELECT on auth.users → the
    # query errors, it does not leak.
    v = _view(
        name="users",
        definition="SELECT * FROM auth.users",
        security_invoker=True,
    )
    assert _check(v) == []


def test_no_fire_when_scoped_to_caller() -> None:
    # The canonical "my account" view — scoped to the caller's own row.
    v = _view(
        name="me",
        definition="SELECT id, email FROM auth.users WHERE id = auth.uid()",
    )
    assert _check(v) == []


def test_no_fire_when_scoped_via_select_wrapped_auth_uid() -> None:
    # The PERF001-recommended `(SELECT auth.uid())` wrap still binds the caller.
    v = _view(
        name="me",
        definition=(
            "SELECT email FROM auth.users WHERE id = (SELECT auth.uid())"
        ),
    )
    assert _check(v) == []


def test_no_fire_when_scoped_via_current_setting() -> None:
    v = _view(
        name="me",
        definition=(
            "SELECT email FROM auth.users "
            "WHERE id = current_setting('request.jwt.claim.sub')::uuid"
        ),
    )
    assert _check(v) == []


def test_no_fire_when_derived_table_bound_in_outer_where() -> None:
    v = _view(
        name="m",
        definition=(
            "SELECT s.email FROM (SELECT id, email FROM auth.users) s "
            "WHERE s.id = auth.uid()"
        ),
    )
    assert _check(v) == []


def test_no_fire_outside_exposed_schema() -> None:
    v = _view(
        schema="private",
        name="users",
        definition="SELECT * FROM auth.users",
    )
    # Default exposed schema is public; a private-schema view is not API-exposed.
    assert SEC052().check(Schema(views=(v,)), {}) == []


def test_no_fire_when_auth_users_only_in_where_subquery() -> None:
    # auth.users used only to FILTER (a membership test), not as a FROM source
    # whose columns reach the output — not a PII exposure.
    v = _view(
        name="orders",
        definition=(
            "SELECT * FROM public.orders "
            "WHERE owner_id IN (SELECT id FROM auth.users)"
        ),
        references=(("auth", "users"), ("public", "orders")),
    )
    assert _check(v) == []


def test_no_fire_on_unparseable_definition() -> None:
    # Abstain rather than guess — soundness over recall.
    assert _check(_view(name="x", definition="this is not valid sql ;;;")) == []


def test_no_fire_when_no_sensitive_reference() -> None:
    v = _view(
        name="plain",
        definition="SELECT * FROM public.orders",
        references=(("public", "orders"),),
    )
    assert _check(v) == []


def test_no_fire_on_transitive_reexposer() -> None:
    # `public.a` selects from `public.b` (which reads auth.users). `a`'s own
    # body doesn't read auth.users, so its caller-binding can't be judged here;
    # the direct reader `b` is what SEC052 flags. `a.references` is transitive
    # (includes auth.users) but the body parse is authoritative.
    a = _view(
        name="a",
        definition="SELECT * FROM public.b",
        references=(("auth", "users"), ("public", "b")),
    )
    assert _check(a) == []


# --- grant gate (API-reachability; the true exposure signal) ---------------


def test_no_fire_when_view_not_granted_to_low_trust() -> None:
    # A public-schema view over auth.users REVOKE'd from anon/authenticated
    # (readable only by postgres/service_role) is NOT API-reachable → no fire,
    # even though it sits in the exposed schema and reads auth.users unbound.
    v = _view(name="internal", definition="SELECT * FROM auth.users", grants=())
    assert _check(v) == []


def test_no_fire_when_granted_only_to_backend_role() -> None:
    v = _view(
        name="dump",
        definition="SELECT * FROM auth.users",
        grants=(Grant(role="service_role", privileges=("SELECT",)),),
    )
    assert _check(v) == []


def test_no_fire_when_low_trust_grant_lacks_select() -> None:
    # A non-SELECT grant (e.g. an oddly-granted TRIGGER) does not expose rows.
    v = _view(
        name="odd",
        definition="SELECT * FROM auth.users",
        grants=(Grant(role="anon", privileges=("TRIGGER",)),),
    )
    assert _check(v) == []


def test_fires_when_granted_to_anon() -> None:
    v = _view(
        name="u",
        definition="SELECT * FROM auth.users",
        grants=(Grant(role="anon", privileges=("SELECT",)),),
    )
    assert _check(v) == ["public.u"]


def test_config_grantees_custom() -> None:
    v = _view(
        name="u",
        definition="SELECT * FROM auth.users",
        grants=(Grant(role="reporting", privileges=("SELECT",)),),
    )
    # `reporting` isn't a default low-trust grantee → no fire.
    assert _check(v) == []
    # Declaring it makes the view API-reachable in this deployment → fires.
    assert _check(v, grantees=["reporting"]) == ["public.u"]


# --- configuration ---------------------------------------------------------


def test_config_schemas_extends_exposure() -> None:
    v = _view(
        schema="api",
        name="users",
        definition="SELECT * FROM auth.users",
    )
    # Default exposed schema is public only → an api-schema view is not flagged.
    assert SEC052().check(Schema(views=(v,)), {}) == []
    # Declaring api as exposed → fires.
    hits = SEC052().check(Schema(views=(v,)), {"schemas": ["api"]})
    assert [h.location for h in hits] == ["api.users"]


def test_config_tables_custom_sensitive_target() -> None:
    v = _view(
        name="idents",
        definition="SELECT * FROM auth.identities",
        references=(("auth", "identities"),),
    )
    # Default targets only auth.users → no fire.
    assert _check(v) == []
    # Add auth.identities → fires.
    assert _check(v, tables=["auth.identities"]) == ["public.idents"]


def test_config_allowlist_exempts_view() -> None:
    v = _view(name="users", definition="SELECT * FROM auth.users")
    assert _check(v, allowlist=["public.users"]) == []


def test_config_binding_functions_custom() -> None:
    # A project whose caller binding is a custom function.
    v = _view(
        name="me",
        definition="SELECT email FROM auth.users WHERE id = app.current_uid()",
    )
    # Default binding set doesn't include app.current_uid → fires.
    assert _check(v) == ["public.me"]
    # Declaring it as a binding signal clears the finding.
    assert _check(v, binding_functions=["app.current_uid"]) == []


@pytest.mark.parametrize(
    "bad",
    [
        {"tables": ["auth"]},  # not schema.table
        {"tables": ["a.b.c"]},
        {"tables": "auth.users"},  # not a list
        {"binding_functions": "auth.uid"},  # not a list
        {"schemas": [123]},  # not strings
    ],
)
def test_config_validation_errors(bad: dict[str, object]) -> None:
    v = _view(name="u", definition="SELECT * FROM auth.users")
    with pytest.raises(TypeError):
        SEC052().check(Schema(views=(v,)), bad)


# --- registry / catalog ----------------------------------------------------


def test_sec052_is_registered() -> None:
    from pgrls.rules import all_rules

    ids = {r.id for r in all_rules()}
    assert "SEC052" in ids
