"""Unit tests for SEC042 — anonymously-executable SECURITY DEFINER bypass.

SEC042 (error) fires on a SECURITY DEFINER function when BOTH hold: its owner
bypasses RLS (`owner_bypasses_rls` — superuser or BYPASSRLS) AND it is
EXECUTE-able by a configured low-trust role (default `anon` / `PUBLIC`, where
`PUBLIC` also covers the no-REVOKE default-EXECUTE case). Either condition
alone is silent: a non-exempt owner is still subject to RLS (so no bypass),
and a function reachable only by trusted roles is not an anonymous endpoint.
It is the sharp, high-severity subset of SEC014 (which audits every SECDEF
function). Snapshots predating v16 carry empty `execute_roles`, so SEC042
abstains (fail-closed).
"""
from __future__ import annotations

from pgrls.model import Schema, SecdefFunction
from pgrls.rules.sec042 import SEC042


def _f(
    name: str,
    *,
    owner_bypasses_rls: bool,
    execute_roles: tuple[str, ...],
    language: str = "sql",
    signature: str = "",
    schema: str = "public",
) -> SecdefFunction:
    return SecdefFunction(
        qualified_name=f"{schema}.{name}",
        body="SELECT * FROM secrets",
        language=language,
        schema_name=schema,
        function_name=name,
        signature=signature,
        execute_roles=execute_roles,
        owner_bypasses_rls=owner_bypasses_rls,
    )


def _check(*fns: SecdefFunction, options: dict | None = None) -> list:
    schema = Schema(tables=(), security_definer_functions=fns)
    return SEC042().check(schema, options=options or {})


# --- firing --------------------------------------------------------------


def test_fires_on_default_public_execute_superuser_owner() -> None:
    # The canonical footgun: a SECDEF function owned by a superuser, left at
    # the default EXECUTE TO PUBLIC (introspection expands the default to
    # execute_roles=("PUBLIC",)).
    [v] = _check(_f("all_orders", owner_bypasses_rls=True, execute_roles=("PUBLIC",)))
    assert v.rule_id == "SEC042"
    assert v.severity == "error"
    assert v.location == "public.all_orders"
    assert "PUBLIC" in v.message
    assert "POST /rpc/all_orders" in v.message  # PostgREST framing


def test_fires_on_explicit_anon_grant() -> None:
    [v] = _check(_f("rpc", owner_bypasses_rls=True, execute_roles=("anon",)))
    assert v.location == "public.rpc"
    assert "anon" in v.message


def test_fires_on_bypassrls_nonsuper_owner() -> None:
    # owner_bypasses_rls is true for a BYPASSRLS (non-superuser) owner too.
    [v] = _check(_f("rpc", owner_bypasses_rls=True, execute_roles=("anon", "PUBLIC")))
    assert v.location == "public.rpc"


def test_fires_on_plpgsql_function() -> None:
    # No body parsing — the exposure (anon runs RLS-exempt owner code) is
    # language-independent, so plpgsql (which pglast can't parse) still fires.
    [v] = _check(
        _f("rpc", owner_bypasses_rls=True, execute_roles=("PUBLIC",), language="plpgsql")
    )
    assert v.location == "public.rpc"


def test_public_note_only_when_public_is_a_caller() -> None:
    [pub] = _check(_f("a", owner_bypasses_rls=True, execute_roles=("PUBLIC",)))
    assert "defaults to PUBLIC" in pub.message
    [anon] = _check(_f("b", owner_bypasses_rls=True, execute_roles=("anon",)))
    assert "defaults to PUBLIC" not in anon.message


# --- not firing ----------------------------------------------------------


def test_silent_when_owner_not_rls_exempt() -> None:
    # An ordinary owner under FORCE RLS is still subject to RLS, so the SECDEF
    # function returns the owner's scoped rows, not every row — no bypass.
    assert _check(_f("ok", owner_bypasses_rls=False, execute_roles=("PUBLIC",))) == []


def test_silent_when_not_low_trust_executable() -> None:
    # EXECUTE revoked from PUBLIC and granted only to a trusted role.
    assert _check(_f("ok", owner_bypasses_rls=True, execute_roles=("app_writer",))) == []


def test_silent_on_authenticated_only_by_default() -> None:
    # `authenticated` is NOT in the default low-trust set (controlled SECDEF
    # RPCs for signed-in users are a common intentional pattern).
    assert _check(_f("ok", owner_bypasses_rls=True, execute_roles=("authenticated",))) == []


def test_silent_when_execute_roles_empty_pre_v16_snapshot() -> None:
    # A pre-v16 snapshot loads execute_roles=() → abstain (fail-closed).
    assert _check(_f("ok", owner_bypasses_rls=True, execute_roles=())) == []


# --- configuration -------------------------------------------------------


def test_authenticated_fires_when_configured() -> None:
    opts = {"anon_roles": ["anon", "PUBLIC", "authenticated"]}
    [v] = _check(
        _f("rpc", owner_bypasses_rls=True, execute_roles=("authenticated",)),
        options=opts,
    )
    assert v.location == "public.rpc"


def test_public_lowercase_in_config_matches_pseudo_role() -> None:
    opts = {"anon_roles": ["public"]}  # lowercase normalized to PUBLIC
    [v] = _check(
        _f("rpc", owner_bypasses_rls=True, execute_roles=("PUBLIC",)), options=opts
    )
    assert v.location == "public.rpc"


def test_narrowing_anon_roles_drops_public_default() -> None:
    # Configuring only ["anon"] means a default-PUBLIC function no longer
    # fires (the operator opted out of the PUBLIC default).
    opts = {"anon_roles": ["anon"]}
    assert (
        _check(_f("rpc", owner_bypasses_rls=True, execute_roles=("PUBLIC",)), options=opts)
        == []
    )


def test_allowlist_exempts_function() -> None:
    fn = _f("public_rpc", owner_bypasses_rls=True, execute_roles=("PUBLIC",))
    assert _check(fn, options={"allowlist": ["public.public_rpc"]}) == []


def test_bad_anon_roles_type_raises() -> None:
    import pytest

    fn = _f("rpc", owner_bypasses_rls=True, execute_roles=("anon",))
    with pytest.raises(TypeError):
        _check(fn, options={"anon_roles": "anon"})
    with pytest.raises(TypeError):
        _check(fn, options={"anon_roles": [1, 2]})


# --- overload dedup ------------------------------------------------------


def test_overloads_reported_once() -> None:
    a = _f("rpc", owner_bypasses_rls=True, execute_roles=("PUBLIC",), signature="integer")
    b = _f("rpc", owner_bypasses_rls=True, execute_roles=("PUBLIC",), signature="text")
    locs = [v.location for v in _check(a, b)]
    assert locs == ["public.rpc"]


def test_qualifying_overload_fires_even_if_first_overload_clean() -> None:
    # First overload not low-trust-executable, second one is → still reported
    # once (the non-qualifying first overload must not block the second).
    clean = _f("rpc", owner_bypasses_rls=True, execute_roles=("app",), signature="integer")
    leaky = _f("rpc", owner_bypasses_rls=True, execute_roles=("PUBLIC",), signature="text")
    locs = [v.location for v in _check(clean, leaky)]
    assert locs == ["public.rpc"]


def test_metadata() -> None:
    rule = SEC042()
    assert rule.id == "SEC042"
    assert rule.severity == "error"
    assert rule.title
