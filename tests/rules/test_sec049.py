"""Unit tests for SEC049 — PostgREST-exposed table readable by a low-trust role.

SEC049 (warning) is a *conjunction* rule: a table in a PostgREST-exposed schema
(default ``public``), granted SELECT (table- or column-level) to a low-trust
role (``anon`` / ``authenticated`` / ``PUBLIC``), whose SELECT row-access is
unrestricted — RLS off, or RLS on with a permissive ``USING (true)`` SELECT/ALL
policy and nothing restrictive to filter — is directly readable at
``GET /rest/v1/<table>``. The conservative direction is built in: an admitting
permissive policy must be provably ``true`` and any restrictive policy that
isn't provably ``true`` is assumed to protect (so the table is not flagged).
"""
from __future__ import annotations

import pytest

from pgrls.ast_utils import parse_expr
from pgrls.model import ColumnGrant, Grant, Policy, Schema, Table
from pgrls.rules.sec049 import SEC049


def _policy(
    using: str | None,
    *,
    name: str = "p",
    command: str = "SELECT",
    permissive: bool = True,
    roles: tuple[str, ...] = ("anon",),
) -> Policy:
    return Policy(
        name=name,
        command=command,  # type: ignore[arg-type]
        permissive=permissive,
        roles=roles,
        using_sql=using,
        with_check_sql=None,
        using_ast=parse_expr(using) if using else None,
        with_check_ast=None,
    )


def _table(
    *,
    schema: str = "public",
    name: str = "t",
    rls_enabled: bool = False,
    grants: tuple[Grant, ...] = (),
    column_grants: tuple[ColumnGrant, ...] = (),
    policies: tuple[Policy, ...] = (),
) -> Table:
    return Table(
        schema=schema,
        name=name,
        rls_enabled=rls_enabled,
        force_rls=False,
        policies=policies,
        grants=grants,
        column_grants=column_grants,
        columns=("id",),
    )


def _check(table: Table, options: dict | None = None) -> list:
    return SEC049().check(Schema(tables=(table,)), options=options or {})


_GRANT_ANON = (Grant(role="anon", privileges=("SELECT",)),)


# --- firing --------------------------------------------------------------


def test_fires_rls_off_grant_anon() -> None:
    [v] = _check(_table(rls_enabled=False, grants=_GRANT_ANON))
    assert v.rule_id == "SEC049"
    assert v.severity == "warning"
    assert v.location == "public.t"
    assert "anon" in v.message
    assert "GET /rest/v1/t" in v.message
    assert "RLS is disabled" in v.message


def test_fires_rls_off_grant_public() -> None:
    [v] = _check(
        _table(grants=(Grant(role="PUBLIC", privileges=("SELECT",)),))
    )
    assert "PUBLIC" in v.message


def test_fires_rls_off_grant_authenticated() -> None:
    # `authenticated` is low-trust by default: any logged-in user reading
    # every row is a cross-tenant leak.
    [v] = _check(
        _table(grants=(Grant(role="authenticated", privileges=("SELECT",)),))
    )
    assert "authenticated" in v.message


def test_fires_rls_on_permissive_true_select() -> None:
    [v] = _check(
        _table(
            rls_enabled=True,
            grants=_GRANT_ANON,
            policies=(_policy("true", command="SELECT"),),
        )
    )
    assert "permissive USING (true)" in v.message
    assert "RLS is disabled" not in v.message


def test_fires_rls_on_permissive_true_for_all() -> None:
    # A FOR ALL permissive USING (true) covers SELECT too.
    assert (
        len(
            _check(
                _table(
                    rls_enabled=True,
                    grants=_GRANT_ANON,
                    policies=(_policy("true", command="ALL"),),
                )
            )
        )
        == 1
    )


def test_fires_when_any_permissive_policy_is_true() -> None:
    # Permissive policies OR-combine: a real-predicate policy AND a USING(true)
    # policy means every row passes via the true one.
    assert (
        len(
            _check(
                _table(
                    rls_enabled=True,
                    grants=_GRANT_ANON,
                    policies=(
                        _policy("tenant_id = 1", name="scoped"),
                        _policy("true", name="open"),
                    ),
                )
            )
        )
        == 1
    )


def test_fires_on_column_level_select_grant() -> None:
    # A column GRANT SELECT (col) to anon still exposes those columns via REST.
    [v] = _check(
        _table(
            column_grants=(
                ColumnGrant(role="anon", column="email", privileges=("SELECT",)),
            )
        )
    )
    assert v.location == "public.t"


def test_restrictive_true_does_not_count_as_a_filter() -> None:
    # A restrictive USING (true) is a no-op floor (SEC031), not a row filter,
    # so a permissive-true + restrictive-true table is still wide open.
    assert (
        len(
            _check(
                _table(
                    rls_enabled=True,
                    grants=_GRANT_ANON,
                    policies=(
                        _policy("true", name="open"),
                        _policy("true", name="floor", permissive=False),
                    ),
                )
            )
        )
        == 1
    )


# --- not firing ----------------------------------------------------------


def test_silent_rls_on_real_permissive_policy() -> None:
    # The normal RLS-gated pattern: a real row-scoping predicate filters rows.
    assert (
        _check(
            _table(
                rls_enabled=True,
                grants=_GRANT_ANON,
                policies=(_policy("tenant_id = current_setting('x', true)"),),
            )
        )
        == []
    )


def test_silent_permissive_true_with_restrictive_real_filter() -> None:
    # A restrictive policy with a real predicate constrains rows even past a
    # permissive USING(true) — the table is protected, so do not flag.
    assert (
        _check(
            _table(
                rls_enabled=True,
                grants=_GRANT_ANON,
                policies=(
                    _policy("true", name="open"),
                    _policy("tenant_id = 1", name="floor", permissive=False),
                ),
            )
        )
        == []
    )


def test_silent_rls_on_no_policy_is_default_deny() -> None:
    # RLS on with no permissive policy denies every row — not exposed.
    assert _check(_table(rls_enabled=True, grants=_GRANT_ANON)) == []


def test_silent_permissive_true_only_for_insert_not_select() -> None:
    # A permissive USING(true) on an INSERT-only policy does not admit SELECT
    # rows; with no SELECT-applicable permissive policy the table is
    # default-deny for reads.
    assert (
        _check(
            _table(
                rls_enabled=True,
                grants=_GRANT_ANON,
                policies=(_policy("true", command="INSERT"),),
            )
        )
        == []
    )


def test_silent_restrictive_true_only_is_default_deny() -> None:
    # A lone restrictive USING(true) (no permissive policy) still denies every
    # row — there is no permissive policy to admit anything.
    assert (
        _check(
            _table(
                rls_enabled=True,
                grants=_GRANT_ANON,
                policies=(_policy("true", permissive=False),),
            )
        )
        == []
    )


# --- role-scoping: a USING(true) policy only exposes the roles it applies to


def test_silent_permissive_true_scoped_to_other_role() -> None:
    # The canonical Supabase backend bypass: a USING(true) policy scoped TO
    # service_role, with SELECT granted to anon. The policy does not apply to
    # anon, so anon falls to default-deny and reads zero rows — must stay
    # silent. (Regression: SEC049 used to ignore policy roles and fired here.)
    assert (
        _check(
            _table(
                rls_enabled=True,
                grants=_GRANT_ANON,
                policies=(_policy("true", roles=("service_role",)),),
            )
        )
        == []
    )


def test_silent_permissive_true_to_authenticated_grant_anon() -> None:
    # Cross-role: USING(true) TO authenticated, SELECT granted to anon only.
    assert (
        _check(
            _table(
                rls_enabled=True,
                grants=_GRANT_ANON,
                policies=(_policy("true", roles=("authenticated",)),),
            )
        )
        == []
    )


def test_fires_permissive_true_to_public_applies_to_anon() -> None:
    # A TO PUBLIC USING(true) policy applies to every role, anon included.
    [v] = _check(
        _table(
            rls_enabled=True,
            grants=_GRANT_ANON,
            policies=(_policy("true", roles=("PUBLIC",)),),
        )
    )
    assert "anon" in v.message


def test_restrictive_scoped_to_other_role_does_not_protect_anon() -> None:
    # A permissive USING(true) TO anon admits anon; a restrictive real policy
    # scoped TO some other role does not apply to anon, so it cannot rescue the
    # exposure — anon still reads every row, so SEC049 fires.
    assert (
        len(
            _check(
                _table(
                    rls_enabled=True,
                    grants=_GRANT_ANON,
                    policies=(
                        _policy("true", name="open", roles=("anon",)),
                        _policy(
                            "tenant_id = 1",
                            name="floor",
                            permissive=False,
                            roles=("other_role",),
                        ),
                    ),
                )
            )
        )
        == 1
    )


def test_only_the_unrestricted_grantee_is_reported() -> None:
    # anon gets a USING(true) policy; authenticated only a tenant-scoped one.
    # Both hold a SELECT grant, but only anon reads every row — the message
    # names anon, not authenticated.
    [v] = _check(
        _table(
            rls_enabled=True,
            grants=(
                Grant(role="anon", privileges=("SELECT",)),
                Grant(role="authenticated", privileges=("SELECT",)),
            ),
            policies=(
                _policy("true", name="open", roles=("anon",)),
                _policy("tenant_id = 1", name="scoped", roles=("authenticated",)),
            ),
        )
    )
    # The grant list names only anon (the message boilerplate contains
    # "any-authenticated", so check the "grants SELECT to <list>," phrase).
    assert "grants SELECT to anon, and" in v.message


def test_silent_grant_to_non_low_trust_role() -> None:
    assert (
        _check(
            _table(grants=(Grant(role="service_role", privileges=("SELECT",)),))
        )
        == []
    )


def test_silent_grant_without_select() -> None:
    # INSERT/UPDATE/DELETE to anon is a write surface, not a read exposure.
    assert (
        _check(_table(grants=(Grant(role="anon", privileges=("INSERT",)),)))
        == []
    )


def test_silent_table_not_in_exposed_schema() -> None:
    assert _check(_table(schema="private", grants=_GRANT_ANON)) == []


def test_silent_no_grant_at_all() -> None:
    assert _check(_table(rls_enabled=False)) == []


# --- configuration: schemas ----------------------------------------------


def test_custom_exposed_schema_fires() -> None:
    [v] = _check(
        _table(schema="api", grants=_GRANT_ANON),
        options={"schemas": ["api"]},
    )
    assert v.location == "api.t"


def test_custom_schemas_replaces_default_public() -> None:
    # Setting schemas to ["api"] drops public from the exposed set.
    assert _check(_table(schema="public", grants=_GRANT_ANON),
                  options={"schemas": ["api"]}) == []


def test_bad_schemas_type_raises_typeerror() -> None:
    # The error names the offending option (`schemas`), not `allowlist`.
    with pytest.raises(TypeError, match="schemas"):
        _check(_table(grants=_GRANT_ANON), options={"schemas": "public"})
    with pytest.raises(TypeError, match="schemas"):
        _check(_table(grants=_GRANT_ANON), options={"schemas": [" public "]})


# --- configuration: grantees ---------------------------------------------


def test_custom_grantees_adds_role() -> None:
    [v] = _check(
        _table(grants=(Grant(role="readonly", privileges=("SELECT",)),)),
        options={"grantees": ["readonly"]},
    )
    assert "readonly" in v.message


def test_grantees_public_lowercase_normalized() -> None:
    [v] = _check(
        _table(grants=(Grant(role="PUBLIC", privileges=("SELECT",)),)),
        options={"grantees": ["public"]},
    )
    assert v.location == "public.t"


def test_configured_grantees_replaces_default_set() -> None:
    # Restricting grantees to ["anon"] means an authenticated-only grant no
    # longer fires.
    assert (
        _check(
            _table(grants=(Grant(role="authenticated", privileges=("SELECT",)),)),
            options={"grantees": ["anon"]},
        )
        == []
    )


def test_bad_grantees_type_raises_typeerror() -> None:
    # The error names the offending option (`grantees`), not `allowlist`.
    with pytest.raises(TypeError, match="grantees"):
        _check(_table(grants=_GRANT_ANON), options={"grantees": "anon"})
    with pytest.raises(TypeError, match="grantees"):
        _check(_table(grants=_GRANT_ANON), options={"grantees": [1]})


def test_grantees_whitespace_entry_raises_typeerror() -> None:
    # Stray whitespace would silently never match an introspected role name;
    # the shared validator now rejects it for grantees too.
    with pytest.raises(TypeError, match="grantees"):
        _check(_table(grants=_GRANT_ANON), options={"grantees": [" anon "]})


# --- configuration: allowlist --------------------------------------------


def test_allowlist_exempts_intentionally_public_table() -> None:
    assert (
        _check(
            _table(name="countries", grants=_GRANT_ANON),
            options={"allowlist": ["public.countries"]},
        )
        == []
    )


def test_allowlist_accepts_a_bare_table_name() -> None:
    # Regression: parse_table_ref_allowlist validates a bare (unqualified)
    # entry as legal, so the membership test must honor it. It previously
    # compared against `schema.table` only, silently no-op'ing a bare-name
    # exemption and leaving the table flagged. Now uses the shared
    # `table_in_allowlist` helper (bare name OR schema.table), like the
    # other table-scoped rules.
    assert (
        _check(
            _table(name="countries", grants=_GRANT_ANON),
            options={"allowlist": ["countries"]},
        )
        == []
    )


def test_allowlist_does_not_exempt_a_different_table() -> None:
    [v] = _check(
        _table(name="invoices", grants=_GRANT_ANON),
        options={"allowlist": ["public.countries"]},
    )
    assert v.location == "public.invoices"


def test_allowlist_bare_name_does_not_exempt_a_different_table() -> None:
    [v] = _check(
        _table(name="invoices", grants=_GRANT_ANON),
        options={"allowlist": ["countries"]},
    )
    assert v.location == "public.invoices"


def test_allowlist_bad_type_raises_typeerror() -> None:
    with pytest.raises(TypeError):
        _check(_table(grants=_GRANT_ANON), options={"allowlist": "public.t"})


# --- multiple roles + metadata -------------------------------------------


def test_message_lists_all_low_trust_grantees_sorted() -> None:
    [v] = _check(
        _table(
            grants=(
                Grant(role="anon", privileges=("SELECT",)),
                Grant(role="authenticated", privileges=("SELECT",)),
            )
        )
    )
    # Sorted, comma-joined: "anon, authenticated".
    assert "anon, authenticated" in v.message


def test_metadata() -> None:
    rule = SEC049()
    assert rule.id == "SEC049"
    assert rule.severity == "warning"
    assert rule.title
