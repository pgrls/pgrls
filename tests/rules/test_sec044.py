"""Unit tests for SEC044 — default privileges grant future tables to PUBLIC.

SEC044 (warning) flags a ``pg_default_acl`` entry for TABLES that grants a
row-access privilege (SELECT/INSERT/UPDATE/DELETE) to a low-trust grantee
(default set ``{"PUBLIC"}``). It is a standing-config / defense-in-depth
finding: default privileges are not retroactive, so the rule fires on the
entry itself regardless of whether any table exists under it yet — a new
table whose author forgets RLS is then silently exposed.

``anon`` / ``authenticated`` are deliberately NOT flagged by default (the
RLS-gated Supabase pattern); widen via ``[lint.rules.SEC044].grantees``.
A schema-scoped entry locates to its schema name; a cluster-wide entry
(``schema=None``) locates to the ``(cluster-wide)`` sentinel.
"""
from __future__ import annotations

import pytest

from pgrls.model import DefaultPrivilege, Schema
from pgrls.rules.sec044 import SEC044


def _check(
    *defaults: DefaultPrivilege, options: dict | None = None
) -> list:
    return SEC044().check(
        Schema(default_privileges=defaults), options=options or {}
    )


def _dp(
    *,
    schema: str | None = "public",
    grantee: str = "PUBLIC",
    privileges: tuple[str, ...] = ("SELECT",),
    grantor: str | None = None,
) -> DefaultPrivilege:
    return DefaultPrivilege(
        schema=schema,
        grantee=grantee,
        privileges=privileges,
        grantor=grantor,
    )


# --- firing --------------------------------------------------------------


def test_fires_on_public_select() -> None:
    [v] = _check(_dp(grantee="PUBLIC", privileges=("SELECT",)))
    assert v.rule_id == "SEC044"
    assert v.severity == "warning"
    assert v.location == "public"
    assert "PUBLIC" in v.message
    assert "future table" in v.message.lower()
    assert "SELECT" in v.message


@pytest.mark.parametrize("priv", ["SELECT", "INSERT", "UPDATE", "DELETE"])
def test_fires_on_each_row_access_privilege(priv: str) -> None:
    [v] = _check(_dp(grantee="PUBLIC", privileges=(priv,)))
    assert v.location == "public"
    assert priv in v.message


def test_fires_only_names_row_access_privileges_in_message() -> None:
    # An entry mixing row-access and non-row-access privileges fires, and the
    # message names only the row-access ones (those are the exposure).
    [v] = _check(
        _dp(grantee="PUBLIC", privileges=("SELECT", "REFERENCES", "TRIGGER"))
    )
    assert "SELECT" in v.message
    assert "REFERENCES" not in v.message
    assert "TRIGGER" not in v.message


def test_fires_on_cluster_wide_entry_with_sentinel_location() -> None:
    # A cluster-wide default (set without IN SCHEMA, schema=None) fires and
    # locates to the (cluster-wide) sentinel.
    [v] = _check(_dp(schema=None, grantee="PUBLIC", privileges=("SELECT",)))
    assert v.location == "(cluster-wide)"
    assert "cluster-wide" in v.message
    # The REVOKE remediation for a cluster-wide entry omits IN SCHEMA — the
    # statement reads `ALTER DEFAULT PRIVILEGES REVOKE ...` with no schema.
    assert "ALTER DEFAULT PRIVILEGES REVOKE SELECT ON TABLES" in v.message


def test_message_carries_revoke_remediation_with_schema() -> None:
    [v] = _check(_dp(schema="reporting", grantee="PUBLIC"))
    assert "ALTER DEFAULT PRIVILEGES IN SCHEMA reporting REVOKE" in v.message
    assert "FROM PUBLIC" in v.message
    assert "allowlist" in v.message.lower()


def test_fires_on_two_distinct_schemas() -> None:
    locs = sorted(
        v.location
        for v in _check(
            _dp(schema="public", grantee="PUBLIC"),
            _dp(schema="reporting", grantee="PUBLIC"),
        )
    )
    assert locs == ["public", "reporting"]


# --- configuration: grantees ---------------------------------------------


def test_silent_on_anon_grantee_by_default() -> None:
    # The RLS-gated Supabase pattern: granting future tables to `anon` is
    # deliberate, so the default {PUBLIC} set does not flag it.
    assert _check(_dp(grantee="anon")) == []


def test_silent_on_authenticated_grantee_by_default() -> None:
    assert _check(_dp(grantee="authenticated")) == []


def test_fires_on_anon_when_configured_via_grantees() -> None:
    [v] = _check(
        _dp(grantee="anon"),
        options={"grantees": ["PUBLIC", "anon"]},
    )
    assert v.location == "public"
    assert "anon" in v.message


def test_grantees_public_lowercase_is_normalized() -> None:
    # A config entry of "public" matches the PUBLIC pseudo-role (case-
    # insensitively), mirroring SEC042's anon_roles normalization.
    [v] = _check(
        _dp(grantee="PUBLIC"),
        options={"grantees": ["public"]},
    )
    assert v.location == "public"


def test_configured_grantees_replaces_default_set() -> None:
    # Setting grantees to only ["anon"] drops PUBLIC from the low-trust set,
    # so a PUBLIC default no longer fires.
    assert _check(_dp(grantee="PUBLIC"), options={"grantees": ["anon"]}) == []


def test_bad_grantees_type_raises_typeerror() -> None:
    with pytest.raises(TypeError):
        _check(_dp(grantee="PUBLIC"), options={"grantees": "PUBLIC"})
    with pytest.raises(TypeError):
        _check(_dp(grantee="PUBLIC"), options={"grantees": [1, 2]})


# --- not firing ----------------------------------------------------------


@pytest.mark.parametrize(
    "privs",
    [("REFERENCES",), ("TRIGGER",), ("TRUNCATE",), ("REFERENCES", "TRIGGER")],
)
def test_silent_on_non_row_access_privileges(privs: tuple[str, ...]) -> None:
    # A default granting only REFERENCES / TRIGGER / TRUNCATE to PUBLIC does
    # not read or write a future table's rows, so it is not a row-exposure.
    assert _check(_dp(grantee="PUBLIC", privileges=privs)) == [], privs


def test_silent_on_empty_default_privileges() -> None:
    assert _check() == []


# --- configuration: allowlist --------------------------------------------


def test_allowlist_by_schema_exempts() -> None:
    assert (
        _check(_dp(schema="public"), options={"allowlist": ["public"]}) == []
    )


def test_allowlist_does_not_exempt_a_different_schema() -> None:
    [v] = _check(
        _dp(schema="public"),
        _dp(schema="reporting"),
        options={"allowlist": ["reporting"]},
    )
    assert v.location == "public"


def test_allowlist_cluster_wide_sentinel_exempts() -> None:
    # The cluster-wide entry can be allowlisted by its sentinel location.
    assert (
        _check(
            _dp(schema=None, grantee="PUBLIC"),
            options={"allowlist": ["(cluster-wide)"]},
        )
        == []
    )


def test_allowlist_suppresses_all_grantors_in_a_schema() -> None:
    # The allowlist matches on the rendered location, so allowlisting a schema
    # suppresses every default in it regardless of grantor — a deliberate
    # default is a per-schema decision, not a per-grantor one.
    assert (
        _check(
            _dp(schema="reporting", grantor="a"),
            _dp(schema="reporting", grantor="b"),
            options={"allowlist": ["reporting"]},
        )
        == []
    )


def test_allowlist_bad_type_raises_typeerror() -> None:
    with pytest.raises(TypeError):
        _check(_dp(schema="public"), options={"allowlist": "public"})


def test_allowlist_whitespace_entry_raises_typeerror() -> None:
    # Surrounding whitespace would silently fail to match — the shared
    # validator rejects it loudly.
    with pytest.raises(TypeError):
        _check(_dp(schema="public"), options={"allowlist": [" public "]})


# --- dedupe + metadata ---------------------------------------------------


def test_dedupes_per_schema_grantee() -> None:
    # Two records for the same (schema, grantee) — a defensively hand-built
    # Schema — produce a single finding.
    vs = _check(
        _dp(schema="public", grantee="PUBLIC", privileges=("SELECT",)),
        _dp(schema="public", grantee="PUBLIC", privileges=("INSERT",)),
    )
    assert len(vs) == 1
    assert vs[0].location == "public"


def test_cluster_wide_and_namesake_schema_are_distinct_findings() -> None:
    # Dedup keys on the raw schema (None vs str), not the rendered location.
    # Postgres *does* permit CREATE SCHEMA "(cluster-wide)" via a quoted
    # identifier, so a real schema of that name and a true cluster-wide entry
    # (schema=None) both render to the "(cluster-wide)" sentinel — they must
    # still be reported as two distinct exposures, not silently collapsed.
    vs = _check(
        _dp(schema=None, grantee="PUBLIC", privileges=("SELECT",)),
        _dp(schema="(cluster-wide)", grantee="PUBLIC", privileges=("SELECT",)),
    )
    assert len(vs) == 2
    # Both happen to render the same display location (intended), but the two
    # underlying entries were not deduped away.
    assert [v.location for v in vs] == ["(cluster-wide)", "(cluster-wide)"]


# --- grantor (defaclrole) ------------------------------------------------


def test_distinct_grantors_in_same_scope_are_distinct_findings() -> None:
    # pg_default_acl is keyed on (defaclrole, namespace, objtype), so two
    # defaults to PUBLIC in the same schema created FOR ROLE different grantors
    # are distinct standing rules, each needing its own FOR ROLE REVOKE — so
    # SEC044 must report both, not fold them.
    vs = _check(
        _dp(schema="public", grantee="PUBLIC", grantor="app_owner"),
        _dp(schema="public", grantee="PUBLIC", grantor="migrator"),
    )
    assert len(vs) == 2
    grantors = sorted(
        "app_owner" if "app_owner" in v.message else "migrator" for v in vs
    )
    assert grantors == ["app_owner", "migrator"]


def test_same_grantor_dedupes() -> None:
    # Same (schema, grantee, grantor) across two records still reports once.
    vs = _check(
        _dp(schema="public", grantee="PUBLIC", grantor="app_owner",
            privileges=("SELECT",)),
        _dp(schema="public", grantee="PUBLIC", grantor="app_owner",
            privileges=("INSERT",)),
    )
    assert len(vs) == 1


def test_remediation_names_grantor_with_for_role_in_schema() -> None:
    # The REVOKE must carry FOR ROLE <grantor> (before IN SCHEMA, per the
    # Postgres grammar) so it actually clears the right role's default rather
    # than silently no-opping.
    [v] = _check(_dp(schema="reporting", grantee="PUBLIC", grantor="app_owner"))
    assert (
        "ALTER DEFAULT PRIVILEGES FOR ROLE app_owner IN SCHEMA reporting "
        "REVOKE" in v.message
    )
    assert "app_owner" in v.message


def test_remediation_names_grantor_for_cluster_wide() -> None:
    # A cluster-wide entry's REVOKE carries FOR ROLE but no IN SCHEMA.
    [v] = _check(_dp(schema=None, grantee="PUBLIC", grantor="postgres"))
    assert (
        "ALTER DEFAULT PRIVILEGES FOR ROLE postgres REVOKE SELECT ON TABLES"
        in v.message
    )


def test_remediation_omits_for_role_when_grantor_absent() -> None:
    # A grantor-less entry (hand-built / pre-grantor snapshot) emits the
    # grantor-free REVOKE — no dangling "FOR ROLE None".
    [v] = _check(_dp(schema="reporting", grantee="PUBLIC", grantor=None))
    assert "ALTER DEFAULT PRIVILEGES IN SCHEMA reporting REVOKE" in v.message
    assert "FOR ROLE" not in v.message


def test_metadata() -> None:
    rule = SEC044()
    assert rule.id == "SEC044"
    assert rule.severity == "warning"
    assert rule.title
