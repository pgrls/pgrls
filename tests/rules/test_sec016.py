"""Unit tests for SEC016 — role with the BYPASSRLS attribute.

SEC016 fires on every non-superuser role carrying the BYPASSRLS
attribute. Such a role skips every row-level security policy on
every table — RLS is effectively off for it. Superuser roles are
skipped (a superuser bypasses RLS via `rolsuper` regardless, so
BYPASSRLS is redundant noise on one).
"""
from __future__ import annotations

import pytest

from pgrls.model import BypassRlsRole, Schema
from pgrls.rules.sec016 import SEC016


def _role(
    name: str,
    *,
    superuser: bool = False,
    can_login: bool = True,
) -> BypassRlsRole:
    return BypassRlsRole(
        name=name, superuser=superuser, can_login=can_login
    )


# --- firing --------------------------------------------------------------


def test_sec016_fires_on_non_superuser_bypassrls_role() -> None:
    schema = Schema(bypassrls_roles=(_role("etl_worker"),))
    [v] = SEC016().check(schema, options={})
    assert v.rule_id == "SEC016"
    assert v.severity == "warning"
    assert v.location == "etl_worker"
    assert "BYPASSRLS" in v.message
    # The fix is named explicitly so the operator can copy it.
    assert "ALTER ROLE etl_worker NOBYPASSRLS" in v.message
    assert "[lint.rules.SEC016]" in v.message


def test_sec016_skips_superuser_role() -> None:
    # A superuser bypasses RLS via rolsuper regardless of BYPASSRLS;
    # the attribute is redundant noise on one, so SEC016 stays
    # silent rather than double-reporting a far larger finding.
    schema = Schema(
        bypassrls_roles=(_role("admin", superuser=True),),
    )
    assert SEC016().check(schema, options={}) == []


def test_sec016_silent_when_no_bypassrls_roles() -> None:
    # A default cluster has no role explicitly granted BYPASSRLS;
    # introspection captures an empty tuple and SEC016 is silent.
    assert SEC016().check(Schema(), options={}) == []


def test_sec016_mixed_roles_flags_only_non_superuser() -> None:
    schema = Schema(
        bypassrls_roles=(
            _role("superadmin", superuser=True),
            _role("app_role"),
            _role("replicator", can_login=False),
        ),
    )
    flagged = {v.location for v in SEC016().check(schema, options={})}
    assert flagged == {"app_role", "replicator"}


# --- can_login message variants -----------------------------------------


def test_sec016_message_login_role_names_direct_connection() -> None:
    # A LOGIN role can be authenticated as directly — the message
    # says so, because the operator's first question is "does my
    # app connect as this?".
    schema = Schema(bypassrls_roles=(_role("app_role", can_login=True),))
    [v] = SEC016().check(schema, options={})
    assert "can log in directly" in v.message


def test_sec016_message_nologin_role_names_set_role_path() -> None:
    # A NOLOGIN role can't be connected to, but a member can
    # SET ROLE to it — the message names that reachability path so
    # the finding isn't dismissed as "nobody uses this role".
    schema = Schema(
        bypassrls_roles=(_role("replicator", can_login=False),),
    )
    [v] = SEC016().check(schema, options={})
    assert "cannot log in directly" in v.message
    assert "SET ROLE" in v.message


# --- allowlist -----------------------------------------------------------


def test_sec016_allowlist_skips_named_role() -> None:
    schema = Schema(
        bypassrls_roles=(
            _role("audited_etl"),
            _role("unaudited"),
        ),
    )
    violations = SEC016().check(
        schema, options={"allowlist": ["audited_etl"]}
    )
    assert [v.location for v in violations] == ["unaudited"]


def test_sec016_allowlist_accepts_dotted_role_name() -> None:
    # Postgres permits a literal dot in a quoted role name
    # (`CREATE ROLE "my.role"`); with no schema component there is
    # nothing to disambiguate, so the allowlist accepts it as-is.
    schema = Schema(bypassrls_roles=(_role("my.role"),))
    assert SEC016().check(
        schema, options={"allowlist": ["my.role"]}
    ) == []


def test_sec016_allowlist_rejects_empty_string() -> None:
    with pytest.raises(TypeError, match="role name"):
        SEC016().check(
            Schema(bypassrls_roles=(_role("r"),)),
            options={"allowlist": [""]},
        )


def test_sec016_allowlist_rejects_whitespace_padded_entry() -> None:
    # Byte-exact match against pg_roles.rolname; a padded entry
    # would silently never match, so it's rejected loudly.
    with pytest.raises(TypeError, match="whitespace"):
        SEC016().check(
            Schema(bypassrls_roles=(_role("r"),)),
            options={"allowlist": [" r "]},
        )


def test_sec016_allowlist_rejects_non_list() -> None:
    with pytest.raises(TypeError, match="list of strings"):
        SEC016().check(
            Schema(bypassrls_roles=(_role("r"),)),
            options={"allowlist": "r"},
        )


# --- message detail ------------------------------------------------------


def test_sec016_message_includes_allowlist_hint() -> None:
    schema = Schema(bypassrls_roles=(_role("reporting"),))
    [v] = SEC016().check(schema, options={})
    assert "'reporting'" in v.message
    assert "[lint.rules.SEC016]" in v.message


def test_sec016_message_contrasts_force_rls() -> None:
    # The message contrasts BYPASSRLS (unconditional) with the
    # table-owner bypass (stops at FORCE ROW LEVEL SECURITY) so an
    # operator who knows SEC003 doesn't assume FORCE fixes this.
    schema = Schema(bypassrls_roles=(_role("app_role"),))
    [v] = SEC016().check(schema, options={})
    assert "FORCE ROW LEVEL SECURITY" in v.message
