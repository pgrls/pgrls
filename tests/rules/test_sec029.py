"""Unit tests for SEC029 — role can SET ROLE to a BYPASSRLS role.

SEC029 (warning) flags a role that is a member (transitively) of a
BYPASSRLS-carrying role and so can `SET ROLE` to it and bypass every
policy — an RLS-bypass path invisible from the role's own
attributes (BYPASSRLS is not inherited through membership). The
transitive closure is computed at introspection time and stored on
`Schema.bypassrls_escalation_roles`; these tests construct that
field directly.
"""
from __future__ import annotations

import pytest

from pgrls.model import BypassRlsEscalation, Schema
from pgrls.rules.sec029 import SEC029


def _schema(*escalations: BypassRlsEscalation) -> Schema:
    return Schema(tables=(), bypassrls_escalation_roles=escalations)


# --- firing --------------------------------------------------------------


def test_sec029_fires_on_member_of_bypassrls_role() -> None:
    schema = _schema(
        BypassRlsEscalation(member="app", via=("admin",), member_can_login=True)
    )
    [v] = SEC029().check(schema, options={})
    assert v.rule_id == "SEC029"
    assert v.severity == "warning"
    assert v.location == "app"
    assert "'admin'" in v.message
    assert "SET ROLE" in v.message
    assert "allowlist" in v.message


def test_sec029_login_member_message() -> None:
    schema = _schema(
        BypassRlsEscalation(member="app", via=("admin",), member_can_login=True)
    )
    [v] = SEC029().check(schema, options={})
    assert "LOGIN role" in v.message


def test_sec029_nologin_member_message() -> None:
    schema = _schema(
        BypassRlsEscalation(
            member="batch", via=("admin",), member_can_login=False
        )
    )
    [v] = SEC029().check(schema, options={})
    assert "NOLOGIN role" in v.message


def test_sec029_names_multiple_reachable_bypassrls_roles() -> None:
    schema = _schema(
        BypassRlsEscalation(
            member="app", via=("admin", "ops"), member_can_login=True
        )
    )
    [v] = SEC029().check(schema, options={})
    assert "'admin', 'ops'" in v.message


def test_sec029_one_violation_per_member() -> None:
    schema = _schema(
        BypassRlsEscalation(member="app", via=("admin",), member_can_login=True),
        BypassRlsEscalation(
            member="batch", via=("admin",), member_can_login=False
        ),
    )
    locs = sorted(v.location for v in SEC029().check(schema, options={}))
    assert locs == ["app", "batch"]


# --- silent --------------------------------------------------------------


def test_sec029_silent_when_no_escalation_roles() -> None:
    # The common case: no role can reach a BYPASSRLS role.
    assert SEC029().check(_schema(), options={}) == []


# --- allowlist -----------------------------------------------------------


def test_sec029_respects_role_name_allowlist() -> None:
    schema = _schema(
        BypassRlsEscalation(member="app", via=("admin",), member_can_login=True)
    )
    assert SEC029().check(schema, options={"allowlist": ["app"]}) == []


def test_sec029_allowlist_is_per_member() -> None:
    schema = _schema(
        BypassRlsEscalation(member="app", via=("admin",), member_can_login=True),
        BypassRlsEscalation(
            member="batch", via=("admin",), member_can_login=False
        ),
    )
    findings = SEC029().check(schema, options={"allowlist": ["app"]})
    assert [v.location for v in findings] == ["batch"]


def test_sec029_raises_on_malformed_allowlist() -> None:
    schema = _schema(
        BypassRlsEscalation(member="app", via=("admin",), member_can_login=True)
    )
    with pytest.raises(TypeError):
        SEC029().check(schema, options={"allowlist": "app"})
