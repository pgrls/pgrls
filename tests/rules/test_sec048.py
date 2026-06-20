"""Unit tests for SEC048 — low-trust role can reach a non-FORCE'd owner.

SEC048 (warning) flags a role that is a member (transitively) of a table
owner that is NOT superuser/BYPASSRLS, when that owner owns an
enabled-but-not-forced RLS table: owner privileges (unlike the BYPASSRLS
*attribute* SEC029 covers) ARE reachable through membership, so the member
bypasses RLS on the owner's not-forced tables. It is the table-owner analog
of SEC029, and co-fires with SEC002 (which reports the table) by design.

The reachable-member closure (already excluding superuser/BYPASSRLS owners
and members — conditions 3 and 4 of the spec) is computed at introspection
time and stored on `Schema.owner_reachable_members`; these tests construct
that field directly, plus the `Table(owner=...)` rows the message reads for
its example-table clause. The introspection-side exclusions are exercised by
the live test in tests/test_introspect.py.
"""
from __future__ import annotations

import pytest

from pgrls.model import OwnerReachableMember, Schema, Table
from pgrls.rules.sec048 import SEC048


def _table(
    *,
    owner: str = "app_owner",
    name: str = "orders",
    rls_enabled: bool = True,
    force_rls: bool = False,
) -> Table:
    return Table(
        schema="public",
        name=name,
        rls_enabled=rls_enabled,
        force_rls=force_rls,
        policies=(),
        owner=owner,
    )


def _member(
    *,
    member: str = "app",
    via_owners: tuple[str, ...] = ("app_owner",),
    member_can_login: bool = True,
) -> OwnerReachableMember:
    return OwnerReachableMember(
        member=member,
        via_owners=via_owners,
        member_can_login=member_can_login,
    )


def _schema(
    *members: OwnerReachableMember, tables: tuple[Table, ...] = ()
) -> Schema:
    return Schema(tables=tables, owner_reachable_members=members)


# --- firing --------------------------------------------------------------


def test_sec048_fires_on_member_of_non_forced_owner() -> None:
    schema = _schema(_member(), tables=(_table(),))
    [v] = SEC048().check(schema, options={})
    assert v.rule_id == "SEC048"
    assert v.severity == "warning"
    assert v.location == "app"
    assert "'app_owner'" in v.message
    assert "FORCE ROW LEVEL SECURITY" in v.message
    assert "allowlist" in v.message


def test_sec048_names_example_exposed_table() -> None:
    # The message names an example owned, enabled-not-forced table so the
    # operator can see what is exposed.
    schema = _schema(_member(), tables=(_table(name="orders"),))
    [v] = SEC048().check(schema, options={})
    assert "public.orders" in v.message


def test_sec048_login_member_message() -> None:
    schema = _schema(_member(member_can_login=True), tables=(_table(),))
    [v] = SEC048().check(schema, options={})
    assert "LOGIN role" in v.message
    assert "authenticating as it bypasses RLS directly" in v.message


def test_sec048_nologin_member_message() -> None:
    schema = _schema(
        _member(member="batch", member_can_login=False), tables=(_table(),)
    )
    [v] = SEC048().check(schema, options={})
    assert "NOLOGIN role" in v.message


def test_sec048_names_multiple_reachable_owners() -> None:
    schema = _schema(
        _member(via_owners=("app_owner", "report_owner")),
        tables=(_table(owner="app_owner"),),
    )
    [v] = SEC048().check(schema, options={})
    assert "'app_owner', 'report_owner'" in v.message


def test_sec048_one_violation_per_member() -> None:
    # Transitive M -> mid -> O: both the deep member and the intermediate hop
    # are reachable members, each surfaced once at its own location.
    schema = _schema(
        _member(member="app", member_can_login=True),
        _member(member="mid", member_can_login=False),
        tables=(_table(),),
    )
    locs = sorted(v.location for v in SEC048().check(schema, options={}))
    assert locs == ["app", "mid"]


def test_sec048_fires_even_without_example_table_in_scope() -> None:
    # The closure guarantees the owner owns an enabled-not-forced table, but
    # if that table is out of the scanned `tables` set (only its owner is
    # known via the closure), the rule still fires — just without the example
    # clause. This is the snapshot-built case where the closure was captured
    # but the table rows are a different schema selection.
    schema = _schema(_member(), tables=())
    [v] = SEC048().check(schema, options={})
    assert v.location == "app"
    assert "for example" not in v.message


# --- silent / no-fire (FP boundary) --------------------------------------


def test_sec048_silent_when_no_reachable_members() -> None:
    # The common case: nobody can reach a non-forced owner. This subsumes the
    # spec's no-fire cases that the *introspection* closure already filters —
    # a FORCE'd-only owner, a superuser/BYPASSRLS owner or member, a
    # non-member low-trust role — all yield an empty closure.
    assert SEC048().check(_schema(tables=(_table(),)), options={}) == []


def test_sec048_silent_when_owner_only_owns_forced_table_reported_empty() -> (
    None
):
    # Defensive: even if a (hypothetical) closure entry slipped through for an
    # owner whose tables are all FORCE'd, the message's example lookup finds
    # no enabled-not-forced table. The rule still reports (the closure is the
    # source of truth for the verdict), but names no forced table as the
    # example — never a false "exposed table". In practice the closure is
    # empty for such an owner; this pins the example-omission behaviour.
    schema = _schema(_member(), tables=(_table(force_rls=True),))
    [v] = SEC048().check(schema, options={})
    assert "for example" not in v.message
    assert "public.orders" not in v.message


# --- allowlist (member) --------------------------------------------------


def test_sec048_respects_member_allowlist() -> None:
    schema = _schema(_member(), tables=(_table(),))
    assert SEC048().check(schema, options={"allowlist": ["app"]}) == []


def test_sec048_allowlist_is_per_member() -> None:
    schema = _schema(
        _member(member="app"),
        _member(member="batch", member_can_login=False),
        tables=(_table(),),
    )
    findings = SEC048().check(schema, options={"allowlist": ["app"]})
    assert [v.location for v in findings] == ["batch"]


def test_sec048_raises_on_malformed_allowlist() -> None:
    schema = _schema(_member(), tables=(_table(),))
    with pytest.raises(TypeError):
        SEC048().check(schema, options={"allowlist": "app"})


def test_sec048_raises_on_whitespace_allowlist_entry() -> None:
    schema = _schema(_member(), tables=(_table(),))
    with pytest.raises(TypeError):
        SEC048().check(schema, options={"allowlist": [" app "]})


# --- trusted_owner_roles -------------------------------------------------


def test_sec048_trusted_owner_role_suppresses() -> None:
    schema = _schema(_member(), tables=(_table(),))
    out = SEC048().check(
        schema, options={"trusted_owner_roles": ["app_owner"]}
    )
    assert out == []


def test_sec048_trusted_owner_only_drops_that_owner() -> None:
    # Member reaches two owners; trusting one leaves the finding (via the
    # other untrusted owner), and the message names only the untrusted owner.
    schema = _schema(
        _member(via_owners=("app_owner", "report_owner")),
        tables=(_table(owner="app_owner"),),
    )
    [v] = SEC048().check(
        schema, options={"trusted_owner_roles": ["app_owner"]}
    )
    assert "'report_owner'" in v.message
    assert "'app_owner'" not in v.message


def test_sec048_trusted_all_owners_suppresses_member() -> None:
    schema = _schema(
        _member(via_owners=("app_owner", "report_owner")),
        tables=(_table(),),
    )
    out = SEC048().check(
        schema,
        options={"trusted_owner_roles": ["app_owner", "report_owner"]},
    )
    assert out == []


def test_sec048_raises_on_malformed_trusted_owner_roles() -> None:
    schema = _schema(_member(), tables=(_table(),))
    with pytest.raises(TypeError):
        SEC048().check(schema, options={"trusted_owner_roles": "app_owner"})


def test_sec048_raises_on_empty_trusted_owner_role_entry() -> None:
    schema = _schema(_member(), tables=(_table(),))
    with pytest.raises(TypeError):
        SEC048().check(schema, options={"trusted_owner_roles": [""]})


# --- pre-v21 snapshot (fail-closed) --------------------------------------


def test_sec048_abstains_on_pre_v21_snapshot() -> None:
    # A pre-v21 snapshot decodes `owner_reachable_members=()` (and table
    # owners as ""), so SEC048 finds nothing — fail-closed, exactly like
    # SEC042/SEC047 on old snapshots. Model that with the empty default.
    old_style = Schema(
        tables=(
            Table(
                schema="public",
                name="orders",
                rls_enabled=True,
                force_rls=False,
                policies=(),
                # owner defaults to "" on a pre-v21 decode
            ),
        ),
    )
    assert SEC048().check(old_style, options={}) == []
