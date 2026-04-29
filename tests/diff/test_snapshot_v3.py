"""Unit tests for snapshot v3 round-trip and Schema.from_snapshot."""
from __future__ import annotations

import pytest

from pgrls.model import (
    Grant,
    Policy,
    SNAPSHOT_VERSION,
    Schema,
    Table,
)


def test_snapshot_version_is_3() -> None:
    assert SNAPSHOT_VERSION == 3


def test_to_snapshot_emits_grants_field() -> None:
    schema = Schema(
        tables=(
            Table(
                schema="public",
                name="invoices",
                rls_enabled=True,
                force_rls=True,
                policies=(),
                columns=("id",),
                partition_of=None,
                grants=(
                    Grant(role="authenticated", privileges=("SELECT", "INSERT")),
                ),
            ),
        )
    )
    snap = schema.to_snapshot()
    assert snap["version"] == 3
    table = snap["tables"][0]
    assert table["grants"] == [
        {"role": "authenticated", "privileges": ["SELECT", "INSERT"]}
    ]


def test_from_snapshot_round_trips_v3() -> None:
    original = Schema(
        tables=(
            Table(
                schema="public",
                name="t",
                rls_enabled=True,
                force_rls=True,
                policies=(),
                columns=("id",),
                partition_of=None,
                grants=(
                    Grant(role="authenticated", privileges=("SELECT",)),
                ),
            ),
        )
    )
    snap = original.to_snapshot()
    loaded = Schema.from_snapshot(snap)
    assert loaded == original


def test_from_snapshot_v2_yields_empty_grants() -> None:
    # Legacy snapshot — v2 lacks the `grants` field. Loader fills
    # it in as `()` per table so downstream code doesn't have to
    # special-case missing data.
    v2 = {
        "version": 2,
        "tables": [
            {
                "schema": "public",
                "name": "t",
                "rls_enabled": True,
                "force_rls": True,
                "policies": [],
                "columns": ["id"],
                "partition_of": None,
            },
        ],
    }
    loaded = Schema.from_snapshot(v2)
    assert loaded.tables[0].grants == ()


def test_from_snapshot_v1_raises_clearly() -> None:
    v1 = {"version": 1, "tables": []}
    with pytest.raises(Exception, match="version 1"):
        Schema.from_snapshot(v1)


def test_from_snapshot_unknown_version_raises() -> None:
    with pytest.raises(Exception, match="version 999"):
        Schema.from_snapshot({"version": 999, "tables": []})


def test_from_snapshot_round_trips_v3_with_policies() -> None:
    # Regression test for the to_snapshot/from_snapshot round-trip
    # with non-empty policies. to_snapshot serializes per-table
    # policies into a top-level "policies" array (with
    # table_schema/table_name/policy_name keys), but from_snapshot
    # historically only read the per-table embedded "policies" key
    # (with the "name" key) — so a round-trip through file silently
    # dropped every policy. The v0.2 demo case 81 caught this; this
    # test pins the contract going forward so a refactor of either
    # side surfaces here at unit-test time.
    original = Schema(
        tables=(
            Table(
                schema="public",
                name="t",
                rls_enabled=True,
                force_rls=True,
                policies=(
                    Policy(
                        name="tenant_isolation",
                        command="SELECT",
                        permissive=True,
                        roles=("PUBLIC",),
                        using_sql="id > 0",
                        with_check_sql=None,
                    ),
                ),
                columns=("id",),
                partition_of=None,
                grants=(),
            ),
        )
    )
    loaded = Schema.from_snapshot(original.to_snapshot())
    # Equality compare doesn't hold (loaded re-parses ASTs while
    # `original` has using_ast=None) — assert on user-facing fields
    # explicitly so the contract is visible in the test body.
    assert len(loaded.tables) == 1
    assert len(loaded.tables[0].policies) == 1
    p = loaded.tables[0].policies[0]
    assert p.name == "tenant_isolation"
    assert p.command == "SELECT"
    assert p.permissive is True
    assert p.roles == ("PUBLIC",)
    assert p.using_sql == "id > 0"
    assert p.with_check_sql is None


def test_from_snapshot_round_trips_v3_with_grants() -> None:
    # Mirror of test_from_snapshot_round_trips_v3_with_policies but for grants.
    # Pins the to_snapshot/from_snapshot round-trip contract when a table
    # carries non-empty grants.
    original = Schema(
        tables=(
            Table(
                schema="public",
                name="invoices",
                rls_enabled=True,
                force_rls=True,
                policies=(),
                columns=("id",),
                partition_of=None,
                grants=(
                    Grant(role="authenticated", privileges=("SELECT", "INSERT")),
                ),
            ),
        )
    )
    loaded = Schema.from_snapshot(original.to_snapshot())
    assert len(loaded.tables) == 1
    t = loaded.tables[0]
    assert len(t.grants) == 1
    g = t.grants[0]
    assert g.role == "authenticated"
    assert set(g.privileges) == {"SELECT", "INSERT"}


def test_from_snapshot_reparses_using_ast() -> None:
    # using_ast / with_check_ast aren't serialized; from_snapshot
    # re-parses them via parse_expr.
    snap = {
        "version": 3,
        "tables": [
            {
                "schema": "public",
                "name": "t",
                "rls_enabled": True,
                "force_rls": True,
                "columns": ["id"],
                "partition_of": None,
                "policies": [
                    {
                        "name": "p",
                        "command": "SELECT",
                        "permissive": True,
                        "roles": ["PUBLIC"],
                        "using_sql": "id > 0",
                        "with_check_sql": None,
                    }
                ],
                "grants": [],
            }
        ],
    }
    loaded = Schema.from_snapshot(snap)
    policy = loaded.tables[0].policies[0]
    assert policy.using_ast is not None
    assert policy.with_check_ast is None
