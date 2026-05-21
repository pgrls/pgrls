"""Unit tests for snapshot v3 round-trip and Schema.from_snapshot."""
from __future__ import annotations

import pytest

from pgrls.model import (
    Grant,
    Policy,
    Schema,
    Table,
)


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
    # bumped 4 → 5 in v0.5 (column_details); 5 → 6 in v0.5.8
    # (triggers); 6 → 7 in v0.5.10 (indexes); 7 → 8 in v0.5.13
    # (SecdefFunction.search_path); 8 → 9 in v0.5.14
    # (bypassrls_roles); 9 → 10 in v0.5.15 (leakproof_functions);
    # 10 → 11 in v0.5.54 (bypassrls_escalation_roles).
    # The grants test is about content, not version — pin the latest
    # so a future bump is deliberate.
    assert snap["version"] == 11
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
    # Under v0.2.1's lazy-AST contract both sides have
    # `using_ast=None` after construction, so equality holds —
    # but assert on user-facing fields explicitly so the contract
    # is visible in the test body and the test stays readable
    # without depending on dataclass `__eq__` semantics.
    assert len(loaded.tables) == 1
    assert len(loaded.tables[0].policies) == 1
    p = loaded.tables[0].policies[0]
    assert p.name == "tenant_isolation"
    assert p.command == "SELECT"
    assert p.permissive is True
    assert p.roles == ("PUBLIC",)
    assert p.using_sql == "id > 0"
    assert p.with_check_sql is None
    # Sanity-check the lazy-AST contract is actually in effect.
    assert p.using_ast is None
    assert p.with_check_ast is None


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


def test_from_snapshot_does_not_eagerly_parse_ast() -> None:
    # v0.2.1 contract change: from_snapshot leaves using_ast and
    # with_check_ast as None. The only consumer that needed the
    # AST was pgrls.diff._diff_columns, which now lazy-parses.
    # Eager parsing on load was wasted work for diffs that don't
    # drop columns — see Schema.from_snapshot docstring rationale.
    #
    # Callers that need the AST after from_snapshot must parse on
    # demand via `pgrls.ast_utils.parse_expr(policy.using_sql)`.
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
    # SQL fields survive — only the ASTs are skipped.
    assert policy.using_sql == "id > 0"
    assert policy.with_check_sql is None
    # Both ASTs are None per the new contract.
    assert policy.using_ast is None
    assert policy.with_check_ast is None


def test_diff_columns_lazy_parses_when_ast_is_none() -> None:
    # End-to-end pin: a snapshot loaded via from_snapshot has no
    # using_ast populated, but `_diff_columns` must still detect
    # column references via on-demand parsing. Without the lazy
    # path, snapshot-vs-anything diffs would silently lose the
    # COLUMN_DROPPED_REFERENCED rule.
    from pgrls.diff import ChangeKind, diff_schemas

    base_snap = {
        "version": 3,
        "tables": [
            {
                "schema": "public",
                "name": "t",
                "rls_enabled": True,
                "force_rls": True,
                "columns": ["id", "tenant_id"],
                "partition_of": None,
                "grants": [],
            }
        ],
        "policies": [
            {
                "table_schema": "public",
                "table_name": "t",
                "policy_name": "isolate",
                "command": "SELECT",
                "permissive": True,
                "roles": ["PUBLIC"],
                "using_sql": "tenant_id = 'x'",
                "with_check_sql": None,
            }
        ],
    }
    head_snap = {
        "version": 3,
        "tables": [
            {
                "schema": "public",
                "name": "t",
                "rls_enabled": True,
                "force_rls": True,
                "columns": ["id"],  # tenant_id dropped
                "partition_of": None,
                "grants": [],
            }
        ],
        "policies": [
            {
                "table_schema": "public",
                "table_name": "t",
                "policy_name": "isolate",
                "command": "SELECT",
                "permissive": True,
                "roles": ["PUBLIC"],
                "using_sql": "tenant_id = 'x'",  # still references the dropped column
                "with_check_sql": None,
            }
        ],
    }
    base = Schema.from_snapshot(base_snap)
    head = Schema.from_snapshot(head_snap)
    # Pre-condition: ASTs are None (lazy contract).
    assert base.tables[0].policies[0].using_ast is None
    assert head.tables[0].policies[0].using_ast is None

    changes = diff_schemas(base, head)
    column_changes = [
        c for c in changes if c.kind == ChangeKind.COLUMN_DROPPED_REFERENCED
    ]
    assert len(column_changes) == 1
    assert column_changes[0].location == "public.t.tenant_id"
    assert column_changes[0].classification == "requires_review"


def test_diff_columns_lazy_parses_with_check_sql_path() -> None:
    # Mirror of test_diff_columns_lazy_parses_when_ast_is_none for
    # the with_check_sql branch of the lazy-parse loop. Both
    # branches share identical structure; this test pins the
    # with-check half so a regression that drops the second
    # iteration of the per-policy loop surfaces here.
    from pgrls.diff import ChangeKind, diff_schemas

    base_snap = {
        "version": 3,
        "tables": [
            {
                "schema": "public",
                "name": "t",
                "rls_enabled": True,
                "force_rls": True,
                "columns": ["id", "tenant_id"],
                "partition_of": None,
                "grants": [],
            }
        ],
        "policies": [
            {
                "table_schema": "public",
                "table_name": "t",
                "policy_name": "isolate",
                "command": "INSERT",
                "permissive": True,
                "roles": ["PUBLIC"],
                "using_sql": None,
                # The reference lives in WITH CHECK, not USING.
                "with_check_sql": "tenant_id = 'x'",
            }
        ],
    }
    head_snap = {
        "version": 3,
        "tables": [
            {
                "schema": "public",
                "name": "t",
                "rls_enabled": True,
                "force_rls": True,
                "columns": ["id"],  # tenant_id dropped
                "partition_of": None,
                "grants": [],
            }
        ],
        "policies": [
            {
                "table_schema": "public",
                "table_name": "t",
                "policy_name": "isolate",
                "command": "INSERT",
                "permissive": True,
                "roles": ["PUBLIC"],
                "using_sql": None,
                "with_check_sql": "tenant_id = 'x'",
            }
        ],
    }
    base = Schema.from_snapshot(base_snap)
    head = Schema.from_snapshot(head_snap)
    assert head.tables[0].policies[0].with_check_ast is None

    changes = diff_schemas(base, head)
    column_changes = [
        c for c in changes if c.kind == ChangeKind.COLUMN_DROPPED_REFERENCED
    ]
    assert len(column_changes) == 1
    assert column_changes[0].location == "public.t.tenant_id"
