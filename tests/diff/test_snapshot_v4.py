"""Unit tests for snapshot v4 round-trip and view metadata."""
from __future__ import annotations

import pytest

from pgrls.model import (
    SNAPSHOT_VERSION,
    BypassRlsEscalation,
    BypassRlsRole,
    Index,
    LeakproofFunction,
    Policy,
    Schema,
    SecdefFunction,
    Table,
    Trigger,
    View,
)


def test_snapshot_version_is_14() -> None:
    # Bumped 13 → 14 to add separate schema_name / function_name to
    # SecdefFunction and LeakproofFunction. v3–v13 baselines still load
    # (Schema.from_snapshot accepts 3 through 14).
    assert SNAPSHOT_VERSION == 15


def test_to_snapshot_emits_views_field() -> None:
    schema = Schema(
        tables=(),
        views=(
            View(
                schema="public",
                name="invoices_v",
                is_materialized=False,
                security_invoker=True,
                security_barrier=False,
                definition="SELECT * FROM public.invoices",
                references=(("public", "invoices"),),
                security_definer_calls=(),
            ),
        ),
    )
    snap = schema.to_snapshot()
    # views added at v4; v5 added column_details; v6 added triggers;
    # v7 added indexes; v8 added SecdefFunction.search_path; v9
    # added bypassrls_roles; v10 added leakproof_functions; v11
    # added bypassrls_escalation_roles (all additive and orthogonal
    # to the views field this test exercises).
    assert snap["version"] == 15
    assert "views" in snap
    assert snap["views"][0]["name"] == "invoices_v"
    assert snap["views"][0]["security_invoker"] is True
    assert snap["views"][0]["references"] == [["public", "invoices"]]


def test_from_snapshot_round_trips_v4_with_views() -> None:
    original = Schema(
        tables=(),
        views=(
            View(
                schema="public",
                name="orders_mv",
                is_materialized=True,
                security_invoker=False,
                security_barrier=True,
                definition="SELECT * FROM public.orders",
                references=(("public", "orders"),),
                security_definer_calls=("public.audit_lookup",),
            ),
        ),
    )
    loaded = Schema.from_snapshot(original.to_snapshot())
    assert loaded.views == original.views


def test_from_snapshot_v3_yields_empty_views() -> None:
    # v3 snapshots load fine but have no view data — `Schema.views`
    # is `()`. Confirms the v3 → v4 boundary is non-breaking on
    # the load side; the missing data is just absent.
    v3 = {
        "version": 3,
        "tables": [],
        "policies": [],
    }
    loaded = Schema.from_snapshot(v3)
    assert loaded.views == ()


def test_from_snapshot_rejects_v2_with_clear_message() -> None:
    # v2 was supported in v0.2.x; v0.3.0 drops it. Test pins
    # the rejection so a future "let's add v2 back for legacy
    # users" change makes the deliberate cut visible.
    v2 = {
        "version": 2,
        "tables": [],
    }
    with pytest.raises(Exception, match="version 2"):
        Schema.from_snapshot(v2)


def test_from_snapshot_rejects_unknown_version() -> None:
    with pytest.raises(Exception, match="version 999"):
        Schema.from_snapshot({"version": 999, "tables": []})


def test_to_snapshot_emits_security_definer_functions_field() -> None:
    schema = Schema(
        tables=(),
        views=(),
        security_definer_functions=(
            SecdefFunction(
                qualified_name="public.read_secret",
                body="SELECT * FROM public.secret",
                language="sql",
            ),
        ),
    )
    snap = schema.to_snapshot()
    assert "security_definer_functions" in snap
    # `search_path` is the v8 addition — defaults to None when the
    # SecdefFunction is constructed without it (as here).
    # `signature` is the v12 addition — defaults to "" when omitted.
    # `schema_name` / `function_name` are the v14 additions — default
    # to "" when the SecdefFunction is built without them (as here).
    assert snap["security_definer_functions"] == [
        {
            "qualified_name": "public.read_secret",
            "body": "SELECT * FROM public.secret",
            "language": "sql",
            "search_path": None,
            "signature": "",
            "schema_name": "",
            "function_name": "",
        }
    ]


def test_from_snapshot_round_trips_v4_with_security_definer_functions() -> None:
    original = Schema(
        tables=(),
        views=(),
        security_definer_functions=(
            SecdefFunction(
                qualified_name="public.read_secret",
                body="SELECT * FROM public.secret",
                language="sql",
            ),
            SecdefFunction(
                qualified_name="public.audit_lookup",
                body="DECLARE r RECORD; BEGIN ... END;",
                language="plpgsql",
            ),
        ),
    )
    loaded = Schema.from_snapshot(original.to_snapshot())
    assert loaded.security_definer_functions == original.security_definer_functions


def test_from_snapshot_v4_without_security_definer_functions_loads_clean() -> None:
    # An older v4 snapshot written before the additive
    # `security_definer_functions` extension shipped — the field is
    # absent from the JSON. Loading must succeed and yield `()`.
    legacy_v4 = {
        "version": 4,
        "tables": [],
        "policies": [],
        "views": [],
    }
    loaded = Schema.from_snapshot(legacy_v4)
    assert loaded.security_definer_functions == ()


def test_from_snapshot_v3_yields_empty_security_definer_functions() -> None:
    # v3 has no `security_definer_functions`; load must succeed and
    # the field defaults to an empty tuple.
    v3 = {
        "version": 3,
        "tables": [],
        "policies": [],
    }
    loaded = Schema.from_snapshot(v3)
    assert loaded.security_definer_functions == ()


def test_from_snapshot_round_trips_v6_with_triggers() -> None:
    # SEC013 reads `Table.triggers` from the snapshot. If a future
    # refactor of `to_snapshot` / `from_snapshot` drifts the field
    # names (e.g. renaming `function_schema` to `func_schema`), the
    # write/read pair stays internally consistent inside a single
    # process — so a unit test that only checks `to_snapshot()`
    # output won't catch it. Round-tripping through `json.dumps`
    # forces the JSON shape to match what a file-persisted snapshot
    # carries, the way `pgrls diff` actually exercises the contract.
    import json

    original = Schema(
        tables=(
            Table(
                schema="public",
                name="invoices",
                rls_enabled=True,
                force_rls=True,
                policies=(
                    Policy(
                        name="tenant_read",
                        command="SELECT",
                        permissive=True,
                        roles=("authenticated",),
                        using_sql="tenant_id = current_setting('app.tenant')",
                        with_check_sql=None,
                    ),
                ),
                triggers=(
                    Trigger(
                        name="audit_insert",
                        function_schema="audit",
                        function_name="log_change",
                        event="INSERT OR UPDATE",
                        timing="BEFORE",
                        enabled=True,
                    ),
                    Trigger(
                        name="disabled_legacy",
                        function_schema="public",
                        function_name="old_handler",
                        event="DELETE",
                        timing="AFTER",
                        enabled=False,
                    ),
                ),
            ),
        ),
    )
    snap_json = json.dumps(original.to_snapshot())
    loaded = Schema.from_snapshot(json.loads(snap_json))
    assert loaded.tables[0].triggers == original.tables[0].triggers
    assert loaded == original


def test_from_snapshot_v5_yields_empty_triggers() -> None:
    # v5 (released as v0.5.x prior to SEC013) has no `triggers`
    # field on table entries. Loading must succeed and the field
    # defaults to `()` — SEC013 then simply finds nothing to flag
    # against the older snapshot until it's re-captured.
    v5 = {
        "version": 5,
        "tables": [
            {
                "schema": "public",
                "name": "t",
                "rls_enabled": True,
                "force_rls": True,
                "columns": ["id"],
                "partition_of": None,
                "grants": [],
                "column_details": [],
            }
        ],
        "policies": [],
        "views": [],
        "security_definer_functions": [],
    }
    loaded = Schema.from_snapshot(v5)
    assert loaded.tables[0].triggers == ()


def test_from_snapshot_round_trips_v7_with_indexes() -> None:
    # PERF003 reads `Table.indexes` from the snapshot. If a future
    # refactor of `to_snapshot` / `from_snapshot` drifts the field
    # names (e.g. renaming `is_partial` → `partial`), the write/
    # read pair stays internally consistent inside a single
    # process — so a unit test that only checks `to_snapshot()`
    # output won't catch it. Round-tripping through `json.dumps`
    # forces the JSON shape to match what a file-persisted snapshot
    # carries, the way `pgrls diff` actually exercises the contract.
    # Mirrors `test_from_snapshot_round_trips_v6_with_triggers`.
    import json

    original = Schema(
        tables=(
            Table(
                schema="public",
                name="invoices",
                rls_enabled=True,
                force_rls=True,
                policies=(
                    Policy(
                        name="tenant_read",
                        command="SELECT",
                        permissive=True,
                        roles=("authenticated",),
                        using_sql="tenant_id = current_setting('app.tenant')",
                        with_check_sql=None,
                    ),
                ),
                indexes=(
                    Index(
                        name="invoices_tenant_idx",
                        access_method="btree",
                        columns=("tenant_id",),
                        is_unique=False,
                        is_partial=False,
                    ),
                    Index(
                        name="invoices_active_partial",
                        access_method="btree",
                        columns=("id",),
                        is_unique=True,
                        is_partial=True,
                    ),
                    Index(
                        name="invoices_lower_email",
                        access_method="btree",
                        # Expression-index position: empty string
                        # placeholder (introspection's COALESCE
                        # output for `pg_index.indkey = 0`).
                        columns=("",),
                        is_unique=False,
                        is_partial=False,
                    ),
                ),
            ),
        ),
    )
    snap_json = json.dumps(original.to_snapshot())
    loaded = Schema.from_snapshot(json.loads(snap_json))
    assert loaded.tables[0].indexes == original.tables[0].indexes
    assert loaded == original


def test_from_snapshot_v6_yields_empty_indexes() -> None:
    # v6 (released as v0.5.8 with SEC013) has no `indexes` field on
    # table entries. Loading must succeed and the field defaults
    # to `()` — PERF003 then simply finds nothing to flag against
    # the older snapshot until it's re-captured.
    v6 = {
        "version": 6,
        "tables": [
            {
                "schema": "public",
                "name": "t",
                "rls_enabled": True,
                "force_rls": True,
                "columns": ["id"],
                "partition_of": None,
                "grants": [],
                "column_details": [],
                "triggers": [],
            }
        ],
        "policies": [],
        "views": [],
        "security_definer_functions": [],
    }
    loaded = Schema.from_snapshot(v6)
    assert loaded.tables[0].indexes == ()


def test_from_snapshot_round_trips_v8_with_search_path() -> None:
    # SEC015 reads `SecdefFunction.search_path` from the snapshot.
    # Round-trip through `json.dumps` so the JSON shape matches a
    # file-persisted snapshot — the same contract `pgrls diff`
    # exercises. Covers both the pinned and the None (no-clause)
    # case.
    import json

    original = Schema(
        tables=(),
        views=(),
        security_definer_functions=(
            SecdefFunction(
                qualified_name="public.pinned_fn",
                body="SELECT 1",
                language="sql",
                search_path="pg_catalog, pg_temp",
            ),
            SecdefFunction(
                qualified_name="public.unpinned_fn",
                body="SELECT 2",
                language="sql",
                search_path=None,
            ),
        ),
    )
    snap_json = json.dumps(original.to_snapshot())
    loaded = Schema.from_snapshot(json.loads(snap_json))
    assert loaded.security_definer_functions == original.security_definer_functions
    assert loaded.security_definer_functions[0].search_path == "pg_catalog, pg_temp"
    assert loaded.security_definer_functions[1].search_path is None


def test_from_snapshot_v7_yields_none_search_path() -> None:
    # A v7 snapshot (v0.5.10–v0.5.12) carries `security_definer_functions`
    # entries with no `search_path` key — the v8 addition. Loading
    # must succeed and default the field to None. SEC015 then
    # conservatively flags every such function until the snapshot
    # is re-captured against a live database (v8).
    v7 = {
        "version": 7,
        "tables": [],
        "policies": [],
        "views": [],
        "security_definer_functions": [
            {
                "qualified_name": "public.legacy_fn",
                "body": "SELECT 1",
                "language": "sql",
            }
        ],
    }
    loaded = Schema.from_snapshot(v7)
    assert loaded.security_definer_functions[0].search_path is None


def test_to_snapshot_emits_bypassrls_roles_field() -> None:
    schema = Schema(
        tables=(),
        views=(),
        bypassrls_roles=(
            BypassRlsRole(
                name="etl_worker", superuser=False, can_login=True
            ),
        ),
    )
    snap = schema.to_snapshot()
    assert "bypassrls_roles" in snap
    assert snap["version"] == 15
    assert snap["bypassrls_roles"] == [
        {"name": "etl_worker", "superuser": False, "can_login": True}
    ]


def test_from_snapshot_round_trips_v9_with_bypassrls_roles() -> None:
    # SEC016 reads `Schema.bypassrls_roles` from the snapshot.
    # Round-trip through `json.dumps` so the JSON shape matches a
    # file-persisted snapshot — the same contract `pgrls diff`
    # exercises. Mirrors the v6/v7/v8 round-trip tests.
    import json

    original = Schema(
        tables=(),
        views=(),
        bypassrls_roles=(
            BypassRlsRole(
                name="admin_role", superuser=True, can_login=True
            ),
            BypassRlsRole(
                name="replication_worker",
                superuser=False,
                can_login=False,
            ),
        ),
    )
    snap_json = json.dumps(original.to_snapshot())
    loaded = Schema.from_snapshot(json.loads(snap_json))
    assert loaded.bypassrls_roles == original.bypassrls_roles
    assert loaded == original


def test_from_snapshot_v8_yields_empty_bypassrls_roles() -> None:
    # A v8 snapshot (v0.5.13) carries no `bypassrls_roles` key — the
    # v9 addition. Loading must succeed and default the field to
    # `()`. SEC016 then finds nothing to flag against the older
    # snapshot until it's re-captured against a live database (v9).
    v8 = {
        "version": 8,
        "tables": [],
        "policies": [],
        "views": [],
        "security_definer_functions": [],
    }
    loaded = Schema.from_snapshot(v8)
    assert loaded.bypassrls_roles == ()


def test_to_snapshot_emits_leakproof_functions_field() -> None:
    schema = Schema(
        tables=(),
        views=(),
        leakproof_functions=(
            LeakproofFunction(qualified_name="public.fast_eq"),
        ),
    )
    snap = schema.to_snapshot()
    assert "leakproof_functions" in snap
    assert snap["version"] == 15
    # `signature` is the v12 addition — defaults to "" when the
    # LeakproofFunction is constructed without it (as here).
    assert snap["leakproof_functions"] == [
        {
            "qualified_name": "public.fast_eq",
            "signature": "",
            "schema_name": "",
            "function_name": "",
        }
    ]


def test_from_snapshot_round_trips_v10_with_leakproof_functions() -> None:
    # SEC017 reads `Schema.leakproof_functions` from the snapshot.
    # Round-trip through `json.dumps` so the JSON shape matches a
    # file-persisted snapshot — the same contract `pgrls diff`
    # exercises. Mirrors the v6/v7/v8/v9 round-trip tests.
    import json

    original = Schema(
        tables=(),
        views=(),
        leakproof_functions=(
            LeakproofFunction(qualified_name="public.fast_eq"),
            LeakproofFunction(qualified_name="audit.redact"),
        ),
    )
    snap_json = json.dumps(original.to_snapshot())
    loaded = Schema.from_snapshot(json.loads(snap_json))
    assert loaded.leakproof_functions == original.leakproof_functions
    assert loaded == original


def test_from_snapshot_v9_yields_empty_leakproof_functions() -> None:
    # A v9 snapshot (v0.5.14) carries no `leakproof_functions` key —
    # the v10 addition. Loading must succeed and default the field
    # to `()`. SEC017 then finds nothing to flag against the older
    # snapshot until it's re-captured against a live database (v10).
    v9 = {
        "version": 9,
        "tables": [],
        "policies": [],
        "views": [],
        "security_definer_functions": [],
        "bypassrls_roles": [],
    }
    loaded = Schema.from_snapshot(v9)
    assert loaded.leakproof_functions == ()


def test_to_snapshot_emits_bypassrls_escalation_roles_field() -> None:
    schema = Schema(
        tables=(),
        views=(),
        bypassrls_escalation_roles=(
            BypassRlsEscalation(
                member="app",
                via=("admin", "ops"),
                member_can_login=True,
            ),
        ),
    )
    snap = schema.to_snapshot()
    assert "bypassrls_escalation_roles" in snap
    assert snap["version"] == 15
    assert snap["bypassrls_escalation_roles"] == [
        {
            "member": "app",
            "via": ["admin", "ops"],
            "member_can_login": True,
        }
    ]


def test_from_snapshot_round_trips_v11_with_bypassrls_escalation_roles() -> (
    None
):
    # SEC029 reads `Schema.bypassrls_escalation_roles` from the
    # snapshot. Round-trip through `json.dumps` so the JSON shape
    # matches a file-persisted snapshot — the same contract `pgrls
    # diff` exercises. The `via` tuple must survive the list↔tuple
    # conversion. Mirrors the v6/v7/v8/v9/v10 round-trip tests.
    import json

    original = Schema(
        tables=(),
        views=(),
        bypassrls_escalation_roles=(
            BypassRlsEscalation(
                member="app",
                via=("admin", "ops"),
                member_can_login=True,
            ),
            BypassRlsEscalation(
                member="batch",
                via=("admin",),
                member_can_login=False,
            ),
        ),
    )
    snap_json = json.dumps(original.to_snapshot())
    loaded = Schema.from_snapshot(json.loads(snap_json))
    assert (
        loaded.bypassrls_escalation_roles
        == original.bypassrls_escalation_roles
    )
    assert loaded == original


def test_from_snapshot_v10_yields_empty_bypassrls_escalation_roles() -> None:
    # A v10 snapshot (v0.5.15) carries no `bypassrls_escalation_roles`
    # key — the v11 addition. Loading must succeed and default the
    # field to `()`. SEC029 then finds nothing to flag against the
    # older snapshot until it's re-captured against a live database
    # (v11).
    v10 = {
        "version": 10,
        "tables": [],
        "policies": [],
        "views": [],
        "security_definer_functions": [],
        "bypassrls_roles": [],
        "leakproof_functions": [],
    }
    loaded = Schema.from_snapshot(v10)
    assert loaded.bypassrls_escalation_roles == ()
