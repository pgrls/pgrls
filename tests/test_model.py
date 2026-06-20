from __future__ import annotations

import pytest

from pgrls.model import (
    BypassRlsEscalation,
    BypassRlsRole,
    Column,
    DefaultPrivilege,
    Grant,
    Index,
    LeakproofFunction,
    Policy,
    PolicyCommand,
    Schema,
    SecdefFunction,
    Snapshot,
    Table,
    Trigger,
    View,
)


def test_table_construction() -> None:
    t = Table(
        schema="public",
        name="orders",
        rls_enabled=True,
        force_rls=True,
        policies=(),
    )
    assert t.qualified_name == "public.orders"


def test_policy_construction() -> None:
    p = Policy(
        name="tenant_isolation",
        command="SELECT",
        permissive=True,
        roles=("authenticated",),
        using_sql="(tenant_id = current_setting('app.tenant_id'))",
        with_check_sql=None,
    )
    assert p.command == "SELECT"
    assert p.is_permissive is True


def test_policy_command_literal_values() -> None:
    valid: list[PolicyCommand] = ["ALL", "SELECT", "INSERT", "UPDATE", "DELETE"]
    for cmd in valid:
        p = Policy(
            name=f"p_{cmd}",
            command=cmd,
            permissive=True,
            roles=(),
            using_sql=None,
            with_check_sql=None,
        )
        assert p.command == cmd


def test_schema_to_snapshot_shape() -> None:
    table = Table(
        schema="public",
        name="orders",
        rls_enabled=True,
        force_rls=False,
        policies=(
            Policy(
                name="select_own",
                command="SELECT",
                permissive=True,
                roles=("authenticated",),
                using_sql="(user_id = current_setting('app.user_id'))",
                with_check_sql=None,
            ),
        ),
    )
    snap: Snapshot = Schema(tables=(table,)).to_snapshot()
    assert snap == {
        "version": 19,
        "tables": [
            {
                "schema": "public",
                "name": "orders",
                "rls_enabled": True,
                "force_rls": False,
                "columns": [],
                "partition_of": None,
                "grants": [],
                "column_details": [],
                "triggers": [],
                "indexes": [],
            }
        ],
        "policies": [
            {
                "id": "public.orders.select_own",
                "table_schema": "public",
                "table_name": "orders",
                "policy_name": "select_own",
                "command": "SELECT",
                "permissive": True,
                "roles": ["authenticated"],
                "using_sql": "(user_id = current_setting('app.user_id'))",
                "with_check_sql": None,
            }
        ],
        "views": [],
        "security_definer_functions": [],
        "bypassrls_roles": [],
        "leakproof_functions": [],
        "bypassrls_escalation_roles": [],
        "default_privileges": [],
        "immutable_functions": [],
    }


def test_snapshot_is_json_serializable() -> None:
    import json

    schema = Schema(
        tables=(
            Table(
                schema="public",
                name="empty",
                rls_enabled=False,
                force_rls=False,
                policies=(),
            ),
        )
    )
    text = json.dumps(schema.to_snapshot(), sort_keys=True)
    assert "public.empty" not in text  # no policies, no policy ids
    assert '"rls_enabled": false' in text


def test_snapshot_policy_ordering_is_deterministic() -> None:
    p1 = Policy(
        name="p1", command="SELECT", permissive=True, roles=("a",),
        using_sql=None, with_check_sql=None,
    )
    p2 = Policy(
        name="p2", command="UPDATE", permissive=True, roles=("b",),
        using_sql=None, with_check_sql=None,
    )
    p3 = Policy(
        name="p3", command="DELETE", permissive=False, roles=("c",),
        using_sql=None, with_check_sql=None,
    )
    table_a = Table(
        schema="public", name="a",
        rls_enabled=True, force_rls=False,
        policies=(p1, p2),
    )
    table_b = Table(
        schema="public", name="b",
        rls_enabled=True, force_rls=False,
        policies=(p3,),
    )
    schema = Schema(tables=(table_a, table_b))

    snap1 = schema.to_snapshot()
    snap2 = schema.to_snapshot()
    assert snap1 == snap2
    policy_ids = [p["id"] for p in snap1["policies"]]
    assert policy_ids == ["public.a.p1", "public.a.p2", "public.b.p3"]


def test_model_classes_are_hashable() -> None:
    """Frozen dataclasses with tuple fields should be hashable for set/dict use."""
    p = Policy(
        name="x",
        command="SELECT",
        permissive=True,
        roles=(),
        using_sql=None,
        with_check_sql=None,
    )
    t = Table(
        schema="public",
        name="t",
        rls_enabled=True,
        force_rls=False,
        policies=(p,),
    )
    s = Schema(tables=(t,))

    # Each is independently hashable
    hash(p)
    hash(t)
    hash(s)

    # And usable in a set
    assert {p, t, s} == {p, t, s}


def test_policy_has_optional_ast_fields_defaulting_to_none() -> None:
    from pgrls.model import Policy

    p = Policy(
        name="x",
        command="SELECT",
        permissive=True,
        roles=("PUBLIC",),
        using_sql="a = 1",
        with_check_sql=None,
    )
    assert p.using_ast is None
    assert p.with_check_ast is None


def test_table_has_columns_field_defaulting_empty() -> None:
    from pgrls.model import Table

    t = Table(
        schema="public",
        name="t",
        rls_enabled=False,
        force_rls=False,
        policies=(),
    )
    assert t.columns == ()


def test_snapshot_includes_table_columns() -> None:
    from pgrls.model import Schema, Table

    table = Table(
        schema="public",
        name="users",
        rls_enabled=True,
        force_rls=True,
        policies=(),
        columns=("id", "email"),
    )
    snap = Schema(tables=(table,)).to_snapshot()
    assert snap["tables"][0]["columns"] == ["id", "email"]


def test_snapshot_version_is_nineteen_after_immutable_functions_capture() -> None:
    # SNAPSHOT_VERSION bumped 18 → 19 to add top-level immutable_functions
    # (user-defined functions with provolatile='i') so SEC046 can flag an
    # IMMUTABLE function whose body reads session state (constant-folded into a
    # cached plan → cross-user leak). Pin the new version so a future bump is
    # deliberate. (v18 added default_privileges for SEC044; v17 added
    # Table.inherits for SEC043.)
    snap = Schema(tables=()).to_snapshot()
    assert snap["version"] == 19


def test_policy_to_sql_omits_to_clause_when_no_roles() -> None:
    # A Policy with no roles must NOT render `TO ` (empty) — that's a
    # syntax error that aborts `diff --apply`. A roleless CREATE POLICY
    # defaults to PUBLIC, so omitting the TO clause is the correct,
    # executable render.
    from pgrls.model import Policy, policy_to_sql

    p = Policy(
        name="p",
        command="ALL",
        permissive=True,
        roles=(),
        using_sql="true",
        with_check_sql=None,
        using_ast=None,
        with_check_ast=None,
    )
    sql = policy_to_sql(p, "public.t")
    assert "TO " not in sql
    assert sql == "CREATE POLICY p ON public.t USING (true);"


def test_snapshot_includes_partition_of_when_set() -> None:
    table = Table(
        schema="public",
        name="events_2026",
        rls_enabled=False,
        force_rls=False,
        policies=(),
        partition_of=("public", "events"),
    )
    snap = Schema(tables=(table,)).to_snapshot()
    # JSON has no tuples — round-tripping through a list is required for
    # `json.dumps` to succeed without a custom encoder.
    assert snap["tables"][0]["partition_of"] == ["public", "events"]


def test_snapshot_partition_of_is_none_for_non_partition() -> None:
    table = Table(
        schema="public",
        name="things",
        rls_enabled=True,
        force_rls=True,
        policies=(),
    )
    snap = Schema(tables=(table,)).to_snapshot()
    assert snap["tables"][0]["partition_of"] is None


def test_ancestors_of_yields_nothing_for_non_partition() -> None:
    t = Table(
        schema="public",
        name="t",
        rls_enabled=True,
        force_rls=False,
        policies=(),
    )
    schema = Schema(tables=(t,))
    assert list(schema.ancestors_of(t)) == []


def test_ancestors_of_walks_immediate_parent() -> None:
    parent = Table(
        schema="public",
        name="events",
        rls_enabled=True,
        force_rls=False,
        policies=(),
    )
    child = Table(
        schema="public",
        name="events_2026",
        rls_enabled=False,
        force_rls=False,
        policies=(),
        partition_of=("public", "events"),
    )
    schema = Schema(tables=(parent, child))
    chain = list(schema.ancestors_of(child))
    assert [t.qualified_name for t in chain] == ["public.events"]


def test_ancestors_of_walks_multi_level_chain() -> None:
    grandparent = Table(
        schema="public",
        name="events",
        rls_enabled=True,
        force_rls=False,
        policies=(),
    )
    middle = Table(
        schema="public",
        name="events_t1",
        rls_enabled=False,
        force_rls=False,
        policies=(),
        partition_of=("public", "events"),
    )
    leaf = Table(
        schema="public",
        name="events_t1_2026",
        rls_enabled=False,
        force_rls=False,
        policies=(),
        partition_of=("public", "events_t1"),
    )
    schema = Schema(tables=(grandparent, middle, leaf))
    chain = list(schema.ancestors_of(leaf))
    assert [t.qualified_name for t in chain] == [
        "public.events_t1",
        "public.events",
    ]


def test_ancestors_of_terminates_when_parent_outside_introspected_set() -> None:
    # Parent in an unscoped schema isn't in `Schema.tables` — the walk
    # ends at the gap. The caller (e.g. SEC001) checks
    # `child.partition_of` to distinguish "no ancestor" from "ancestor
    # we couldn't see".
    child = Table(
        schema="public",
        name="events_2026",
        rls_enabled=False,
        force_rls=False,
        policies=(),
        partition_of=("private", "events"),
    )
    schema = Schema(tables=(child,))
    assert list(schema.ancestors_of(child)) == []


def test_ancestors_of_raises_on_cycle() -> None:
    import pytest

    # Postgres can't produce this; only corrupted state can. Surface it.
    a = Table(
        schema="public",
        name="a",
        rls_enabled=False,
        force_rls=False,
        policies=(),
        partition_of=("public", "b"),
    )
    b = Table(
        schema="public",
        name="b",
        rls_enabled=False,
        force_rls=False,
        policies=(),
        partition_of=("public", "a"),
    )
    schema = Schema(tables=(a, b))
    with pytest.raises(ValueError, match="cycle"):
        list(schema.ancestors_of(a))


def test_ancestors_of_raises_on_self_cycle_without_yielding_self() -> None:
    # A table whose `partition_of` points back to itself is a length-1
    # cycle. The `seen` set is seeded with the starting table's qname
    # specifically so this case raises before yielding the table as
    # its own ancestor — that would mislead any caller doing
    # `any(a.rls_enabled for a in ancestors)`. Pin the no-yield-then-
    # raise contract.
    import pytest

    self_referential = Table(
        schema="public",
        name="loop",
        rls_enabled=False,
        force_rls=False,
        policies=(),
        partition_of=("public", "loop"),
    )
    schema = Schema(tables=(self_referential,))

    iterator = schema.ancestors_of(self_referential)
    with pytest.raises(ValueError, match="cycle"):
        next(iterator)


# --- inheritance_ancestors_of (classic INHERITS DAG walk) ----------------


def test_inheritance_ancestors_of_yields_nothing_for_standalone() -> None:
    t = Table(
        schema="public",
        name="t",
        rls_enabled=True,
        force_rls=False,
        policies=(),
    )
    schema = Schema(tables=(t,))
    assert list(schema.inheritance_ancestors_of(t)) == []


def test_inheritance_ancestors_of_walks_immediate_parent() -> None:
    parent = Table(
        schema="public",
        name="events",
        rls_enabled=True,
        force_rls=False,
        policies=(),
    )
    child = Table(
        schema="public",
        name="events_legacy",
        rls_enabled=False,
        force_rls=False,
        policies=(),
        inherits=(("public", "events"),),
    )
    schema = Schema(tables=(parent, child))
    chain = list(schema.inheritance_ancestors_of(child))
    assert [t.qualified_name for t in chain] == ["public.events"]


def test_inheritance_ancestors_of_walks_multi_level_chain() -> None:
    grandparent = Table(
        schema="public",
        name="events",
        rls_enabled=True,
        force_rls=False,
        policies=(),
    )
    middle = Table(
        schema="public",
        name="events_mid",
        rls_enabled=False,
        force_rls=False,
        policies=(),
        inherits=(("public", "events"),),
    )
    leaf = Table(
        schema="public",
        name="events_leaf",
        rls_enabled=False,
        force_rls=False,
        policies=(),
        inherits=(("public", "events_mid"),),
    )
    schema = Schema(tables=(grandparent, middle, leaf))
    chain = [t.qualified_name for t in schema.inheritance_ancestors_of(leaf)]
    # Depth-first: the single chain yields mid then events.
    assert chain == ["public.events_mid", "public.events"]


def test_inheritance_ancestors_of_walks_multiple_parents_dag() -> None:
    # Classic inheritance is a DAG: a child may inherit from several parents.
    # All distinct ancestors are yielded (order is depth-first in `inherits`
    # order). This is the case a partition's single-parent walk can't reach.
    p1 = Table(
        schema="public",
        name="audited",
        rls_enabled=True,
        force_rls=False,
        policies=(),
    )
    p2 = Table(
        schema="public",
        name="timestamped",
        rls_enabled=False,
        force_rls=False,
        policies=(),
    )
    child = Table(
        schema="public",
        name="records",
        rls_enabled=False,
        force_rls=False,
        policies=(),
        inherits=(("public", "audited"), ("public", "timestamped")),
    )
    schema = Schema(tables=(p1, p2, child))
    chain = {t.qualified_name for t in schema.inheritance_ancestors_of(child)}
    assert chain == {"public.audited", "public.timestamped"}


def test_inheritance_ancestors_of_dedupes_diamond() -> None:
    # A diamond (two parents reconverging on a common grandparent) must yield
    # the grandparent exactly ONCE — re-reaching an already-finished node via
    # a second path is benign and must not duplicate or (crucially) raise as
    # if it were a cycle.
    root = Table(
        schema="public",
        name="root",
        rls_enabled=True,
        force_rls=False,
        policies=(),
    )
    left = Table(
        schema="public",
        name="left",
        rls_enabled=False,
        force_rls=False,
        policies=(),
        inherits=(("public", "root"),),
    )
    right = Table(
        schema="public",
        name="right",
        rls_enabled=False,
        force_rls=False,
        policies=(),
        inherits=(("public", "root"),),
    )
    leaf = Table(
        schema="public",
        name="leaf",
        rls_enabled=False,
        force_rls=False,
        policies=(),
        inherits=(("public", "left"), ("public", "right")),
    )
    schema = Schema(tables=(root, left, right, leaf))
    chain = [t.qualified_name for t in schema.inheritance_ancestors_of(leaf)]
    # root appears once despite two reachable paths.
    assert chain.count("public.root") == 1
    assert set(chain) == {"public.left", "public.right", "public.root"}


def test_inheritance_ancestors_of_terminates_at_out_of_scope_gap() -> None:
    # A parent in an unscoped schema isn't in `Schema.tables` — the walk
    # ends at the gap without yielding it, mirroring `ancestors_of`.
    child = Table(
        schema="public",
        name="records",
        rls_enabled=False,
        force_rls=False,
        policies=(),
        inherits=(("private", "base"),),
    )
    schema = Schema(tables=(child,))
    assert list(schema.inheritance_ancestors_of(child)) == []


def test_inheritance_ancestors_of_raises_on_two_node_cycle() -> None:
    # Postgres rejects inheritance cycles; only corrupted state can produce
    # one. A two-node cycle (a → b → a) must raise, not silently truncate.
    a = Table(
        schema="public",
        name="a",
        rls_enabled=False,
        force_rls=False,
        policies=(),
        inherits=(("public", "b"),),
    )
    b = Table(
        schema="public",
        name="b",
        rls_enabled=False,
        force_rls=False,
        policies=(),
        inherits=(("public", "a"),),
    )
    schema = Schema(tables=(a, b))
    with pytest.raises(ValueError, match="cycle"):
        list(schema.inheritance_ancestors_of(a))


def test_inheritance_ancestors_of_raises_on_deep_cycle_below_start() -> None:
    # The cycle does NOT pass through the starting table (leaf → p → q → p).
    # The white/grey/black DFS colouring must still catch it — seeding only
    # the start node in the active-path set would miss this, so pin it.
    p = Table(
        schema="public",
        name="p",
        rls_enabled=False,
        force_rls=False,
        policies=(),
        inherits=(("public", "q"),),
    )
    q = Table(
        schema="public",
        name="q",
        rls_enabled=False,
        force_rls=False,
        policies=(),
        inherits=(("public", "p"),),
    )
    leaf = Table(
        schema="public",
        name="leaf",
        rls_enabled=False,
        force_rls=False,
        policies=(),
        inherits=(("public", "p"),),
    )
    schema = Schema(tables=(p, q, leaf))
    with pytest.raises(ValueError, match="cycle"):
        list(schema.inheritance_ancestors_of(leaf))


def test_inheritance_ancestors_of_raises_on_self_cycle_without_yielding() -> None:
    # A table whose `inherits` points back to itself is a length-1 cycle.
    # The active-path set is seeded with the start table specifically so this
    # raises before yielding the table as its own ancestor.
    self_ref = Table(
        schema="public",
        name="loop",
        rls_enabled=False,
        force_rls=False,
        policies=(),
        inherits=(("public", "loop"),),
    )
    schema = Schema(tables=(self_ref,))
    iterator = schema.inheritance_ancestors_of(self_ref)
    with pytest.raises(ValueError, match="cycle"):
        next(iterator)


def test_snapshot_includes_inherits_when_set() -> None:
    # v17: `inherits` is emitted (and round-trips) only when non-empty.
    child = Table(
        schema="public",
        name="records",
        rls_enabled=False,
        force_rls=False,
        policies=(),
        inherits=(("public", "audited"), ("public", "timestamped")),
    )
    schema = Schema(tables=(child,))
    snap = schema.to_snapshot()
    [t] = snap["tables"]
    assert t["inherits"] == [["public", "audited"], ["public", "timestamped"]]
    # round-trips list-of-lists back to tuple-of-tuples
    restored = Schema.from_snapshot(snap)
    assert restored.tables[0].inherits == (
        ("public", "audited"),
        ("public", "timestamped"),
    )


def test_snapshot_omits_inherits_key_when_empty() -> None:
    # A table with no classic inheritance must serialize byte-identically to
    # before v17 (no `inherits` key) — the conditional-emit / no-churn
    # contract, mirroring column_grants.
    t = Table(
        schema="public",
        name="standalone",
        rls_enabled=True,
        force_rls=False,
        policies=(),
    )
    snap = Schema(tables=(t,)).to_snapshot()
    assert "inherits" not in snap["tables"][0]


def test_default_privileges_round_trip_through_snapshot() -> None:
    # v18: top-level default_privileges (from pg_default_acl) serialize and
    # decode for SEC044, including a cluster-wide entry (schema=None → null)
    # and the grantor (defaclrole, part of the entry's identity).
    schema = Schema(
        default_privileges=(
            DefaultPrivilege(
                schema="public",
                grantee="PUBLIC",
                privileges=("SELECT",),
                grantor="app_owner",
            ),
            DefaultPrivilege(
                schema=None,
                grantee="anon",
                privileges=("SELECT", "INSERT"),
                grantor="postgres",
            ),
        )
    )
    snap = schema.to_snapshot()
    assert snap["default_privileges"] == [
        {
            "schema": "public",
            "grantee": "PUBLIC",
            "privileges": ["SELECT"],
            "grantor": "app_owner",
        },
        {
            "schema": None,
            "grantee": "anon",
            "privileges": ["SELECT", "INSERT"],
            "grantor": "postgres",
        },
    ]
    restored = Schema.from_snapshot(snap)
    assert restored.default_privileges == schema.default_privileges
    # The cluster-wide entry round-trips back to schema=None.
    assert restored.default_privileges[1].schema is None
    # The grantor round-trips.
    assert restored.default_privileges[0].grantor == "app_owner"


def test_default_privileges_absent_in_pre_v18_snapshot_loads_empty() -> None:
    # A v17 snapshot has no default_privileges key → loads as ().
    snap = {"version": 17, "tables": [], "policies": []}
    assert Schema.from_snapshot(snap).default_privileges == ()


def test_default_privilege_grantor_absent_loads_none() -> None:
    # An entry without a "grantor" key (a hand-built or in-flight pre-grantor
    # v18 snapshot) decodes with grantor=None — the rule then emits a
    # grantor-less REVOKE rather than crashing.
    snap = {
        "version": 18,
        "tables": [],
        "policies": [],
        "default_privileges": [
            {"schema": "public", "grantee": "PUBLIC", "privileges": ["SELECT"]}
        ],
    }
    [dp] = Schema.from_snapshot(snap).default_privileges
    assert dp.grantor is None


def test_table_with_list_partition_of_is_unhashable() -> None:
    # Contract: `partition_of` must be a tuple (or None). The type hint
    # says so; the frozen dataclass auto-hash will fail loudly if
    # someone passes a list. JSON has no tuples — a future consumer
    # that round-trips through `to_snapshot` and feeds the resulting
    # 2-list back into `Table(...)` must convert list → tuple first.
    # Pin the failure so that bug surfaces at hash time instead of
    # at some downstream set-membership check.
    import pytest

    t = Table(
        schema="public",
        name="events_2026",
        rls_enabled=False,
        force_rls=False,
        policies=(),
        partition_of=["public", "events"],  # type: ignore[arg-type]
    )
    with pytest.raises(TypeError):
        hash(t)


def test_schema_by_qname_is_cached_across_calls() -> None:
    # `Schema._by_qname` is a `cached_property`, so successive accesses
    # must return the same dict instance. This pins the O(N) cost of
    # the lookup map (vs O(N²) when SEC001 walks every partition).
    parent = Table(
        schema="public",
        name="events",
        rls_enabled=True,
        force_rls=False,
        policies=(),
    )
    child = Table(
        schema="public",
        name="events_2026",
        rls_enabled=False,
        force_rls=False,
        policies=(),
        partition_of=("public", "events"),
    )
    schema = Schema(tables=(parent, child))
    first = schema._by_qname
    second = schema._by_qname
    assert first is second  # pragma: no mutate


def test_snapshot_v12_top_level_keys_are_stable_contract() -> None:
    # Snapshot top-level keys are part of the public surface (any
    # consumer reading the JSON depends on these names). Pin
    # `version`, `tables`, `policies`, `views`,
    # `security_definer_functions`, `bypassrls_roles`,
    # `leakproof_functions`, `bypassrls_escalation_roles`,
    # `default_privileges`, `immutable_functions` so a quiet refactor that
    # renames or drops a key fails this test rather than slipping past CI. v19
    # adds the top-level `immutable_functions` array (user-defined
    # provolatile='i' functions) for SEC046; v18 added `default_privileges`
    # (from pg_default_acl) for SEC044. (v12 added per-overload `signature` to
    # SecdefFunction / LeakproofFunction — a per-entry field, not a top-level
    # key.)
    snap = Schema(tables=()).to_snapshot()
    assert set(snap.keys()) == {
        "version",
        "tables",
        "policies",
        "views",
        "security_definer_functions",
        "bypassrls_roles",
        "leakproof_functions",
        "bypassrls_escalation_roles",
        "default_privileges",
        "immutable_functions",
    }
    assert snap["version"] == 19


def test_snapshot_v7_table_entry_keys_are_stable() -> None:
    table = Table(
        schema="public",
        name="t",
        rls_enabled=True,
        force_rls=True,
        policies=(),
        columns=("id",),
        partition_of=("public", "parent"),
    )
    snap = Schema(tables=(table,)).to_snapshot()
    assert set(snap["tables"][0].keys()) == {
        "schema",
        "name",
        "rls_enabled",
        "force_rls",
        "columns",
        "partition_of",
        "grants",
        "column_details",
        "triggers",
        "indexes",
    }


def test_snapshot_v2_policy_entry_keys_are_stable() -> None:
    p = Policy(
        name="p",
        command="SELECT",
        permissive=True,
        roles=("PUBLIC",),
        using_sql="true",
        with_check_sql=None,
    )
    table = Table(
        schema="public",
        name="t",
        rls_enabled=True,
        force_rls=True,
        policies=(p,),
    )
    snap = Schema(tables=(table,)).to_snapshot()
    assert set(snap["policies"][0].keys()) == {
        "id",
        "table_schema",
        "table_name",
        "policy_name",
        "command",
        "permissive",
        "roles",
        "using_sql",
        "with_check_sql",
    }


def test_view_dataclass_has_expected_fields() -> None:
    from pgrls.model import View

    v = View(
        schema="public",
        name="invoices_v",
        is_materialized=False,
        security_invoker=True,
        security_barrier=False,
        definition="SELECT * FROM public.invoices",
        references=(("public", "invoices"),),
        security_definer_calls=(),
    )
    assert v.qualified_name == "public.invoices_v"
    assert v.is_materialized is False
    assert v.security_invoker is True
    assert v.references == (("public", "invoices"),)


def test_view_dataclass_is_frozen() -> None:
    import dataclasses

    from pgrls.model import View

    v = View(
        schema="public",
        name="vw",
        is_materialized=False,
        security_invoker=False,
        security_barrier=False,
        definition="",
        references=(),
        security_definer_calls=(),
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        v.name = "x"  # type: ignore[misc]


def test_fully_populated_schema_roundtrip() -> None:
    """Property: from_snapshot(to_snapshot(s)) == s for a Schema that
    populates every field of every dataclass.

    Guards the to_snapshot / from_snapshot field-list symmetry going
    forward: if a field is added to a dataclass and wired into only one
    of the two halves, this round-trip stops being an identity and the
    test fails. AST fields on Policy are deliberately None here — they
    are intentionally not serialized (callers re-parse on demand), so
    None is the snapshot-able state that round-trips by equality.
    """
    schema = Schema(
        tables=(
            Table(
                schema="public",
                name="parent",
                rls_enabled=True,
                force_rls=True,
                policies=(
                    Policy(
                        name="tenant_isolation",
                        command="SELECT",
                        permissive=False,
                        roles=("app_user", "PUBLIC"),
                        using_sql="tenant_id = current_setting('app.tid')::int",
                        with_check_sql=None,
                        using_ast=None,
                        with_check_ast=None,
                    ),
                    Policy(
                        name="insert_guard",
                        command="INSERT",
                        permissive=True,
                        roles=("app_user",),
                        using_sql=None,
                        with_check_sql="tenant_id = current_setting('app.tid')::int",
                        using_ast=None,
                        with_check_ast=None,
                    ),
                ),
                columns=("id", "tenant_id"),
                partition_of=None,
                grants=(
                    Grant(role="app_user", privileges=("SELECT", "INSERT")),
                    Grant(role="PUBLIC", privileges=("SELECT",)),
                ),
                column_details=(
                    Column(name="id", data_type="integer", is_nullable=False),
                    Column(
                        name="tenant_id",
                        data_type="integer",
                        is_nullable=False,
                    ),
                ),
                triggers=(
                    Trigger(
                        name="audit_trg",
                        function_schema="audit",
                        function_name="log_change",
                        event="INSERT OR UPDATE",
                        timing="AFTER",
                        enabled=False,
                    ),
                ),
                indexes=(
                    Index(
                        name="parent_tenant_idx",
                        access_method="btree",
                        # second position is an expression slot (empty
                        # string) — exercises the positional-alignment
                        # round-trip.
                        columns=("tenant_id", ""),
                        is_unique=True,
                        is_partial=True,
                        is_primary=False,
                    ),
                    Index(
                        name="parent_pkey",
                        access_method="btree",
                        columns=("id",),
                        is_unique=True,
                        is_partial=False,
                        is_primary=True,
                    ),
                ),
            ),
            Table(
                schema="public",
                name="child",
                rls_enabled=False,
                force_rls=False,
                policies=(),
                columns=("id",),
                partition_of=("public", "parent"),
                grants=(),
                column_details=(
                    Column(name="id", data_type="integer", is_nullable=True),
                ),
                triggers=(),
                indexes=(),
            ),
        ),
        views=(
            View(
                schema="public",
                name="v_users",
                is_materialized=True,
                security_invoker=True,
                security_barrier=True,
                definition="SELECT id FROM public.parent",
                references=(("public", "parent"), ("public", "child")),
                security_definer_calls=("public.read_secret", "audit.who"),
            ),
        ),
        security_definer_functions=(
            SecdefFunction(
                qualified_name="public.read_secret",
                body="SELECT 1",
                language="sql",
                search_path="pg_catalog, public, pg_temp",
                signature="integer, text",
            ),
        ),
        bypassrls_roles=(
            BypassRlsRole(name="admin", superuser=False, can_login=True),
        ),
        leakproof_functions=(
            LeakproofFunction(
                qualified_name="public.lp", signature="integer"
            ),
        ),
        bypassrls_escalation_roles=(
            BypassRlsEscalation(
                member="app_user",
                via=("admin", "ops"),
                member_can_login=True,
            ),
        ),
    )

    assert Schema.from_snapshot(schema.to_snapshot()) == schema


# --- #5: snapshot trust-boundary validation (to_sql injection) ----------


def _minimal_snapshot(**table_overrides: object) -> dict:
    """A minimal valid v14 snapshot with one bare table; callers
    override a table field to inject a malicious value."""
    table = {
        "schema": "public",
        "name": "t",
        "rls_enabled": False,
        "force_rls": False,
        "columns": [],
        "partition_of": None,
        "grants": [],
        "column_details": [],
        "triggers": [],
        "indexes": [],
        "policies": [],
    }
    table.update(table_overrides)
    return {
        "version": 14,
        "tables": [table],
        "policies": [],
        "views": [],
        "security_definer_functions": [],
        "bypassrls_roles": [],
        "leakproof_functions": [],
        "bypassrls_escalation_roles": [],
    }


def test_from_snapshot_rejects_data_type_injection() -> None:
    snap = _minimal_snapshot(
        column_details=[
            {
                "name": "id",
                "data_type": "int); DROP TABLE secrets; --",
                "is_nullable": True,
            }
        ]
    )
    with pytest.raises(ValueError, match="data_type"):
        Schema.from_snapshot(snap)


def test_from_snapshot_rejects_grant_privilege_injection() -> None:
    snap = _minimal_snapshot(
        grants=[{"role": "r", "privileges": ["SELECT ON x TO evil; GRANT ALL"]}]
    )
    with pytest.raises(ValueError, match="privilege"):
        Schema.from_snapshot(snap)


def test_from_snapshot_rejects_empty_grant_privileges() -> None:
    # R13 #5: an empty privileges list would make to_sql() emit
    # `GRANT  ON … TO role;` (double space), a syntax error that aborts
    # the baseline `pgrls diff --apply` runs. Live introspection groups
    # by role (always >=1 privilege), so this only guards a hand-built /
    # tampered snapshot — reject at decode, not at apply.
    snap = _minimal_snapshot(grants=[{"role": "r", "privileges": []}])
    with pytest.raises(ValueError, match="no privileges"):
        Schema.from_snapshot(snap)


def test_column_grants_round_trip_through_snapshot() -> None:
    # R15 #2: column-level grants serialize/decode additively (snapshot
    # v15). A schema that has them round-trips faithfully; one that does
    # not omits the key entirely (byte-stable for pre-feature schemas).
    from pgrls.model import ColumnGrant, Column, SNAPSHOT_VERSION

    cg = ColumnGrant(role="PUBLIC", column="ssn", privileges=("SELECT",))
    t = Table(
        schema="public", name="users", rls_enabled=False, force_rls=False,
        policies=(), columns=("ssn",),
        column_details=(Column(name="ssn", data_type="text", is_nullable=True),),
        column_grants=(cg,),
    )
    snap = Schema(tables=(t,)).to_snapshot()
    assert snap["version"] == SNAPSHOT_VERSION == 19
    assert snap["tables"][0]["column_grants"] == [
        {"role": "PUBLIC", "column": "ssn", "privileges": ["SELECT"]}
    ]
    assert Schema.from_snapshot(snap).tables[0].column_grants == (cg,)
    # A table with no column grants omits the key (byte-stability).
    plain = Table(
        schema="public", name="plain", rls_enabled=True, force_rls=True,
        policies=(),
        column_details=(Column(name="id", data_type="uuid", is_nullable=False),),
    )
    assert "column_grants" not in Schema(tables=(plain,)).to_snapshot()["tables"][0]


def test_from_snapshot_rejects_invalid_column_grant_privilege() -> None:
    # DELETE/TRUNCATE/TRIGGER cannot be granted at column granularity;
    # reject a tampered snapshot that lists one (mirrors the table-grant
    # privilege validation).
    snap = _minimal_snapshot(
        column_grants=[
            {"role": "PUBLIC", "column": "ssn", "privileges": ["DELETE"]}
        ]
    )
    with pytest.raises(ValueError, match="column privilege"):
        Schema.from_snapshot(snap)


def test_from_snapshot_rejects_invalid_policy_command() -> None:
    snap = _minimal_snapshot(
        policies=[
            {
                "policy_name": "p",
                "command": "ALL; DROP TABLE x",
                "permissive": True,
                "roles": ["r"],
                "using_sql": "true",
            }
        ]
    )
    with pytest.raises(ValueError, match="invalid command"):
        Schema.from_snapshot(snap)


def test_policy_to_sql_rejects_out_of_literal_command() -> None:
    # R12 #4: policy_to_sql splices `command` raw as `FOR {command}`. The
    # decoder rejects bad commands, but a Policy built directly in Python
    # (a less-trusted future caller) could carry an out-of-Literal value;
    # the emit sink must self-defend like its USING/WITH CHECK siblings.
    from pgrls.model import Policy, policy_to_sql

    p = Policy(
        name="p",
        command="SELECT; DROP TABLE x; --",  # type: ignore[arg-type]
        permissive=True,
        roles=("r",),
        using_sql="true",
        with_check_sql=None,
    )
    with pytest.raises(ValueError, match="invalid command"):
        policy_to_sql(p, "public.t")


def test_from_snapshot_rejects_non_string_role() -> None:
    # R12 #5: roles are emitted as identifiers into `CREATE POLICY … TO`,
    # so a tampered snapshot with a non-string role must surface the same
    # clean ValueError the other structured fields produce — not a raw
    # TypeError deep in quote_ident.
    snap = _minimal_snapshot(
        policies=[
            {
                "policy_name": "p",
                "command": "ALL",
                "permissive": True,
                "roles": [123],
                "using_sql": "true",
                "with_check_sql": "true",
            }
        ]
    )
    with pytest.raises(ValueError, match="invalid role"):
        Schema.from_snapshot(snap)


def test_from_snapshot_rejects_select_delete_policy_with_with_check() -> None:
    # Regression (round-3 #11): a SELECT / DELETE policy carrying a
    # WITH CHECK clause makes `policy_to_sql` (and `pgrls diff --apply`)
    # emit DDL Postgres rejects — WITH CHECK is valid only on INSERT /
    # UPDATE / ALL. Reject the malformed combination at the decode boundary.
    for command in ("SELECT", "DELETE"):
        snap = _minimal_snapshot(
            policies=[
                {
                    "policy_name": "p",
                    "command": command,
                    "permissive": True,
                    "roles": ["r"],
                    "using_sql": "true",
                    "with_check_sql": "id > 0",
                }
            ]
        )
        with pytest.raises(ValueError, match="WITH CHECK"):
            Schema.from_snapshot(snap)


def test_from_snapshot_rejects_insert_policy_with_using() -> None:
    # The mirror case: USING is valid only on SELECT / UPDATE / DELETE /
    # ALL; an INSERT policy with USING would emit invalid DDL.
    snap = _minimal_snapshot(
        policies=[
            {
                "policy_name": "p",
                "command": "INSERT",
                "permissive": True,
                "roles": ["r"],
                "using_sql": "true",
                "with_check_sql": "id > 0",
            }
        ]
    )
    with pytest.raises(ValueError, match="USING"):
        Schema.from_snapshot(snap)


def test_from_snapshot_accepts_valid_command_clause_combinations() -> None:
    # The combination check must NOT reject Postgres-valid shapes: USING
    # on SELECT/DELETE, WITH CHECK on INSERT, both on UPDATE/ALL. An
    # empty-string clause is harmless (never emitted) and is also accepted.
    policies = [
        {"policy_name": "s", "command": "SELECT", "permissive": True,
         "roles": ["r"], "using_sql": "true"},
        {"policy_name": "d", "command": "DELETE", "permissive": True,
         "roles": ["r"], "using_sql": "true"},
        {"policy_name": "i", "command": "INSERT", "permissive": True,
         "roles": ["r"], "with_check_sql": "true"},
        {"policy_name": "u", "command": "UPDATE", "permissive": True,
         "roles": ["r"], "using_sql": "true", "with_check_sql": "true"},
        {"policy_name": "a", "command": "ALL", "permissive": True,
         "roles": ["r"], "using_sql": "true", "with_check_sql": "true"},
        {"policy_name": "se", "command": "SELECT", "permissive": True,
         "roles": ["r"], "using_sql": "true", "with_check_sql": ""},
    ]
    schema = Schema.from_snapshot(_minimal_snapshot(policies=policies))
    assert len(schema.tables[0].policies) == 6


def test_from_snapshot_accepts_real_types_and_privileges() -> None:
    # Validation is permissive enough for real Postgres types /
    # privileges — these must round-trip without error.
    snap = _minimal_snapshot(
        column_details=[
            {"name": "id", "data_type": "integer", "is_nullable": False},
            {"name": "amt", "data_type": "numeric(10,2)", "is_nullable": True},
            {"name": "tags", "data_type": "text[]", "is_nullable": True},
            {
                "name": "ts",
                "data_type": "timestamp with time zone",
                "is_nullable": True,
            },
        ],
        grants=[{"role": "app", "privileges": ["SELECT", "INSERT", "UPDATE"]}],
    )
    schema = Schema.from_snapshot(snap)
    assert schema.tables[0].column_details[1].data_type == "numeric(10,2)"


def test_from_snapshot_rejects_data_type_column_injection() -> None:
    # Regression (round-2 #1): the comma + space the old regex allowed
    # for `numeric(10,2)` ALSO let a snapshot inject a SECOND column.
    # Parse-validation rejects it (the probe CREATE TABLE has 2 columns).
    snap = _minimal_snapshot(
        column_details=[
            {
                "name": "id",
                "data_type": "integer, evil boolean DEFAULT (true)",
                "is_nullable": True,
            }
        ]
    )
    with pytest.raises(ValueError, match="data_type"):
        Schema.from_snapshot(snap)


def test_from_snapshot_rejects_data_type_inherits_injection() -> None:
    snap = _minimal_snapshot(
        column_details=[
            {
                "name": "id",
                "data_type": "integer) INHERITS (pg_catalog.pg_class",
                "is_nullable": True,
            }
        ]
    )
    with pytest.raises(ValueError, match="data_type"):
        Schema.from_snapshot(snap)


def test_from_snapshot_accepts_quoted_identifier_type() -> None:
    # Regression (round-2 #10): the old char-allowlist over-restricted
    # and rejected a legitimate quoted type name, crashing diff on a
    # valid schema. Parse-validation accepts it.
    snap = _minimal_snapshot(
        column_details=[{"name": "x", "data_type": '"My Type"', "is_nullable": True}]
    )
    schema = Schema.from_snapshot(snap)
    assert schema.tables[0].column_details[0].data_type == '"My Type"'


def test_from_snapshot_rejects_collate_in_data_type() -> None:
    # Regression (round-5): a COLLATE clause smuggled into a column
    # data_type is interpolated into the CREATE TABLE `diff --apply` runs.
    # A legitimate format_type data_type never carries an inline COLLATE,
    # so the parse-validator must reject it.
    snap = _minimal_snapshot(
        column_details=[
            {"name": "c", "data_type": 'integer COLLATE "C"',
             "is_nullable": True},
        ]
    )
    with pytest.raises(ValueError, match="data_type"):
        Schema.from_snapshot(snap)


def test_from_snapshot_rejects_non_object_payload() -> None:
    # Regression (round-5): a file that is valid JSON but not a snapshot
    # OBJECT (bare array / null / string / number) must raise the ValueError
    # `_resolve_diff_source` catches, not an unhandled AttributeError that
    # escapes as a raw traceback.
    for payload in ([], None, "x", 42):
        with pytest.raises(ValueError, match="JSON object"):
            Schema.from_snapshot(payload)  # type: ignore[arg-type]


def test_from_snapshot_rejects_injection_in_secdef_signature() -> None:
    # Regression (round-7): `signature` is interpolated into the
    # ALTER FUNCTION the SEC015 fixer emits, so a hand-crafted snapshot
    # smuggling DDL through it must be rejected at the decode boundary
    # like data_type / privileges already are.
    snap = _minimal_snapshot()
    snap["security_definer_functions"] = [
        {
            "qualified_name": "public.f",
            "body": "SELECT 1",
            "language": "sql",
            "signature":
                "integer) RETURNS void LANGUAGE sql AS ''; "
                "DROP TABLE users; --",
        }
    ]
    with pytest.raises(ValueError, match="signature"):
        Schema.from_snapshot(snap)


def test_from_snapshot_rejects_injection_in_leakproof_signature() -> None:
    snap = _minimal_snapshot()
    snap["leakproof_functions"] = [
        {"qualified_name": "public.f", "signature": "integer); DROP TABLE x; --"}
    ]
    with pytest.raises(ValueError, match="signature"):
        Schema.from_snapshot(snap)


def test_from_snapshot_accepts_real_function_signatures() -> None:
    # Real pg_get_function_identity_arguments outputs must round-trip.
    snap = _minimal_snapshot()
    snap["security_definer_functions"] = [
        {"qualified_name": "public.f", "body": "SELECT 1", "language": "sql",
         "signature": "a integer, b text[]"},
    ]
    snap["leakproof_functions"] = [
        {"qualified_name": "public.g", "signature": "VARIADIC text[]"},
    ]
    schema = Schema.from_snapshot(snap)
    assert schema.security_definer_functions[0].signature == "a integer, b text[]"
    assert schema.leakproof_functions[0].signature == "VARIADIC text[]"


def test_from_snapshot_rejects_trailing_comment_in_secdef_signature() -> None:
    # Regression (round-10 #4): the CREATE FUNCTION probe accepts a
    # post-paramlist `SET` clause and a trailing `--` comments out the
    # probe's own `)` tail, so this tampered signature would PASS the
    # old probe and let the SEC015 fixer emit an ALTER FUNCTION that
    # pins pg_temp FIRST (re-introducing CVE-2018-1058). The comment
    # guard rejects it at the decode boundary.
    snap = _minimal_snapshot()
    snap["security_definer_functions"] = [
        {
            "qualified_name": "public.f",
            "body": "SELECT 1",
            "language": "sql",
            "signature": "integer) SET search_path = pg_temp, public --",
        }
    ]
    with pytest.raises(ValueError, match="signature"):
        Schema.from_snapshot(snap)


def test_from_snapshot_rejects_trailing_comment_in_leakproof_signature() -> None:
    snap = _minimal_snapshot()
    snap["leakproof_functions"] = [
        {"qualified_name": "public.f", "signature": "integer) SECURITY DEFINER --"}
    ]
    with pytest.raises(ValueError, match="signature"):
        Schema.from_snapshot(snap)
