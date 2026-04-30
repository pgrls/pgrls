from __future__ import annotations

import pytest

from pgrls.model import Policy, PolicyCommand, Schema, Snapshot, Table


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
        "version": 4,
        "tables": [
            {
                "schema": "public",
                "name": "orders",
                "rls_enabled": True,
                "force_rls": False,
                "columns": [],
                "partition_of": None,
                "grants": [],
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


def test_snapshot_version_is_four_after_views_addition() -> None:
    # `views` was added for v0.3 — SNAPSHOT_VERSION bumped from
    # 3 → 4 per the model.py docstring contract that additive structural
    # changes bump the version. Pin the new version so a future bump is
    # deliberate.
    snap = Schema(tables=()).to_snapshot()
    assert snap["version"] == 4


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


def test_snapshot_v4_top_level_keys_are_stable_contract() -> None:
    # Snapshot top-level keys are part of the public surface (any
    # consumer reading the JSON depends on these names). Pin
    # `version`, `tables`, `policies`, `views` so a quiet refactor
    # that renames or drops a key fails this test rather than
    # slipping past CI.
    snap = Schema(tables=()).to_snapshot()
    assert set(snap.keys()) == {"version", "tables", "policies", "views"}
    assert snap["version"] == 4


def test_snapshot_v3_table_entry_keys_are_stable() -> None:
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
