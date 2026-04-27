from __future__ import annotations

from pgrls.model import Schema, Table
from pgrls.rules.sec001 import SEC001


def _table(
    name: str,
    *,
    rls: bool,
    schema: str = "public",
    partition_of: tuple[str, str] | None = None,
) -> Table:
    return Table(
        schema=schema,
        name=name,
        rls_enabled=rls,
        force_rls=False,
        policies=(),
        partition_of=partition_of,
    )


def test_flags_table_without_rls() -> None:
    schema = Schema(tables=(_table("users", rls=False),))
    violations = SEC001().check(schema, options={})
    assert len(violations) == 1
    v = violations[0]
    assert v.rule_id == "SEC001"
    assert v.severity == "error"
    assert v.location == "public.users"
    assert "users" in v.message


def test_no_violation_when_rls_enabled() -> None:
    schema = Schema(tables=(_table("users", rls=True),))
    assert SEC001().check(schema, options={}) == []


def test_multiple_tables_independent() -> None:
    schema = Schema(
        tables=(
            _table("with_rls", rls=True),
            _table("without_rls_a", rls=False),
            _table("without_rls_b", rls=False),
        )
    )
    violations = SEC001().check(schema, options={})
    locations = sorted(v.location for v in violations)
    assert locations == ["public.without_rls_a", "public.without_rls_b"]


def test_allowlist_skips_table_by_unqualified_name() -> None:
    schema = Schema(
        tables=(
            _table("countries", rls=False),
            _table("users", rls=False),
        )
    )
    violations = SEC001().check(schema, options={"allowlist": ["countries"]})
    locations = [v.location for v in violations]
    assert locations == ["public.users"]


def test_allowlist_supports_qualified_names() -> None:
    schema = Schema(
        tables=(
            _table("things", rls=False, schema="tenant"),
            _table("things", rls=False, schema="public"),
        )
    )
    violations = SEC001().check(
        schema, options={"allowlist": ["tenant.things"]}
    )
    locations = [v.location for v in violations]
    assert locations == ["public.things"]


def test_allowlist_invalid_type_raises() -> None:
    schema = Schema(tables=(_table("users", rls=False),))
    try:
        SEC001().check(schema, options={"allowlist": "users"})
    except TypeError as exc:
        assert "allowlist" in str(exc)
    else:
        raise AssertionError("expected TypeError")


def test_metadata_present() -> None:
    rule = SEC001()
    assert rule.id == "SEC001"
    assert rule.severity == "error"
    assert rule.title


def test_does_not_fire_on_partition_child_when_parent_has_rls() -> None:
    # Postgres does not propagate relrowsecurity to partition children.
    # Without partition awareness SEC001 falsely fires on every child of
    # a partitioned RLS-enabled parent. Pin that the partition_of chain
    # is consulted before reporting.
    parent = _table("events", rls=True)
    child = _table(
        "events_2026", rls=False, partition_of=("public", "events")
    )
    schema = Schema(tables=(parent, child))
    assert SEC001().check(schema, options={}) == []


def test_fires_on_partition_child_when_parent_lacks_rls() -> None:
    parent = _table("events", rls=False)
    child = _table(
        "events_2026", rls=False, partition_of=("public", "events")
    )
    schema = Schema(tables=(parent, child))
    locations = sorted(v.location for v in SEC001().check(schema, options={}))
    assert locations == ["public.events", "public.events_2026"]


def test_walks_multi_level_partition_chain() -> None:
    # events (RLS) -> events_t1 (no RLS, partitioned) -> events_t1_2026
    # The grandchild's chain reaches RLS via events_t1 -> events. Skip it.
    grandparent = _table("events", rls=True)
    middle = _table(
        "events_t1", rls=False, partition_of=("public", "events")
    )
    leaf = _table(
        "events_t1_2026",
        rls=False,
        partition_of=("public", "events_t1"),
    )
    schema = Schema(tables=(grandparent, middle, leaf))
    assert SEC001().check(schema, options={}) == []


def test_fires_on_partition_child_when_ancestor_outside_schema_scope() -> None:
    # If the parent lives in a schema we didn't introspect, partition_of
    # still points to it but the lookup fails. Conservative behavior:
    # we cannot prove RLS coverage, so SEC001 fires (no silent pass).
    child = _table(
        "events_2026", rls=False, partition_of=("other", "events")
    )
    schema = Schema(tables=(child,))
    violations = SEC001().check(schema, options={})
    assert len(violations) == 1
    assert violations[0].location == "public.events_2026"
