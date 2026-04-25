from __future__ import annotations

from pgrls.model import Schema, Table
from pgrls.rules.sec001 import SEC001


def _table(name: str, *, rls: bool, schema: str = "public") -> Table:
    return Table(
        schema=schema,
        name=name,
        rls_enabled=rls,
        force_rls=False,
        policies=(),
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
