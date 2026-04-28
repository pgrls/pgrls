"""Unit tests for SEC002 — FORCE ROW LEVEL SECURITY missing."""
from __future__ import annotations

from pgrls.model import Schema, Table
from pgrls.rules.sec002 import SEC002


def _table(schema: str, name: str, *, rls: bool, force: bool) -> Table:
    return Table(
        schema=schema,
        name=name,
        rls_enabled=rls,
        force_rls=force,
        policies=(),
    )


def test_sec002_fires_when_rls_enabled_and_force_disabled() -> None:
    schema = Schema(
        tables=(_table("public", "t", rls=True, force=False),)
    )
    violations = SEC002().check(schema, options={})
    assert len(violations) == 1
    v = violations[0]
    assert v.rule_id == "SEC002"
    assert v.severity == "error"
    assert v.location == "public.t"


def test_sec002_does_not_fire_when_force_enabled() -> None:
    schema = Schema(
        tables=(_table("public", "t", rls=True, force=True),)
    )
    assert SEC002().check(schema, options={}) == []


def test_sec002_does_not_fire_when_rls_disabled() -> None:
    schema = Schema(
        tables=(_table("public", "t", rls=False, force=False),)
    )
    assert SEC002().check(schema, options={}) == []


def test_sec002_allowlist_exempts_unqualified_match() -> None:
    schema = Schema(
        tables=(_table("public", "t", rls=True, force=False),)
    )
    assert SEC002().check(schema, options={"allowlist": ["t"]}) == []


def test_sec002_allowlist_exempts_qualified_match() -> None:
    schema = Schema(
        tables=(_table("public", "t", rls=True, force=False),)
    )
    assert SEC002().check(schema, options={"allowlist": ["public.t"]}) == []


def test_sec002_allowlist_does_not_exempt_unrelated_table() -> None:
    schema = Schema(
        tables=(_table("public", "t", rls=True, force=False),)
    )
    violations = SEC002().check(schema, options={"allowlist": ["other"]})
    assert len(violations) == 1


def test_sec002_bad_allowlist_type_raises_clearly() -> None:
    schema = Schema(
        tables=(_table("public", "t", rls=True, force=False),)
    )
    import pytest
    with pytest.raises(TypeError, match="allowlist"):
        SEC002().check(schema, options={"allowlist": "t"})  # type: ignore[arg-type]


def test_sec002_bad_allowlist_item_type_raises_clearly() -> None:
    schema = Schema(
        tables=(_table("public", "t", rls=True, force=False),)
    )
    import pytest
    with pytest.raises(TypeError, match="allowlist"):
        SEC002().check(schema, options={"allowlist": [123]})  # type: ignore[list-item]
