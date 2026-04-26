"""Unit tests for SEC003 — Permissive policy grants PUBLIC."""
from __future__ import annotations

from pgrls.model import Policy, Schema, Table
from pgrls.rules.sec003 import SEC003


def _table_with_policy(policy: Policy) -> Table:
    return Table(
        schema="public",
        name="t",
        rls_enabled=True,
        force_rls=True,
        policies=(policy,),
    )


def _policy(name: str, *, permissive: bool, roles: tuple[str, ...]) -> Policy:
    return Policy(
        name=name,
        command="SELECT",
        permissive=permissive,
        roles=roles,
        using_sql="true",
        with_check_sql=None,
    )


def test_sec003_fires_on_permissive_public_policy() -> None:
    schema = Schema(
        tables=(
            _table_with_policy(
                _policy("p", permissive=True, roles=("PUBLIC",))
            ),
        )
    )
    violations = SEC003().check(schema, options={})
    assert len(violations) == 1
    v = violations[0]
    assert v.rule_id == "SEC003"
    assert v.severity == "error"
    assert v.location == "public.t.p"


def test_sec003_does_not_fire_on_restrictive_public_policy() -> None:
    schema = Schema(
        tables=(
            _table_with_policy(
                _policy("p", permissive=False, roles=("PUBLIC",))
            ),
        )
    )
    assert SEC003().check(schema, options={}) == []


def test_sec003_does_not_fire_on_permissive_specific_role() -> None:
    schema = Schema(
        tables=(
            _table_with_policy(
                _policy("p", permissive=True, roles=("authenticated",))
            ),
        )
    )
    assert SEC003().check(schema, options={}) == []


def test_sec003_allowlist_exempts_qualified_policy_id() -> None:
    schema = Schema(
        tables=(
            _table_with_policy(
                _policy("p", permissive=True, roles=("PUBLIC",))
            ),
        )
    )
    assert SEC003().check(
        schema, options={"allowlist": ["public.t.p"]}
    ) == []


def test_sec003_bad_allowlist_type_raises_clearly() -> None:
    schema = Schema(
        tables=(
            _table_with_policy(
                _policy("p", permissive=True, roles=("PUBLIC",))
            ),
        )
    )
    import pytest
    with pytest.raises(TypeError, match="allowlist"):
        SEC003().check(schema, options={"allowlist": "p"})  # type: ignore[arg-type]
