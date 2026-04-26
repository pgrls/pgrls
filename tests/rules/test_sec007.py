"""Unit tests for SEC007 — every policy on the table is permissive."""
from __future__ import annotations

import pytest

from pgrls.model import Policy, Schema, Table
from pgrls.rules.sec007 import SEC007


def _policy(*, name: str = "p", permissive: bool = True) -> Policy:
    return Policy(
        name=name,
        command="SELECT",
        permissive=permissive,
        roles=("authenticated",),
        using_sql="id IS NOT NULL",
        with_check_sql=None,
    )


def _table(
    *,
    rls_enabled: bool = True,
    policies: tuple[Policy, ...],
    schema: str = "public",
    name: str = "t",
) -> Table:
    return Table(
        schema=schema,
        name=name,
        rls_enabled=rls_enabled,
        force_rls=True,
        policies=policies,
        columns=("id",),
    )


def _wrap(table: Table) -> Schema:
    return Schema(tables=(table,))


def test_sec007_fires_on_all_permissive_table() -> None:
    schema = _wrap(
        _table(
            policies=(
                _policy(name="a", permissive=True),
                _policy(name="b", permissive=True),
            )
        )
    )
    violations = SEC007().check(schema, {})
    assert len(violations) == 1
    assert violations[0].rule_id == "SEC007"
    assert violations[0].location == "public.t"


def test_sec007_fires_on_single_permissive_policy() -> None:
    # Single permissive is still "all permissive" — the missing
    # restrictive floor is the same problem.
    schema = _wrap(_table(policies=(_policy(),)))
    assert len(SEC007().check(schema, {})) == 1


def test_sec007_does_not_fire_when_any_policy_is_restrictive() -> None:
    schema = _wrap(
        _table(
            policies=(
                _policy(name="a", permissive=True),
                _policy(name="b", permissive=False),
            )
        )
    )
    assert SEC007().check(schema, {}) == []


def test_sec007_does_not_fire_on_rls_disabled_table() -> None:
    # SEC001 covers this surface; SEC007 must not duplicate it.
    schema = _wrap(
        _table(rls_enabled=False, policies=(_policy(),))
    )
    assert SEC007().check(schema, {}) == []


def test_sec007_does_not_fire_on_table_with_no_policies() -> None:
    # RLS-enabled with zero policies = deny-by-default. Not a SEC007
    # finding, even though `all([])` is vacuously True.
    schema = _wrap(_table(policies=()))
    assert SEC007().check(schema, {}) == []


def test_sec007_allowlist_exempts_qualified_table_id() -> None:
    schema = _wrap(_table(policies=(_policy(),)))
    assert SEC007().check(schema, {"allowlist": ["public.t"]}) == []


def test_sec007_bad_allowlist_type_raises_clearly() -> None:
    schema = _wrap(_table(policies=(_policy(),)))
    with pytest.raises(TypeError, match="allowlist"):
        SEC007().check(schema, {"allowlist": "public.t"})  # type: ignore[dict-item]


def test_sec007_bad_allowlist_item_type_raises_clearly() -> None:
    schema = _wrap(_table(policies=(_policy(),)))
    with pytest.raises(TypeError, match="allowlist"):
        SEC007().check(schema, {"allowlist": ["public.t", 1]})  # type: ignore[list-item]


def test_sec007_fires_on_each_offending_table_independently() -> None:
    schema = Schema(
        tables=(
            _table(
                schema="public",
                name="all_perm",
                policies=(_policy(name="a"), _policy(name="b")),
            ),
            _table(
                schema="public",
                name="mixed",
                policies=(
                    _policy(name="a", permissive=True),
                    _policy(name="b", permissive=False),
                ),
            ),
            _table(
                schema="tenant",
                name="all_perm_too",
                policies=(_policy(name="a"),),
            ),
        )
    )
    locations = sorted(v.location for v in SEC007().check(schema, {}))
    assert locations == ["public.all_perm", "tenant.all_perm_too"]
