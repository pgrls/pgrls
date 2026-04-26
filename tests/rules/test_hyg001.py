"""Unit tests for HYG001 — orphaned column reference."""
from __future__ import annotations

from pgrls.ast_utils import parse_expr
from pgrls.model import Policy, Schema, Table
from pgrls.rules.hyg001 import HYG001


def _policy_with(using: str | None, with_check: str | None = None) -> Policy:
    return Policy(
        name="p",
        command="SELECT",
        permissive=True,
        roles=("authenticated",),
        using_sql=using,
        with_check_sql=with_check,
        using_ast=parse_expr(using) if using else None,
        with_check_ast=parse_expr(with_check) if with_check else None,
    )


def _table(columns: tuple[str, ...], policy: Policy) -> Schema:
    return Schema(
        tables=(
            Table(
                schema="public",
                name="t",
                rls_enabled=True,
                force_rls=True,
                policies=(policy,),
                columns=columns,
            ),
        )
    )


def test_hyg001_fires_when_policy_references_dropped_column() -> None:
    schema = _table(
        columns=("id", "tenant_id"),
        policy=_policy_with("dropped_col = 'x'"),
    )
    violations = HYG001().check(schema, {})
    assert len(violations) == 1
    assert violations[0].rule_id == "HYG001"
    assert violations[0].location == "public.t.p"
    assert "dropped_col" in violations[0].message


def test_hyg001_does_not_fire_when_all_columns_exist() -> None:
    schema = _table(
        columns=("id", "tenant_id"),
        policy=_policy_with("tenant_id = '1' AND id = 1"),
    )
    assert HYG001().check(schema, {}) == []


def test_hyg001_skips_qualified_refs_to_other_aliases() -> None:
    # Heuristic: only unqualified refs check against the host table.
    schema = _table(
        columns=("id",),
        policy=_policy_with("u.email = 'x'"),
    )
    assert HYG001().check(schema, {}) == []


def test_hyg001_skips_subquery_internal_columns() -> None:
    # Heuristic: refs inside SubLink are not checked against host columns.
    schema = _table(
        columns=("id",),
        policy=_policy_with(
            "id IN (SELECT u_id FROM users WHERE active = true)"
        ),
    )
    assert HYG001().check(schema, {}) == []


def test_hyg001_walks_with_check_too() -> None:
    schema = _table(
        columns=("id",),
        policy=_policy_with(
            using="id = 1",
            with_check="dropped_col = 'x'",
        ),
    )
    violations = HYG001().check(schema, {})
    assert len(violations) == 1


def test_hyg001_skips_policy_without_ast() -> None:
    schema = _table(
        columns=("id",),
        policy=Policy(
            name="p",
            command="SELECT",
            permissive=True,
            roles=("authenticated",),
            using_sql=None,
            with_check_sql=None,
            using_ast=None,
            with_check_ast=None,
        ),
    )
    assert HYG001().check(schema, {}) == []
