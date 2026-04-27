"""Unit tests for SEC005 — policy expression has no own-column reference."""
from __future__ import annotations

import pytest

from pgrls.ast_utils import parse_expr
from pgrls.model import Policy, Schema, Table
from pgrls.rules.sec005 import SEC005


def _policy(
    using: str | None = None,
    with_check: str | None = None,
    *,
    name: str = "p",
    command: str = "SELECT",
) -> Policy:
    return Policy(
        name=name,
        command=command,  # type: ignore[arg-type]
        permissive=True,
        roles=("authenticated",),
        using_sql=using,
        with_check_sql=with_check,
        using_ast=parse_expr(using) if using else None,
        with_check_ast=parse_expr(with_check) if with_check else None,
    )


def _wrap(
    policy: Policy,
    *,
    columns: tuple[str, ...] = ("id", "tenant_id", "email"),
    table_name: str = "t",
    schema_name: str = "public",
) -> Schema:
    return Schema(
        tables=(
            Table(
                schema=schema_name,
                name=table_name,
                rls_enabled=True,
                force_rls=True,
                policies=(policy,),
                columns=columns,
            ),
        )
    )


def test_sec005_fires_when_using_has_no_column_ref() -> None:
    # The classic "session-state-only" predicate — no row attributes used.
    schema = _wrap(
        _policy(using="'admin' = current_setting('app.role')")
    )
    violations = SEC005().check(schema, {})
    assert len(violations) == 1
    assert violations[0].rule_id == "SEC005"
    assert violations[0].location == "public.t.p"


def test_sec005_does_not_fire_with_one_part_own_column_ref() -> None:
    schema = _wrap(
        _policy(using="tenant_id = current_setting('app.t')")
    )
    assert SEC005().check(schema, {}) == []


def test_sec005_does_not_fire_with_two_part_own_column_ref() -> None:
    schema = _wrap(
        _policy(using="t.tenant_id = current_setting('app.t')")
    )
    assert SEC005().check(schema, {}) == []


def test_sec005_does_not_fire_with_three_part_own_column_ref() -> None:
    schema = _wrap(
        _policy(using="public.t.tenant_id = current_setting('app.t')")
    )
    assert SEC005().check(schema, {}) == []


def test_sec005_fires_when_two_part_ref_targets_a_different_table() -> None:
    # `other.tenant_id` is a ref to another table's column; it doesn't
    # count as own.
    schema = _wrap(
        _policy(using="other.tenant_id = current_setting('app.t')")
    )
    assert len(SEC005().check(schema, {})) == 1


def test_sec005_fires_when_three_part_ref_targets_a_different_schema() -> None:
    schema = _wrap(
        _policy(using="other.t.tenant_id = current_setting('app.t')")
    )
    assert len(SEC005().check(schema, {})) == 1


def test_sec005_does_not_fire_when_with_check_has_own_column() -> None:
    # Combined USING + WITH CHECK — coverage from either is enough.
    schema = _wrap(
        _policy(
            using=None,
            with_check="tenant_id = current_setting('app.t')",
            command="INSERT",
        )
    )
    assert SEC005().check(schema, {}) == []


def test_sec005_fires_when_only_refs_are_inside_a_sublink() -> None:
    # Subquery refs `tenant_uid` (a column of `tenants`, not the policy's
    # table). With no own-col anywhere in the expression, SEC005 fires.
    # Choosing a column name absent from the policy's table is necessary
    # because SEC005 walks subqueries too — see the module docstring for
    # the false-negative trade-off.
    schema = _wrap(
        _policy(
            using=(
                "current_setting('app.t') IN (SELECT tenant_uid FROM tenants)"
            )
        )
    )
    assert len(SEC005().check(schema, {})) == 1


def test_sec005_does_not_fire_on_correlated_exists_membership() -> None:
    # Standard membership-table pattern: the policy's own `tenant_id`
    # is referenced via correlation inside the EXISTS. SEC005 must not
    # fire — the policy IS row-scoped, just through a join. Pins the
    # fix for the false positive that exclude_sublinks=True introduced.
    schema = _wrap(
        _policy(
            using=(
                "EXISTS (SELECT 1 FROM tenant_members m "
                "WHERE m.tenant_id = tenant_id "
                "AND m.user_id = current_setting('app.user_id'))"
            )
        )
    )
    assert SEC005().check(schema, {}) == []


def test_sec005_does_not_fire_with_function_wrapped_own_column() -> None:
    # `lower(email)` still references `email`; extract_column_refs walks
    # function arguments.
    schema = _wrap(
        _policy(using="lower(email) = 'admin@example.com'")
    )
    assert SEC005().check(schema, {}) == []


def test_sec005_does_not_fire_when_table_has_no_columns() -> None:
    # Defensive no-op: nothing to reference, nothing to fire on.
    schema = _wrap(
        _policy(using="'admin' = current_setting('app.role')"),
        columns=(),
    )
    assert SEC005().check(schema, {}) == []


def test_sec005_skips_when_both_asts_are_none() -> None:
    # Defensive: parse failure or missing clauses → no violation, no error.
    p = Policy(
        name="p",
        command="SELECT",
        permissive=True,
        roles=("authenticated",),
        using_sql=None,
        with_check_sql=None,
        using_ast=None,
        with_check_ast=None,
    )
    schema = _wrap(p)
    assert SEC005().check(schema, {}) == []


def test_sec005_allowlist_exempts_qualified_policy_id() -> None:
    schema = _wrap(
        _policy(using="'admin' = current_setting('app.role')")
    )
    options = {"allowlist": ["public.t.p"]}
    assert SEC005().check(schema, options) == []


def test_sec005_bad_allowlist_type_raises_clearly() -> None:
    schema = _wrap(
        _policy(using="'admin' = current_setting('app.role')")
    )
    with pytest.raises(TypeError, match="allowlist"):
        SEC005().check(schema, {"allowlist": "public.t.p"})  # type: ignore[dict-item]


def test_sec005_bad_allowlist_item_type_raises_clearly() -> None:
    schema = _wrap(
        _policy(using="'admin' = current_setting('app.role')")
    )
    with pytest.raises(TypeError, match="allowlist"):
        SEC005().check(schema, {"allowlist": ["public.t.p", 42]})  # type: ignore[list-item]


def test_sec005_fires_on_each_offending_policy_independently() -> None:
    schema = Schema(
        tables=(
            Table(
                schema="public",
                name="t",
                rls_enabled=True,
                force_rls=True,
                columns=("id", "tenant_id"),
                policies=(
                    _policy(
                        name="bad_a",
                        using="'admin' = current_setting('app.role')",
                    ),
                    _policy(
                        name="good",
                        using="tenant_id = current_setting('app.t')",
                    ),
                    _policy(
                        name="bad_b",
                        using="current_setting('app.role') IS NOT NULL",
                    ),
                ),
            ),
        )
    )
    violations = SEC005().check(schema, {})
    locations = sorted(v.location for v in violations)
    assert locations == ["public.t.bad_a", "public.t.bad_b"]
