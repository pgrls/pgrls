"""Unit tests for PERF004 — function-wrapped column defeats a plain index.

PERF004 (warning) fires when a policy predicate wraps an own-table
column in a function (`lower(email) = …`) AND the table has a plain
leading-column index on that column — the plain index can't serve the
wrapped predicate, so Postgres seq-scans. It is the precise complement
of PERF003 (which owns the *no index at all* case); the two are
disjoint on the index condition.
"""
from __future__ import annotations

import pytest

from pgrls.ast_utils import parse_expr
from pgrls.model import Index, Policy, Schema, Table
from pgrls.rules.perf003 import PERF003
from pgrls.rules.perf004 import PERF004


def _policy(
    name: str = "p",
    *,
    using_sql: str | None = "lower(email) = current_setting('app.email')",
    with_check_sql: str | None = None,
) -> Policy:
    return Policy(
        name=name,
        command="SELECT",
        permissive=True,
        roles=("authenticated",),
        using_sql=using_sql,
        with_check_sql=with_check_sql,
        using_ast=parse_expr(using_sql) if using_sql else None,
        with_check_ast=parse_expr(with_check_sql) if with_check_sql else None,
    )


def _index(columns: tuple[str, ...], name: str = "idx") -> Index:
    return Index(
        name=name,
        access_method="btree",
        columns=columns,
        is_unique=False,
        is_partial=False,
    )


def _table(
    *,
    policies: tuple[Policy, ...] = (),
    indexes: tuple[Index, ...] = (),
    columns: tuple[str, ...] = ("id", "email", "tenant_id"),
    rls: bool = True,
    name: str = "users",
) -> Table:
    return Table(
        schema="public",
        name=name,
        rls_enabled=rls,
        force_rls=rls,
        policies=policies,
        indexes=indexes,
        columns=columns,
    )


def test_perf004_fires_on_wrapped_column_with_plain_index() -> None:
    schema = Schema(
        tables=(
            _table(policies=(_policy(),), indexes=(_index(("email",)),)),
        )
    )
    [v] = PERF004().check(schema, {})
    assert v.rule_id == "PERF004"
    assert v.severity == "warning"
    assert v.location == "public.users.p"
    assert "'email'" in v.message


def test_perf004_silent_when_wrapped_column_has_no_index() -> None:
    # No index on email → PERF003's case (column un-indexed), not PERF004.
    schema = Schema(tables=(_table(policies=(_policy(),), indexes=()),))
    assert PERF004().check(schema, {}) == []


def test_perf004_silent_on_bare_indexed_column() -> None:
    # `tenant_id = current_setting(...)` — bare column, index usable.
    schema = Schema(
        tables=(
            _table(
                policies=(
                    _policy(using_sql="tenant_id = current_setting('app.t')"),
                ),
                indexes=(_index(("tenant_id",)),),
            ),
        )
    )
    assert PERF004().check(schema, {}) == []


def test_perf004_silent_when_function_wraps_the_value_not_the_column() -> None:
    # `tenant_id = lower(current_setting(...))` — the func wraps the
    # VALUE; tenant_id is a bare operand, its index is usable.
    schema = Schema(
        tables=(
            _table(
                policies=(
                    _policy(
                        using_sql=(
                            "tenant_id = lower(current_setting('app.t'))"
                        )
                    ),
                ),
                indexes=(_index(("tenant_id",)),),
            ),
        )
    )
    assert PERF004().check(schema, {}) == []


def test_perf004_fires_on_with_check_too() -> None:
    schema = Schema(
        tables=(
            _table(
                policies=(
                    _policy(
                        using_sql=None,
                        with_check_sql="lower(email) = current_setting('app.e')",
                    ),
                ),
                indexes=(_index(("email",)),),
            ),
        )
    )
    assert len(PERF004().check(schema, {})) == 1


def test_perf004_fires_on_nested_function_wrap() -> None:
    schema = Schema(
        tables=(
            _table(
                policies=(
                    _policy(using_sql="lower(upper(email)) = current_setting('app.e')"),
                ),
                indexes=(_index(("email",)),),
            ),
        )
    )
    assert len(PERF004().check(schema, {})) == 1


def test_perf004_silent_on_coalesce_out_of_scope() -> None:
    # `coalesce(...)` is a CoalesceExpr node, not a FuncCall — PERF004
    # is deliberately scoped to FuncCall wrapping (the textbook
    # functional-index case), so this is out of scope and stays silent.
    schema = Schema(
        tables=(
            _table(
                policies=(
                    _policy(using_sql="coalesce(tenant_id, 0) = 1"),
                ),
                indexes=(_index(("tenant_id",)),),
            ),
        )
    )
    assert PERF004().check(schema, {}) == []


def test_perf004_skips_sublink_column_refs() -> None:
    # Regression (#24): a function-wrapped column INSIDE a sub-select
    # (`EXISTS (SELECT 1 FROM members WHERE lower(email) = …)`) belongs
    # to `members`, not the policy's own table — the docstring excludes
    # sub-select columns. Even though `email` is an own-table column
    # name with a plain index here, the `lower(email)` inside the
    # sub-select must NOT be collected, or PERF004 false-fires on the
    # own table's index. Mirrors PERF003's
    # `test_perf003_skips_sublink_column_refs`.
    schema = Schema(
        tables=(
            _table(
                policies=(
                    _policy(
                        using_sql=(
                            "EXISTS (SELECT 1 FROM members "
                            "WHERE lower(email) = "
                            "lower(current_setting('app.email')))"
                        )
                    ),
                ),
                indexes=(_index(("email",)),),
            ),
        )
    )
    assert PERF004().check(schema, {}) == []


def test_perf004_still_fires_on_own_wrap_alongside_sublink() -> None:
    # Precision companion to the skip above: a direct own-column wrap
    # (`lower(email) = …`) in the SAME policy as a sub-select still
    # fires on the own column — the sublink skip must not suppress the
    # genuine own-table finding.
    schema = Schema(
        tables=(
            _table(
                policies=(
                    _policy(
                        using_sql=(
                            "lower(email) = current_setting('app.email') "
                            "OR EXISTS (SELECT 1 FROM members "
                            "WHERE lower(members.alias) = 'x')"
                        )
                    ),
                ),
                indexes=(_index(("email",)),),
            ),
        )
    )
    [v] = PERF004().check(schema, {})
    assert "'email'" in v.message


def test_perf004_silent_when_rls_disabled() -> None:
    schema = Schema(
        tables=(
            _table(policies=(_policy(),), indexes=(_index(("email",)),), rls=False),
        )
    )
    assert PERF004().check(schema, {}) == []


def test_perf004_respects_allowlist() -> None:
    schema = Schema(
        tables=(
            _table(policies=(_policy(),), indexes=(_index(("email",)),)),
        )
    )
    assert PERF004().check(schema, {"allowlist": ["public.users.p"]}) == []


def test_perf004_and_perf003_are_disjoint_on_wrapped_column() -> None:
    # Wrapped column WITH a plain index: PERF004 fires, PERF003 silent.
    indexed = Schema(
        tables=(_table(policies=(_policy(),), indexes=(_index(("email",)),)),)
    )
    assert len(PERF004().check(indexed, {})) == 1
    assert PERF003().check(indexed, {}) == []
    # Wrapped column with NO index: PERF003 fires, PERF004 silent.
    bare = Schema(tables=(_table(policies=(_policy(),), indexes=()),))
    assert PERF004().check(bare, {}) == []
    assert len(PERF003().check(bare, {})) == 1


def test_perf004_composite_predicate_splits_by_column_with_perf003() -> None:
    # `lower(email) = X AND tenant_id = Y` on a table where `email` has a
    # plain index but `tenant_id` has none. The two rules split the single
    # policy by column: PERF004 fires on the wrapped+indexed `email` (the
    # plain index can't serve `lower(email)`), PERF003 on the
    # bare-unindexed `tenant_id`. Same policy, different columns — this
    # pins the per-column disjointness contract the docstrings rely on
    # ("a column trips at most one"), which per-policy set membership in
    # the combined-fixture test does not exercise.
    schema = Schema(
        tables=(
            _table(
                policies=(
                    _policy(
                        using_sql=(
                            "lower(email) = current_setting('app.e') "
                            "AND tenant_id = current_setting('app.t')"
                        )
                    ),
                ),
                indexes=(_index(("email",)),),
            ),
        )
    )
    [p4] = PERF004().check(schema, {})
    assert "'email'" in p4.message
    assert "'tenant_id'" not in p4.message
    [p3] = PERF003().check(schema, {})
    assert "'tenant_id'" in p3.message
    assert "'email'" not in p3.message


def test_perf004_bad_allowlist_type_raises() -> None:
    schema = Schema(
        tables=(_table(policies=(_policy(),), indexes=(_index(("email",)),)),)
    )
    with pytest.raises(TypeError):
        PERF004().check(schema, {"allowlist": "public.users.p"})
