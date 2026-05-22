"""Unit tests for PERF003 — policy predicate column without leading-column index."""
from __future__ import annotations

import pytest

from pgrls.ast_utils import parse_expr
from pgrls.model import Index, Policy, Schema, Table
from pgrls.rules.perf003 import PERF003


def _policy(
    name: str = "p",
    *,
    using_sql: str | None = "tenant_id = current_setting('app.tenant_id')",
    with_check_sql: str | None = None,
    permissive: bool = True,
    command: str = "SELECT",
) -> Policy:
    return Policy(
        name=name,
        command=command,  # type: ignore[arg-type]
        permissive=permissive,
        roles=("authenticated",),
        using_sql=using_sql,
        with_check_sql=with_check_sql,
        using_ast=parse_expr(using_sql) if using_sql else None,
        with_check_ast=parse_expr(with_check_sql) if with_check_sql else None,
    )


def _index(name: str = "idx", *, columns: tuple[str, ...] = ("tenant_id",),
           access_method: str = "btree", is_unique: bool = False,
           is_partial: bool = False) -> Index:
    return Index(
        name=name,
        access_method=access_method,
        columns=columns,
        is_unique=is_unique,
        is_partial=is_partial,
    )


def _table(
    name: str = "t",
    *,
    schema: str = "public",
    rls: bool = True,
    policies: tuple[Policy, ...] = (),
    indexes: tuple[Index, ...] = (),
) -> Table:
    return Table(
        schema=schema,
        name=name,
        rls_enabled=rls,
        force_rls=rls,
        policies=policies,
        indexes=indexes,
    )


def test_perf003_fires_when_policy_column_lacks_index() -> None:
    # Canonical case: tenant_id-filtered policy, no index on tenant_id.
    schema = Schema(
        tables=(
            _table(
                "invoices",
                policies=(_policy("tenant_read"),),
                indexes=(),
            ),
        )
    )
    [v] = PERF003().check(schema, {})
    assert v.rule_id == "PERF003"
    assert v.severity == "warning"
    assert v.location == "public.invoices.tenant_read"
    assert "'tenant_id'" in v.message
    assert "leading-column index" in v.message


def test_perf003_silent_when_column_has_btree_leading_index() -> None:
    # The standard fix: a B-tree with tenant_id as the leading
    # column makes the planner happy. Rule must NOT fire.
    schema = Schema(
        tables=(
            _table(
                "invoices",
                policies=(_policy("tenant_read"),),
                indexes=(_index("tenant_idx", columns=("tenant_id",)),),
            ),
        )
    )
    assert PERF003().check(schema, {}) == []


def test_perf003_silent_when_column_is_leading_of_composite_index() -> None:
    # A composite B-tree (tenant_id, created_at) still helps the
    # tenant_id-equality predicate — the planner uses the leading
    # column.
    schema = Schema(
        tables=(
            _table(
                "invoices",
                policies=(_policy("tenant_read"),),
                indexes=(
                    _index(
                        "tenant_created",
                        columns=("tenant_id", "created_at"),
                    ),
                ),
            ),
        )
    )
    assert PERF003().check(schema, {}) == []


def test_perf003_fires_when_column_is_trailing_of_composite_index() -> None:
    # An index (created_at, tenant_id) does NOT help a tenant_id-
    # equality predicate — the leading column is created_at, and
    # Postgres can't use the index for tenant_id alone without an
    # explicit created_at range. Pin the strict "leading column only"
    # contract.
    schema = Schema(
        tables=(
            _table(
                "invoices",
                policies=(_policy("tenant_read"),),
                indexes=(
                    _index(
                        "created_tenant",
                        columns=("created_at", "tenant_id"),
                    ),
                ),
            ),
        )
    )
    [v] = PERF003().check(schema, {})
    assert "'tenant_id'" in v.message


def test_perf003_silent_when_rls_disabled() -> None:
    # No RLS → no policy-driven filtering → PERF003 has no concern.
    # SEC001 already covers the rls=False case.
    schema = Schema(
        tables=(
            _table(
                "events",
                rls=False,
                policies=(_policy("tenant_read"),),
                indexes=(),
            ),
        )
    )
    assert PERF003().check(schema, {}) == []


def test_perf003_silent_when_policy_has_no_column_refs() -> None:
    # A policy like `USING (true)` references no columns — nothing
    # for PERF003 to worry about. (SEC008 catches the `true` literal
    # separately.)
    schema = Schema(
        tables=(
            _table(
                "t",
                policies=(_policy("p", using_sql="true"),),
                indexes=(),
            ),
        )
    )
    assert PERF003().check(schema, {}) == []


def test_perf003_skips_sublink_column_refs() -> None:
    # `EXISTS (SELECT 1 FROM members WHERE members.id = members.user_id)`
    # — refs inside the sublink belong to `members`, not the policy's
    # own table. Without `exclude_sublinks=True`, the rule would
    # wrongly demand an index on `members.user_id` on the protected
    # table. Pin the sublink exclusion.
    schema = Schema(
        tables=(
            _table(
                "documents",
                policies=(_policy(
                    "p",
                    using_sql=(
                        "EXISTS (SELECT 1 FROM members "
                        "WHERE members.user_id = current_setting('app.user'))"
                    ),
                ),),
                indexes=(),
            ),
        )
    )
    # No own-table refs → no fire.
    assert PERF003().check(schema, {}) == []


def test_perf003_handles_qualified_own_table_refs() -> None:
    # `USING (invoices.tenant_id = ...)` — the qualifier matches the
    # table's bare name, so it IS an own-table ref. PERF003 should
    # still demand the index.
    schema = Schema(
        tables=(
            _table(
                "invoices",
                policies=(_policy(
                    "p",
                    using_sql=(
                        "invoices.tenant_id = current_setting('app.t')"
                    ),
                ),),
                indexes=(),
            ),
        )
    )
    [v] = PERF003().check(schema, {})
    assert "'tenant_id'" in v.message


def test_perf003_walks_with_check_clause_too() -> None:
    # INSERT/UPDATE policies use WITH CHECK. The predicate runs per
    # modified row — same per-row evaluation as USING, same need for
    # an index on the filtering column. Pin both branches.
    schema = Schema(
        tables=(
            _table(
                "invoices",
                policies=(_policy(
                    "p",
                    command="INSERT",
                    using_sql=None,
                    with_check_sql=(
                        "tenant_id = current_setting('app.tenant_id')"
                    ),
                ),),
                indexes=(),
            ),
        )
    )
    [v] = PERF003().check(schema, {})
    assert "'tenant_id'" in v.message


def test_perf003_lists_multiple_unindexed_columns_sorted() -> None:
    # A composite predicate referencing two columns, neither
    # indexed — both surface in one violation message, sorted
    # alphabetically for determinism.
    schema = Schema(
        tables=(
            _table(
                "t",
                policies=(_policy(
                    "p",
                    using_sql=(
                        "tenant_id = current_setting('app.t') "
                        "AND owner = current_setting('app.u')"
                    ),
                ),),
                indexes=(),
            ),
        )
    )
    [v] = PERF003().check(schema, {})
    # Both columns mentioned; alphabetical order ('owner', 'tenant_id').
    msg = v.message
    assert "'owner'" in msg
    assert "'tenant_id'" in msg
    # Alphabetical: owner comes before tenant_id.
    assert msg.index("'owner'") < msg.index("'tenant_id'")


def test_perf003_silent_when_one_of_two_columns_indexed() -> None:
    # Composite predicate: one column indexed, one not. The rule
    # fires only for the unindexed column. Pin the per-column
    # granularity.
    schema = Schema(
        tables=(
            _table(
                "t",
                policies=(_policy(
                    "p",
                    using_sql=(
                        "tenant_id = current_setting('app.t') "
                        "AND owner = current_setting('app.u')"
                    ),
                ),),
                indexes=(_index("tenant_idx", columns=("tenant_id",)),),
            ),
        )
    )
    [v] = PERF003().check(schema, {})
    assert "'owner'" in v.message
    assert "'tenant_id'" not in v.message


def test_perf003_treats_any_access_method_as_indexed() -> None:
    # The operator picked the index type. PERF003 doesn't second-
    # guess — hash, gin, gist, brin all satisfy the rule. Pin that
    # a non-btree index silences the rule.
    schema = Schema(
        tables=(
            _table(
                "t",
                policies=(_policy("p"),),
                indexes=(_index(
                    "hash_idx",
                    columns=("tenant_id",),
                    access_method="hash",
                ),),
            ),
        )
    )
    assert PERF003().check(schema, {}) == []


def test_perf003_treats_partial_index_as_indexed() -> None:
    # Partial indexes count — pgrls can't statically prove the
    # partial predicate is compatible with the policy predicate,
    # so we trust the operator's intent. False negatives are
    # preferable to false positives here.
    schema = Schema(
        tables=(
            _table(
                "t",
                policies=(_policy("p"),),
                indexes=(_index(
                    "partial_idx",
                    columns=("tenant_id",),
                    is_partial=True,
                ),),
            ),
        )
    )
    assert PERF003().check(schema, {}) == []


def test_perf003_skips_expression_index_positions() -> None:
    # Expression index `CREATE INDEX ON tbl (lower(email))` has
    # `columns = ("",)` after introspection (no column name for the
    # expression position). PERF003 v0.5.10 doesn't try to match
    # expressions — a column-named policy ref won't match an
    # expression-index leading position. Document the limitation.
    schema = Schema(
        tables=(
            _table(
                "t",
                policies=(_policy("p"),),
                indexes=(_index(
                    "expr_idx",
                    columns=("",),  # expression position
                ),),
            ),
        )
    )
    # tenant_id is the policy column; the expression index doesn't
    # match by name → PERF003 fires. The rule's message tells the
    # operator to allowlist if they have a matching expression index.
    [v] = PERF003().check(schema, {})
    assert "expression indexes aren't matched" in v.message
    assert "allowlist" in v.message.lower()


def test_perf003_allowlist_silences_specific_policy() -> None:
    schema = Schema(
        tables=(
            _table(
                "t",
                policies=(
                    _policy("a"),
                    _policy("b"),
                ),
                indexes=(),
            ),
        )
    )
    options = {"allowlist": ["public.t.a"]}
    locs = [v.location for v in PERF003().check(schema, options)]
    assert locs == ["public.t.b"]


def test_perf003_silent_when_no_policies() -> None:
    # RLS enabled but no policies — SEC009's territory. PERF003
    # has nothing to evaluate.
    schema = Schema(tables=(_table("t", policies=(), indexes=()),))
    assert PERF003().check(schema, {}) == []


def test_perf003_fires_per_policy_independently() -> None:
    # Two policies on the same table, both with unindexed columns —
    # two violations, in policy-iteration order.
    schema = Schema(
        tables=(
            _table(
                "t",
                policies=(
                    _policy("read", using_sql="tenant_id = current_setting('a')"),
                    _policy("write",
                            command="INSERT",
                            using_sql=None,
                            with_check_sql="owner = current_setting('u')"),
                ),
                indexes=(),
            ),
        )
    )
    locs = [v.location for v in PERF003().check(schema, {})]
    assert locs == ["public.t.read", "public.t.write"]


def test_perf003_bad_allowlist_type_raises_clearly() -> None:
    schema = Schema(tables=())
    with pytest.raises(TypeError, match=r"\[lint\.rules\.PERF003\]"):
        PERF003().check(schema, {"allowlist": "not_a_list"})


def test_perf003_bad_allowlist_shape_raises_clearly() -> None:
    # Two-part entries are table refs, not policy IDs.
    schema = Schema(tables=())
    with pytest.raises(TypeError, match="PERF003"):
        PERF003().check(schema, {"allowlist": ["public.t"]})


def test_perf003_message_includes_create_index_hint() -> None:
    # The fix is "add an index"; the message must show the operator
    # the exact CREATE INDEX shape to use, parameterized on the table
    # they're looking at.
    schema = Schema(
        tables=(
            _table(
                "invoices",
                schema="tenant_app",
                policies=(_policy("p"),),
                indexes=(),
            ),
        )
    )
    [v] = PERF003().check(schema, {})
    assert "CREATE INDEX ON tenant_app.invoices" in v.message


def test_perf003_handles_three_part_qualified_ref() -> None:
    # Fully-qualified `schema.table.column` — accepted iff the
    # schema and table both match the policy's relation.
    schema = Schema(
        tables=(
            _table(
                "invoices",
                schema="public",
                policies=(_policy(
                    "p",
                    using_sql=(
                        "public.invoices.tenant_id = current_setting('a')"
                    ),
                ),),
                indexes=(),
            ),
        )
    )
    [v] = PERF003().check(schema, {})
    assert "'tenant_id'" in v.message


def test_perf003_skips_three_part_cross_schema_ref() -> None:
    # `other.users.id` references a different schema — out of scope
    # for PERF003 (the index health of a foreign table is the
    # foreign table's concern).
    schema = Schema(
        tables=(
            _table(
                "invoices",
                schema="public",
                policies=(_policy(
                    "p",
                    using_sql=(
                        "other.users.id = current_setting('a')"
                    ),
                ),),
                indexes=(),
            ),
        )
    )
    assert PERF003().check(schema, {}) == []


def test_perf003_skips_two_part_ref_with_non_matching_qualifier() -> None:
    # `acct.tenant_id` — a two-part ref whose qualifier (`acct`) is
    # neither the table's bare name nor a schema. It's a cross-table
    # ref (a JOIN alias for another relation), so PERF003 leaves it
    # alone: the index health of that other table isn't this policy's
    # concern. The own column `id` IS indexed (PRIMARY-key style), so
    # nothing fires.
    schema = Schema(
        tables=(
            _table(
                "invoices",
                policies=(_policy(
                    "p",
                    using_sql="acct.tenant_id = current_setting('a')",
                ),),
                indexes=(),
            ),
        )
    )
    assert PERF003().check(schema, {}) == []


def test_perf003_skips_four_part_qualified_ref() -> None:
    # A four-part `db.schema.table.column` ref (Postgres accepts the
    # database-qualified form) doesn't match the 1/2/3-part shapes
    # PERF003 resolves, so it's skipped rather than mis-attributed to
    # the policy's own table.
    schema = Schema(
        tables=(
            _table(
                "invoices",
                policies=(_policy(
                    "p",
                    using_sql=(
                        "mydb.public.invoices.tenant_id "
                        "= current_setting('a')"
                    ),
                ),),
                indexes=(),
            ),
        )
    )
    assert PERF003().check(schema, {}) == []


def test_perf003_skips_index_with_empty_columns_tuple() -> None:
    # An index whose `columns` is an empty tuple (no key columns at
    # all — a degenerate / not-yet-populated index shape) can never be
    # a leading-column match. PERF003 skips it and still fires for the
    # unindexed policy column.
    schema = Schema(
        tables=(
            _table(
                "invoices",
                policies=(_policy("tenant_read"),),
                indexes=(_index("empty_idx", columns=()),),
            ),
        )
    )
    [v] = PERF003().check(schema, {})
    assert "'tenant_id'" in v.message
