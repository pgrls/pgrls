"""Unit tests for SEC030 — policy scopes by a nullable discriminator.

SEC030 (info) fires when a table has RLS enabled, a policy, captured
column nullability, and a nullable column that some policy compares
with `=` against an auth-context value (current_setting / auth.uid /
auth.role / auth.jwt). It's the nullable-discriminator companion to
SEC018 (wrong discriminator *type*) and SEC027 (no discriminator at
all): the scoping key is the right type, but a NULL in it silently
hides a row today and is a latent cross-tenant leak the moment a
NULL-tolerant predicate appears.
"""
from __future__ import annotations

import pytest

from pgrls.ast_utils import parse_expr
from pgrls.model import Column, Policy, Schema, Table
from pgrls.rules.sec030 import SEC030

# (name, data_type, is_nullable). Default fixture: id NOT NULL,
# tenant_id nullable, body nullable.
_DEFAULT_COLS: tuple[tuple[str, str, bool], ...] = (
    ("id", "uuid", False),
    ("tenant_id", "integer", True),
    ("body", "text", True),
)


def _policy(
    *,
    name: str = "p",
    command: str = "ALL",
    using: str | None = None,
    with_check: str | None = None,
) -> Policy:
    return Policy(
        name=name,
        command=command,
        permissive=True,
        roles=("PUBLIC",),
        using_sql=using,
        with_check_sql=with_check,
        using_ast=parse_expr(using) if using else None,
        with_check_ast=parse_expr(with_check) if with_check else None,
    )


def _table(
    *policies: Policy,
    schema: str = "public",
    name: str = "documents",
    rls_enabled: bool = True,
    cols: tuple[tuple[str, str, bool], ...] = _DEFAULT_COLS,
    with_details: bool = True,
) -> Table:
    column_details = tuple(
        Column(name=n, data_type=t, is_nullable=null) for n, t, null in cols
    )
    return Table(
        schema=schema,
        name=name,
        rls_enabled=rls_enabled,
        force_rls=True,
        policies=policies,
        columns=tuple(c.name for c in column_details),
        column_details=column_details if with_details else (),
    )


# --- firing --------------------------------------------------------------


def test_sec030_fires_on_nullable_tenant_id_vs_current_setting() -> None:
    schema = Schema(
        tables=(
            _table(
                _policy(using="tenant_id = current_setting('app.tenant')::int"),
            ),
        )
    )
    [v] = SEC030().check(schema, options={})
    assert v.rule_id == "SEC030"
    assert v.severity == "info"
    assert v.location == "public.documents"
    assert "'tenant_id'" in v.message
    assert "NOT NULL" in v.message
    assert "allowlist" in v.message


def test_sec030_fires_on_auth_uid() -> None:
    schema = Schema(
        tables=(
            _table(
                _policy(using="owner_id = auth.uid()"),
                cols=(
                    ("id", "uuid", False),
                    ("owner_id", "uuid", True),
                ),
            ),
        )
    )
    [v] = SEC030().check(schema, options={})
    assert "'owner_id'" in v.message


def test_sec030_fires_with_column_on_either_operand() -> None:
    # current_setting on the LHS, column on the RHS — symmetric.
    schema = Schema(
        tables=(
            _table(
                _policy(using="current_setting('app.tenant')::int = tenant_id"),
            ),
        )
    )
    assert len(SEC030().check(schema, options={})) == 1


def test_sec030_fires_on_with_check_predicate() -> None:
    schema = Schema(
        tables=(
            _table(
                _policy(
                    command="INSERT",
                    with_check="tenant_id = current_setting('app.tenant')::int",
                ),
            ),
        )
    )
    assert len(SEC030().check(schema, options={})) == 1


def test_sec030_fires_on_column_wrapped_in_function() -> None:
    # lower(name) = current_setting(...) still scopes by `name`.
    schema = Schema(
        tables=(
            _table(
                _policy(using="lower(slug) = current_setting('app.slug')"),
                cols=(
                    ("id", "uuid", False),
                    ("slug", "text", True),
                ),
            ),
        )
    )
    [v] = SEC030().check(schema, options={})
    assert "'slug'" in v.message


def test_sec030_lists_multiple_nullable_scoping_columns_in_one_violation() -> None:
    schema = Schema(
        tables=(
            _table(
                _policy(
                    using=(
                        "tenant_id = current_setting('app.tenant')::int "
                        "AND owner_id = auth.uid()"
                    )
                ),
                cols=(
                    ("id", "uuid", False),
                    ("tenant_id", "integer", True),
                    ("owner_id", "uuid", True),
                ),
            ),
        )
    )
    violations = SEC030().check(schema, options={})
    assert len(violations) == 1
    # Sorted, both listed.
    assert "'owner_id', 'tenant_id'" in violations[0].message


# --- not firing ----------------------------------------------------------


def test_sec030_silent_when_discriminator_is_not_null() -> None:
    schema = Schema(
        tables=(
            _table(
                _policy(using="tenant_id = current_setting('app.tenant')::int"),
                cols=(
                    ("id", "uuid", False),
                    ("tenant_id", "integer", False),  # NOT NULL
                    ("body", "text", True),
                ),
            ),
        )
    )
    assert SEC030().check(schema, options={}) == []


def test_sec030_silent_on_non_equality_operator() -> None:
    # `created_at > current_setting(...)` is a range filter, not a
    # row-identity key — a legitimate non-tenant use of current_setting.
    schema = Schema(
        tables=(
            _table(
                _policy(
                    using="created_at > current_setting('app.cutoff')::timestamptz"
                ),
                cols=(
                    ("id", "uuid", False),
                    ("created_at", "timestamptz", True),
                ),
            ),
        )
    )
    assert SEC030().check(schema, options={}) == []


def test_sec030_silent_on_array_membership_any() -> None:
    # `<auth> = ANY(tags)` is array membership (A_Expr kind
    # AEXPR_OP_ANY), a different access model from a scalar
    # discriminator — out of scope even though the operator name is `=`.
    schema = Schema(
        tables=(
            _table(
                _policy(using="current_setting('app.user') = ANY(tags)"),
                cols=(
                    ("id", "uuid", False),
                    ("tags", "text[]", True),
                ),
            ),
        )
    )
    assert SEC030().check(schema, options={}) == []


def test_sec030_silent_when_no_auth_call_on_either_side() -> None:
    # `tenant_id = 5` keys off a literal, not a per-request value —
    # not the scoping shape SEC030 targets.
    schema = Schema(
        tables=(_table(_policy(using="tenant_id = 5")),)
    )
    assert SEC030().check(schema, options={}) == []


def test_sec030_fires_on_subselect_wrapped_auth_value() -> None:
    # `tenant_id = (SELECT current_setting(...))` is the form PERF001
    # recommends (one evaluation per statement). A nullable
    # discriminator is just as dangerous here, so SEC030 must fire —
    # the column is a direct operand, the auth value is detected
    # inside the scalar sub-select.
    schema = Schema(
        tables=(
            _table(
                _policy(
                    using="tenant_id = (SELECT current_setting('app.tenant')::int)"
                ),
            ),
        )
    )
    [v] = SEC030().check(schema, options={})
    assert "'tenant_id'" in v.message


def test_sec030_silent_on_non_own_column() -> None:
    # The column operand must belong to the policy's own table. A
    # sub-select join column with the same name is not the table's.
    schema = Schema(
        tables=(
            _table(
                _policy(
                    using=(
                        "id IN (SELECT doc_id FROM acl "
                        "WHERE acl.tenant_id = current_setting('app.tenant')::int)"
                    )
                ),
            ),
        )
    )
    # `acl.tenant_id` is not documents' column; documents.tenant_id is
    # never compared to an auth value here.
    assert SEC030().check(schema, options={}) == []


def test_sec030_silent_when_rls_disabled() -> None:
    schema = Schema(
        tables=(
            _table(
                _policy(using="tenant_id = current_setting('app.tenant')::int"),
                rls_enabled=False,
            ),
        )
    )
    assert SEC030().check(schema, options={}) == []


def test_sec030_silent_when_no_policies() -> None:
    schema = Schema(tables=(_table(),))
    assert SEC030().check(schema, options={}) == []


def test_sec030_silent_without_captured_column_details() -> None:
    # A hand-built table / pre-v5 snapshot has no column_details, so
    # nullability is unknowable — skip rather than guess.
    schema = Schema(
        tables=(
            _table(
                _policy(using="tenant_id = current_setting('app.tenant')::int"),
                with_details=False,
            ),
        )
    )
    assert SEC030().check(schema, options={}) == []


# --- allowlist + config --------------------------------------------------


def test_sec030_respects_bare_name_allowlist() -> None:
    schema = Schema(
        tables=(
            _table(
                _policy(using="tenant_id = current_setting('app.tenant')::int"),
            ),
        )
    )
    assert (
        SEC030().check(schema, options={"allowlist": ["documents"]}) == []
    )


def test_sec030_respects_qualified_allowlist() -> None:
    schema = Schema(
        tables=(
            _table(
                _policy(using="tenant_id = current_setting('app.tenant')::int"),
            ),
        )
    )
    assert (
        SEC030().check(schema, options={"allowlist": ["public.documents"]})
        == []
    )


def test_sec030_honors_custom_auth_functions() -> None:
    # A project whose tenant value comes from a non-default function
    # can register it; the default set would miss it.
    schema = Schema(
        tables=(
            _table(
                _policy(using="tenant_id = app.current_tenant()"),
            ),
        )
    )
    assert SEC030().check(schema, options={}) == []
    [v] = SEC030().check(
        schema, options={"auth_functions": ["app.current_tenant"]}
    )
    assert "'tenant_id'" in v.message


def test_sec030_malformed_auth_functions_raises() -> None:
    schema = Schema(tables=(_table(),))
    with pytest.raises(TypeError):
        SEC030().check(schema, options={"auth_functions": "current_setting"})


def test_sec030_emits_one_violation_per_table() -> None:
    # Two policies scoping by the same nullable column → one finding,
    # not two.
    schema = Schema(
        tables=(
            _table(
                _policy(
                    name="read",
                    using="tenant_id = current_setting('app.tenant')::int",
                ),
                _policy(
                    name="write",
                    with_check="tenant_id = current_setting('app.tenant')::int",
                ),
            ),
        )
    )
    assert len(SEC030().check(schema, options={})) == 1
