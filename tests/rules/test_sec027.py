"""Unit tests for SEC027 — RLS table has a principal column no
policy scopes by.

SEC027 (info) fires when a table has RLS enabled, at least one
policy, a principal-identity column (`owner` / `owner_id` /
`user_id` by default), and no policy references that column. It's
the per-user under-scoping nudge: a table scoped by tenant but not
by user lets users within a tenant read each other's rows.
"""
from __future__ import annotations

import pytest

from pgrls.ast_utils import parse_expr
from pgrls.model import Policy, Schema, Table
from pgrls.rules.sec027 import SEC027


def _policy(
    *,
    name: str = "p",
    using: str | None = None,
    with_check: str | None = None,
) -> Policy:
    return Policy(
        name=name,
        command="ALL",
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
    columns: tuple[str, ...] = ("id", "tenant_id", "owner_id"),
) -> Table:
    return Table(
        schema=schema,
        name=name,
        rls_enabled=rls_enabled,
        force_rls=True,
        policies=policies,
        columns=columns,
    )


# --- firing --------------------------------------------------------------


def test_sec027_fires_when_owner_id_present_but_only_tenant_scoped() -> None:
    schema = Schema(
        tables=(
            _table(
                _policy(using="tenant_id = current_setting('app.tenant')::int"),
            ),
        )
    )
    [v] = SEC027().check(schema, options={})
    assert v.rule_id == "SEC027"
    assert v.severity == "info"
    assert v.location == "public.documents"
    assert "'owner_id'" in v.message
    assert "allowlist" in v.message


def test_sec027_fires_on_user_id_column() -> None:
    schema = Schema(
        tables=(
            _table(
                _policy(using="tenant_id = current_setting('app.tenant')::int"),
                columns=("id", "tenant_id", "user_id"),
            ),
        )
    )
    [v] = SEC027().check(schema, options={})
    assert v.location == "public.documents"
    assert "'user_id'" in v.message


def test_sec027_fires_on_bare_owner_column() -> None:
    schema = Schema(
        tables=(
            _table(
                _policy(using="tenant_id = current_setting('app.tenant')::int"),
                columns=("id", "tenant_id", "owner"),
            ),
        )
    )
    [v] = SEC027().check(schema, options={})
    assert v.location == "public.documents"


def test_sec027_lists_multiple_unscoped_principal_columns_sorted() -> None:
    schema = Schema(
        tables=(
            _table(
                _policy(using="tenant_id = current_setting('app.tenant')::int"),
                columns=("id", "tenant_id", "owner_id", "user_id"),
            ),
        )
    )
    [v] = SEC027().check(schema, options={})
    # Both unscoped principal columns named, alphabetically.
    assert "'owner_id', 'user_id'" in v.message


# --- silent --------------------------------------------------------------


def test_sec027_silent_when_policy_scopes_by_owner_id() -> None:
    schema = Schema(
        tables=(
            _table(
                _policy(
                    using=(
                        "tenant_id = current_setting('app.tenant')::int "
                        "AND owner_id = current_setting('app.user')::int"
                    )
                ),
            ),
        )
    )
    assert SEC027().check(schema, options={}) == []


def test_sec027_silent_when_owner_id_scoped_via_subselect() -> None:
    # Membership-table join counts as scoping — the rule under-fires
    # rather than over-fires on the legitimate ACL pattern.
    schema = Schema(
        tables=(
            _table(
                _policy(
                    using=(
                        "owner_id IN (SELECT member_id FROM public.acl "
                        "WHERE tenant_id = current_setting('app.tenant')::int)"
                    )
                ),
            ),
        )
    )
    assert SEC027().check(schema, options={}) == []


def test_sec027_silent_when_no_principal_column_present() -> None:
    # Tenant-only table with no owner/user column — nothing to nudge.
    schema = Schema(
        tables=(
            _table(
                _policy(using="tenant_id = current_setting('app.tenant')::int"),
                columns=("id", "tenant_id"),
            ),
        )
    )
    assert SEC027().check(schema, options={}) == []


def test_sec027_silent_when_rls_disabled() -> None:
    # RLS off is SEC001's surface, not SEC027's.
    schema = Schema(
        tables=(
            _table(
                _policy(using="tenant_id = current_setting('app.tenant')::int"),
                rls_enabled=False,
            ),
        )
    )
    assert SEC027().check(schema, options={}) == []


def test_sec027_silent_when_no_policies() -> None:
    # RLS on with no policy is SEC009's silent-deny-all surface.
    schema = Schema(tables=(_table(columns=("id", "tenant_id", "owner_id")),))
    assert SEC027().check(schema, options={}) == []


def test_sec027_silent_when_columns_not_captured() -> None:
    # Hand-built Table with no column list — degrade like SEC005/SEC018.
    schema = Schema(
        tables=(
            _table(
                _policy(using="tenant_id = current_setting('app.tenant')::int"),
                columns=(),
            ),
        )
    )
    assert SEC027().check(schema, options={}) == []


# --- allowlist / configuration ------------------------------------------


def test_sec027_respects_table_allowlist_qualified() -> None:
    schema = Schema(
        tables=(
            _table(
                _policy(using="tenant_id = current_setting('app.tenant')::int"),
            ),
        )
    )
    assert (
        SEC027().check(schema, options={"allowlist": ["public.documents"]})
        == []
    )


def test_sec027_respects_table_allowlist_bare() -> None:
    schema = Schema(
        tables=(
            _table(
                _policy(using="tenant_id = current_setting('app.tenant')::int"),
            ),
        )
    )
    assert (
        SEC027().check(schema, options={"allowlist": ["documents"]}) == []
    )


def test_sec027_custom_principal_columns_replaces_default() -> None:
    # Configure `created_by` (not in the default set) as a boundary;
    # the default `owner_id` is no longer flagged because the custom
    # set REPLACES the default.
    schema = Schema(
        tables=(
            _table(
                _policy(using="tenant_id = current_setting('app.tenant')::int"),
                columns=("id", "tenant_id", "owner_id", "created_by"),
            ),
        )
    )
    findings = SEC027().check(
        schema, options={"principal_columns": ["created_by"]}
    )
    assert len(findings) == 1
    assert "'created_by'" in findings[0].message
    assert "owner_id" not in findings[0].message


def test_sec027_default_set_ignores_created_by() -> None:
    # `created_by` is audit provenance, not in the default principal
    # set — a table whose only principal-ish column is `created_by`
    # does NOT fire by default.
    schema = Schema(
        tables=(
            _table(
                _policy(using="tenant_id = current_setting('app.tenant')::int"),
                columns=("id", "tenant_id", "created_by"),
            ),
        )
    )
    assert SEC027().check(schema, options={}) == []


def test_sec027_raises_on_malformed_principal_columns() -> None:
    schema = Schema(
        tables=(
            _table(
                _policy(using="tenant_id = current_setting('app.tenant')::int"),
            ),
        )
    )
    with pytest.raises(TypeError, match="principal_columns"):
        SEC027().check(schema, options={"principal_columns": "owner_id"})
    with pytest.raises(TypeError, match="principal_columns"):
        SEC027().check(schema, options={"principal_columns": [1, "owner_id"]})


def test_sec027_raises_on_malformed_allowlist() -> None:
    schema = Schema(
        tables=(
            _table(
                _policy(using="tenant_id = current_setting('app.tenant')::int"),
            ),
        )
    )
    with pytest.raises(TypeError, match="allowlist"):
        SEC027().check(schema, options={"allowlist": "public.documents"})
