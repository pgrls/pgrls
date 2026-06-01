"""Unit tests for SEC035 — UNIQUE constraint not scoped to the discriminator."""
from __future__ import annotations

from pgrls.ast_utils import parse_expr
from pgrls.model import Column, Index, Policy, Schema, Table
from pgrls.rules.sec035 import SEC035


def _policy(using: str) -> Policy:
    return Policy(
        name="iso",
        command="ALL",
        permissive=True,
        roles=("authenticated",),
        using_sql=using,
        with_check_sql=using,
        using_ast=parse_expr(using),
        with_check_ast=parse_expr(using),
    )


def _idx(name: str, cols: tuple[str, ...], *, unique: bool, primary: bool = False) -> Index:
    return Index(
        name=name,
        access_method="btree",
        columns=cols,
        is_unique=unique,
        is_partial=False,
        is_primary=primary,
    )


_TENANT_USING = "tenant_id = (SELECT current_setting('app.tenant_id', true)::uuid)"
_COLS = (
    Column("id", "uuid", is_nullable=False),
    Column("tenant_id", "uuid", is_nullable=False),
    Column("email", "text", is_nullable=False),
    Column("ext_ref", "uuid", is_nullable=False),
)


def _table(*indexes: Index, policies=None, rls: bool = True) -> Table:
    return Table(
        schema="public",
        name="users",
        rls_enabled=rls,
        force_rls=True,
        policies=policies if policies is not None else (_policy(_TENANT_USING),),
        columns=tuple(c.name for c in _COLS),
        column_details=_COLS,
        indexes=indexes,
    )


def _run(table: Table, options=None) -> list[str]:
    return [v.location for v in SEC035().check(Schema(tables=(table,)), options or {})]


def test_flags_global_unique_excluding_discriminator() -> None:
    locs = _run(_table(_idx("users_email_key", ("email",), unique=True)))
    assert locs == ["public.users (users_email_key)"]


def test_skips_primary_key() -> None:
    assert _run(_table(_idx("users_pkey", ("id",), unique=True, primary=True))) == []


def test_skips_all_uuid_unique() -> None:
    # A UNIQUE on a uuid is globally unique by construction; leaks nothing.
    assert _run(_table(_idx("users_ext_key", ("ext_ref",), unique=True))) == []


def test_skips_composite_unique_including_discriminator() -> None:
    assert _run(_table(_idx("users_tenant_email", ("tenant_id", "email"), unique=True))) == []


def test_skips_non_unique_index() -> None:
    assert _run(_table(_idx("users_email_idx", ("email",), unique=False))) == []


def test_skips_when_no_discriminator() -> None:
    # Policy doesn't scope by a column = auth value → tenancy unknown.
    t = _table(_idx("users_email_key", ("email",), unique=True), policies=(_policy("true"),))
    assert _run(t) == []


def test_skips_when_rls_disabled_or_no_policies_or_no_indexes() -> None:
    email_key = _idx("users_email_key", ("email",), unique=True)
    assert _run(_table(email_key, rls=False)) == []
    assert _run(_table(email_key, policies=())) == []
    assert _run(_table()) == []  # no indexes


def test_allowlist_suppresses_table() -> None:
    t = _table(_idx("users_email_key", ("email",), unique=True))
    assert _run(t, {"allowlist": ["public.users"]}) == []
    assert _run(t, {"allowlist": ["users"]}) == []  # bare name too


def test_owner_model_discriminator_via_auth_uid() -> None:
    # SEC035 finds a user_id = (SELECT auth.uid()) discriminator too.
    cols = (
        Column("id", "uuid", is_nullable=False),
        Column("user_id", "uuid", is_nullable=False),
        Column("slug", "text", is_nullable=False),
    )
    t = Table(
        schema="public",
        name="docs",
        rls_enabled=True,
        force_rls=True,
        policies=(_policy("user_id = (SELECT auth.uid())"),),
        columns=("id", "user_id", "slug"),
        column_details=cols,
        indexes=(_idx("docs_slug_key", ("slug",), unique=True),),
    )
    locs = [v.location for v in SEC035().check(Schema(tables=(t,)), {})]
    assert locs == ["public.docs (docs_slug_key)"]


def test_sublink_column_not_credited_as_discriminator() -> None:
    # Regression (#26): the table's REAL discriminator is the direct
    # own-table comparison `user_id = (SELECT auth.uid())`. The policy
    # also contains a sub-select ACL whose predicate compares the own-
    # column-NAMED `email` to an auth value
    # (`… WHERE email = current_setting('app.email')`). That `email`
    # lives inside a sub-select on another table and must NOT be
    # credited as this table's discriminator. Before the fix it was,
    # so the global `UNIQUE (email)` was wrongly treated as "scoped"
    # and the genuine cross-tenant finding was silently suppressed —
    # a false negative. With the SubLink guard the discriminator set is
    # just {user_id}, and the un-scoped UNIQUE on `email` fires.
    cols = (
        Column("id", "uuid", is_nullable=False),
        Column("user_id", "uuid", is_nullable=False),
        Column("email", "text", is_nullable=False),
    )
    using = (
        "user_id = (SELECT auth.uid()) "
        "AND id IN (SELECT doc_id FROM shares "
        "WHERE email = current_setting('app.email'))"
    )
    t = Table(
        schema="public",
        name="docs",
        rls_enabled=True,
        force_rls=True,
        policies=(_policy(using),),
        columns=("id", "user_id", "email"),
        column_details=cols,
        indexes=(_idx("docs_email_key", ("email",), unique=True),),
    )
    locs = [v.location for v in SEC035().check(Schema(tables=(t,)), {})]
    assert locs == ["public.docs (docs_email_key)"]


def test_message_names_discriminator_and_fix() -> None:
    v = SEC035().check(
        Schema(tables=(_table(_idx("users_email_key", ("email",), unique=True)),)), {}
    )
    msg = v[0].message
    assert "tenant_id" in msg and "email" in msg and "composite UNIQUE" in msg
