from __future__ import annotations

from pathlib import Path

import psycopg
import pytest

from pgrls.introspect import introspect
from pgrls.model import Schema

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_returns_empty_schema_when_no_tables(pg_conn: psycopg.Connection) -> None:
    schema = introspect(pg_conn, schemas=["public"])
    assert isinstance(schema, Schema)
    assert schema.tables == ()


def test_finds_tables_with_rls_state(
    pg_conn: psycopg.Connection, apply_sql
) -> None:
    apply_sql((FIXTURES_DIR / "known_bad.sql").read_text())
    schema = introspect(pg_conn, schemas=["public"])
    by_name = {t.qualified_name: t for t in schema.tables}
    assert set(by_name) == {"public.users", "public.orders"}

    users = by_name["public.users"]
    assert users.rls_enabled is False
    assert users.force_rls is False
    assert users.policies == ()

    orders = by_name["public.orders"]
    assert orders.rls_enabled is True
    assert orders.force_rls is True
    assert len(orders.policies) == 1
    p = orders.policies[0]
    assert p.name == "orders_owner"
    assert p.command == "SELECT"
    assert p.permissive is True
    assert p.roles == ("PUBLIC",)
    assert p.using_sql is not None and "current_setting" in p.using_sql
    assert p.with_check_sql is None


def test_filters_by_schema(pg_conn: psycopg.Connection, apply_sql) -> None:
    apply_sql(
        """
        CREATE SCHEMA tenant;
        CREATE TABLE public.public_t (id INT);
        CREATE TABLE tenant.tenant_t (id INT);
        """
    )
    public_only = introspect(pg_conn, schemas=["public"])
    assert {t.qualified_name for t in public_only.tables} == {"public.public_t"}

    both = introspect(pg_conn, schemas=["public", "tenant"])
    assert {t.qualified_name for t in both.tables} == {
        "public.public_t",
        "tenant.tenant_t",
    }


def test_skips_views_and_system_tables(
    pg_conn: psycopg.Connection, apply_sql
) -> None:
    apply_sql(
        """
        CREATE TABLE public.real (id INT);
        CREATE VIEW public.view_real AS SELECT * FROM public.real;
        """
    )
    schema = introspect(pg_conn, schemas=["public"])
    names = {t.qualified_name for t in schema.tables}
    assert names == {"public.real"}


def test_unknown_schema_raises(pg_conn: psycopg.Connection) -> None:
    with pytest.raises(ValueError, match="does_not_exist"):
        introspect(pg_conn, schemas=["does_not_exist"])


def test_with_check_and_multi_policy(
    pg_conn: psycopg.Connection, apply_sql
) -> None:
    apply_sql(
        """
        CREATE TABLE public.docs (id INT, owner TEXT);
        ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;
        CREATE POLICY docs_insert ON public.docs FOR INSERT TO PUBLIC WITH CHECK (true);
        CREATE POLICY docs_select ON public.docs FOR SELECT TO PUBLIC USING (true);
        CREATE POLICY docs_update ON public.docs FOR UPDATE TO PUBLIC USING (owner = current_setting('app.user', true)) WITH CHECK (owner = current_setting('app.user', true));
        """
    )
    schema = introspect(pg_conn, schemas=["public"])
    docs = next(t for t in schema.tables if t.name == "docs")
    assert len(docs.policies) == 3

    by_command = {p.command: p for p in docs.policies}
    assert set(by_command) == {"INSERT", "SELECT", "UPDATE"}

    insert = by_command["INSERT"]
    assert insert.with_check_sql is not None
    assert insert.using_sql is None
    assert insert.roles == ("PUBLIC",)

    select = by_command["SELECT"]
    assert select.using_sql is not None
    assert select.with_check_sql is None

    update = by_command["UPDATE"]
    assert update.using_sql is not None
    assert update.with_check_sql is not None
