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


def test_populates_table_columns(
    pg_conn: psycopg.Connection, apply_sql
) -> None:
    # HYG001 depends on Table.columns being populated by introspection.
    # Without this, the rule silently never finds a missing column.
    apply_sql(
        """
        CREATE TABLE public.things (
            id BIGSERIAL PRIMARY KEY,
            tenant_id UUID,
            name TEXT
        );
        """
    )
    schema = introspect(pg_conn, schemas=["public"])
    things = next(t for t in schema.tables if t.name == "things")
    assert set(things.columns) == {"id", "tenant_id", "name"}


def test_columns_skips_dropped_columns(
    pg_conn: psycopg.Connection, apply_sql
) -> None:
    apply_sql(
        """
        CREATE TABLE public.things (id INT, gone INT, kept INT);
        ALTER TABLE public.things DROP COLUMN gone;
        """
    )
    schema = introspect(pg_conn, schemas=["public"])
    things = next(t for t in schema.tables if t.name == "things")
    assert "gone" not in things.columns
    assert "kept" in things.columns


def test_populates_policy_using_ast(
    pg_conn: psycopg.Connection, apply_sql
) -> None:
    # SEC004 / HYG001 walk Policy.using_ast. If introspection forgets to
    # parse it, both rules silently never fire on real databases.
    apply_sql(
        """
        CREATE TABLE public.t (id INT, owner TEXT);
        ALTER TABLE public.t ENABLE ROW LEVEL SECURITY;
        CREATE POLICY p ON public.t FOR SELECT TO PUBLIC USING (owner = 'x');
        """
    )
    schema = introspect(pg_conn, schemas=["public"])
    t = next(x for x in schema.tables if x.name == "t")
    p = t.policies[0]
    assert p.using_sql is not None
    assert p.using_ast is not None  # parsed eagerly during introspection


def test_populates_policy_with_check_ast(
    pg_conn: psycopg.Connection, apply_sql
) -> None:
    apply_sql(
        """
        CREATE TABLE public.t (id INT);
        ALTER TABLE public.t ENABLE ROW LEVEL SECURITY;
        CREATE POLICY p ON public.t FOR INSERT TO PUBLIC WITH CHECK (id > 0);
        """
    )
    schema = introspect(pg_conn, schemas=["public"])
    t = next(x for x in schema.tables if x.name == "t")
    p = t.policies[0]
    assert p.with_check_sql is not None
    assert p.with_check_ast is not None


def test_with_check_ast_is_none_when_clause_absent(
    pg_conn: psycopg.Connection, apply_sql
) -> None:
    apply_sql(
        """
        CREATE TABLE public.t (id INT);
        ALTER TABLE public.t ENABLE ROW LEVEL SECURITY;
        CREATE POLICY p ON public.t FOR SELECT TO PUBLIC USING (id > 0);
        """
    )
    schema = introspect(pg_conn, schemas=["public"])
    t = next(x for x in schema.tables if x.name == "t")
    p = t.policies[0]
    assert p.with_check_sql is None
    assert p.with_check_ast is None


def test_captures_restrictive_policy_permissive_false(
    pg_conn: psycopg.Connection, apply_sql
) -> None:
    apply_sql(
        """
        CREATE TABLE public.t (id INT);
        ALTER TABLE public.t ENABLE ROW LEVEL SECURITY;
        CREATE POLICY allow ON public.t FOR SELECT TO PUBLIC USING (true);
        CREATE POLICY restrict ON public.t AS RESTRICTIVE FOR SELECT TO PUBLIC USING (id > 0);
        """
    )
    schema = introspect(pg_conn, schemas=["public"])
    t = next(x for x in schema.tables if x.name == "t")
    by_name = {p.name: p for p in t.policies}
    assert by_name["allow"].permissive is True
    assert by_name["restrict"].permissive is False


def test_captures_multi_role_policy(
    pg_conn: psycopg.Connection, apply_sql
) -> None:
    apply_sql(
        """
        CREATE ROLE role_a NOLOGIN;
        CREATE ROLE role_b NOLOGIN;
        CREATE TABLE public.t (id INT);
        ALTER TABLE public.t ENABLE ROW LEVEL SECURITY;
        CREATE POLICY p ON public.t FOR SELECT TO role_a, role_b USING (true);
        """
    )
    schema = introspect(pg_conn, schemas=["public"])
    t = next(x for x in schema.tables if x.name == "t")
    p = t.policies[0]
    assert set(p.roles) == {"role_a", "role_b"}


def test_empty_schemas_list_returns_empty_schema(
    pg_conn: psycopg.Connection,
) -> None:
    schema = introspect(pg_conn, schemas=[])
    assert schema.tables == ()


def test_table_with_no_policies_has_empty_policies_tuple(
    pg_conn: psycopg.Connection, apply_sql
) -> None:
    apply_sql("CREATE TABLE public.bare (id INT);")
    schema = introspect(pg_conn, schemas=["public"])
    bare = next(t for t in schema.tables if t.name == "bare")
    assert bare.policies == ()


def test_columns_empty_for_table_with_only_system_columns(
    pg_conn: psycopg.Connection, apply_sql
) -> None:
    # Introspection filters to attnum > 0 (user columns) — system columns
    # like xmin/cmin must not leak through.
    apply_sql("CREATE TABLE public.empty_t ();")
    schema = introspect(pg_conn, schemas=["public"])
    t = next(x for x in schema.tables if x.name == "empty_t")
    assert t.columns == ()
