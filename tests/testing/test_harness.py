"""Smoke tests for the tests/testing/ harness fixtures."""
from __future__ import annotations

import psycopg


def test_rls_widgets_table_exists(testing_pg_conn: psycopg.Connection) -> None:
    with testing_pg_conn.cursor() as cur:
        cur.execute(
            "SELECT 1 FROM pg_catalog.pg_class "
            "WHERE relname = 'rls_widgets' AND relrowsecurity = true"
        )
        assert cur.fetchone() is not None


def test_pgrls_test_actor_role_exists(testing_pg_conn: psycopg.Connection) -> None:
    with testing_pg_conn.cursor() as cur:
        cur.execute(
            "SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'pgrls_test_actor'"
        )
        assert cur.fetchone() is not None


def test_widget_owner_policy_exists(testing_pg_conn: psycopg.Connection) -> None:
    with testing_pg_conn.cursor() as cur:
        cur.execute(
            "SELECT 1 FROM pg_catalog.pg_policy "
            "WHERE polname = 'widget_owner'"
        )
        assert cur.fetchone() is not None
