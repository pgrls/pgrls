"""Pytest fixtures shared across the suite.

`pg_url` boots a single Postgres testcontainer per test session and
yields its connection string. Set `PGRLS_TEST_DATABASE_URL` to skip
the testcontainer and reuse an existing Postgres (useful on Windows
or any environment without Docker; the schemas are still reset
between tests via `pg_conn`).

`pg_conn` is a per-test psycopg connection that resets schemas
between tests so each test starts from a clean DB.
"""
from __future__ import annotations

import os
from collections.abc import Callable, Generator

import psycopg
import pytest
from psycopg import sql
from testcontainers.postgres import PostgresContainer

pytest_plugins = ["pytester"]


@pytest.fixture(scope="session")
def pg_url() -> Generator[str, None, None]:
    existing = os.environ.get("PGRLS_TEST_DATABASE_URL")
    if existing:
        # Escape hatch for environments without Docker (Windows
        # sandboxes, CI matrices that already provide a Postgres
        # service container, etc.). Per-test schema reset still
        # runs via `pg_conn`.
        yield existing
        return
    # Image is env-overridable so a developer can verify
    # behavior against the floor (`postgres:12-alpine`) without
    # editing this file. CI matrices can iterate the supported
    # majors via the same env var.
    image = os.environ.get("PGRLS_TEST_PG_IMAGE", "postgres:16-alpine")
    with PostgresContainer(
        image,
        username="postgres",
        password="postgres",
        dbname="postgres",
    ) as pg:
        yield pg.get_connection_url(driver=None)


@pytest.fixture
def pg_conn(pg_url: str) -> Generator[psycopg.Connection, None, None]:
    with psycopg.connect(pg_url, autocommit=True) as conn:
        with conn.cursor() as cur:
            # Drop all non-system schemas (handles custom schemas created by tests).
            cur.execute(
                """
                SELECT schema_name FROM information_schema.schemata
                WHERE schema_name NOT IN ('public', 'information_schema')
                  AND schema_name NOT LIKE 'pg_%'
                """
            )
            for (schema_name,) in cur.fetchall():
                # Use psycopg.sql.Identifier to compose DDL safely.
                # Today the names come from information_schema (DB-
                # controlled), but f-stringing identifiers into DDL
                # is bad discipline regardless.
                cur.execute(
                    sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(
                        sql.Identifier(schema_name)
                    )
                )
            cur.execute("DROP SCHEMA IF EXISTS public CASCADE")
            cur.execute("CREATE SCHEMA public")
            cur.execute("GRANT ALL ON SCHEMA public TO postgres")
            cur.execute("GRANT ALL ON SCHEMA public TO public")
        yield conn


@pytest.fixture(autouse=True)
def _reset_default_registry(monkeypatch: pytest.MonkeyPatch) -> None:
    """Drop the cached registry between tests.

    `pgrls.rules._DEFAULT_REGISTRY` is a module-level lazy cache.
    No test mutates it today, but if a future test inserts /
    removes rules to the singleton (legitimate test-of-test
    pattern) the next test would inherit the corruption. Resetting
    to `None` per test is cheap (build is sub-millisecond) and
    pins the isolation contract.
    """
    monkeypatch.setattr("pgrls.rules._DEFAULT_REGISTRY", None)


@pytest.fixture
def apply_sql(pg_conn: psycopg.Connection) -> Callable[[str], None]:
    def _apply(sql: str) -> None:
        # Naive `;` split — fine for our test fixtures.
        # Constraint on fixtures: no PL/pgSQL bodies, no `;` in `--` comments.
        statements = [s.strip() for s in sql.split(";") if s.strip()]
        with pg_conn.cursor() as cur:
            for statement in statements:
                cur.execute(statement)

    return _apply
