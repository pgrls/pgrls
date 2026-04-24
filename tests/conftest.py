"""Pytest fixtures shared across the suite.

`pg_url` boots a single Postgres testcontainer per test session and yields its
connection string. `pg_conn` is a per-test psycopg connection that resets schemas
between tests so each test starts from a clean DB.
"""
from __future__ import annotations

from collections.abc import Callable, Generator

import psycopg
import pytest
from testcontainers.postgres import PostgresContainer


@pytest.fixture(scope="session")
def pg_url() -> Generator[str, None, None]:
    with PostgresContainer("postgres:16-alpine", username="postgres", password="postgres", dbname="postgres") as pg:
        yield pg.get_connection_url(driver=None)


@pytest.fixture
def pg_conn(pg_url: str) -> Generator[psycopg.Connection, None, None]:
    with psycopg.connect(pg_url, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute("DROP SCHEMA IF EXISTS public CASCADE")
            cur.execute("CREATE SCHEMA public")
            cur.execute("GRANT ALL ON SCHEMA public TO postgres")
            cur.execute("GRANT ALL ON SCHEMA public TO public")
        yield conn


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
