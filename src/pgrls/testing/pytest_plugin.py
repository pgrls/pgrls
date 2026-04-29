"""Pytest plugin — exposes the `pgrls_db` fixture.

Auto-discovered via the `pytest11` entrypoint declared in
`pyproject.toml`. Users override `pgrls_test_database_url` in
their conftest.py to inject their own DB connection string (e.g.
from a fixture that boots a per-session testcontainer).
"""
from __future__ import annotations

import os
from collections.abc import Generator

import pytest

from pgrls.testing.client import PgrlsTestClient
from pgrls.testing.errors import PgrlsTestConfigError


def _resolve_database_url() -> str:
    """Resolve DATABASE_URL using the documented priority:

    1. `PGRLS_TEST_DATABASE_URL` env var.
    2. `DATABASE_URL` env var (fallback for projects that already
       use this name everywhere).

    Layer 1 priority — the user's conftest fixture override —
    takes precedence by virtue of pytest fixture shadowing
    (a user-defined `pgrls_test_database_url` fixture supersedes
    this plugin's default).
    """
    explicit = os.environ.get("PGRLS_TEST_DATABASE_URL")
    if explicit:
        return explicit
    fallback = os.environ.get("DATABASE_URL")
    if fallback:
        return fallback
    raise PgrlsTestConfigError(
        "pgrls.testing has no DATABASE_URL configured. Set "
        "`PGRLS_TEST_DATABASE_URL` (preferred) or `DATABASE_URL` "
        "in the environment, or define a "
        "`pgrls_test_database_url` fixture in your conftest.py "
        "that returns the connection string."
    )


@pytest.fixture
def pgrls_test_database_url() -> str:
    """Default URL fixture; override in conftest.py to inject your own."""
    return _resolve_database_url()


@pytest.fixture
def pgrls_db(
    pgrls_test_database_url: str,
) -> Generator[PgrlsTestClient, None, None]:
    """Function-scoped pgrls test client.

    Opens a connection, starts a per-test transaction, yields
    the client, rolls back at end. The transaction rollback
    drops every change the test made; the next test starts from
    schema state as the migrations left it.
    """
    with PgrlsTestClient.connect(pgrls_test_database_url) as client:
        with client.transaction():
            yield client
