"""Code-first RLS testing for Postgres.

Public API:

* `PgrlsTestClient` — Layer 2 client. Pure psycopg, no pytest
  dependency. Wraps a Postgres connection with role-switching,
  parameterized SQL execution, a light seed helper, and five
  RLS-specific assertion helpers.
* `PgrlsTestError`, `PgrlsTestAssertionError`,
  `PgrlsTestConfigError` — exception hierarchy.
* `PROTOCOL_VERSION` — the version of the cross-language Layer 1
  contract this client implements. See
  `docs/pgrls-test-protocol.md`.
* `pgrls_db` — pytest fixture, auto-discovered via the pytest11
  entrypoint declared in pyproject.toml. Not imported here
  because pytest plugin modules import on plugin discovery; pull
  it from `pgrls.testing.pytest_plugin` if you need direct
  access.

The cross-language Layer 1 contract this client implements lives
at `docs/pgrls-test-protocol.md`. TS / Go ports follow the same
contract; this Python implementation is the reference.
"""
from __future__ import annotations

from pgrls.testing.client import PgrlsTestClient
from pgrls.testing.errors import (
    PgrlsTestAssertionError,
    PgrlsTestConfigError,
    PgrlsTestError,
)

__all__ = [
    "PROTOCOL_VERSION",
    "PgrlsTestAssertionError",
    "PgrlsTestClient",
    "PgrlsTestConfigError",
    "PgrlsTestError",
]

PROTOCOL_VERSION = 1
