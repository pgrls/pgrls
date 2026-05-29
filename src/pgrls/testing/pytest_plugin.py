"""Pytest plugin — exposes the `pgrls_db` fixture.

Auto-discovered via the `pytest11` entrypoint declared in
`pyproject.toml`. Users override `pgrls_test_database_url` in
their conftest.py to inject their own DB connection string (e.g.
from a fixture that boots a per-session testcontainer).
"""
from __future__ import annotations

import os
import sys
from collections.abc import Generator
from datetime import datetime, timezone

import pytest

from pgrls.testing.client import PgrlsTestClient
from pgrls.testing.errors import PgrlsTestConfigError

_DEFAULT_COVERAGE_PATH = ".pgrls-coverage.json"


class _CoverageAccumulator:
    """Collects the exercised `(schema, relation, role, command)` tuples
    the test clients record, deduped, across the whole session."""

    def __init__(self) -> None:
        self.exercised: set[object] = set()

    def record(self, tuples: object) -> None:
        self.exercised.update(tuples)  # type: ignore[arg-type]


def pytest_addoption(parser: pytest.Parser) -> None:
    """Register the coverage ini options.

    Coverage is on by default (the artifact is written on every run);
    set `pgrls_coverage = false` in pytest config — or `PGRLS_COVERAGE=off`
    in the environment — to disable it.
    """
    parser.addini(
        "pgrls_coverage",
        help="Write an RLS test-coverage artifact on session finish.",
        type="bool",
        default=True,
    )
    parser.addini(
        "pgrls_coverage_path",
        help="Path for the RLS coverage artifact.",
        default=_DEFAULT_COVERAGE_PATH,
    )


def _coverage_enabled(config: pytest.Config) -> bool:
    if os.environ.get("PGRLS_COVERAGE", "").strip().lower() in {
        "off",
        "0",
        "false",
        "no",
    }:
        return False
    return bool(config.getini("pgrls_coverage"))


def _coverage_path(config: pytest.Config) -> str:
    return (
        os.environ.get("PGRLS_COVERAGE_PATH")
        or config.getini("pgrls_coverage_path")
        or _DEFAULT_COVERAGE_PATH
    )


def pytest_configure(config: pytest.Config) -> None:
    if _coverage_enabled(config):
        # Stash the accumulator on config so the function-scoped fixture
        # can push into it and `pytest_sessionfinish` can read it.
        config._pgrls_coverage = _CoverageAccumulator()  # type: ignore[attr-defined]


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    accumulator = getattr(session.config, "_pgrls_coverage", None)
    if accumulator is None or not accumulator.exercised:
        return
    from pgrls.coverage import write_artifact

    path = _coverage_path(session.config)
    try:
        write_artifact(
            path,
            accumulator.exercised,
            generated_at=datetime.now(timezone.utc),
        )
    except OSError as exc:
        # Coverage is advisory — a write failure must not fail the run
        # (tests have already completed). Warn and move on.
        print(
            f"pgrls: warning: could not write coverage artifact {path!r}: {exc}",
            file=sys.stderr,
        )


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
    request: pytest.FixtureRequest,
    pgrls_test_database_url: str,
) -> Generator[PgrlsTestClient, None, None]:
    """Function-scoped pgrls test client.

    Opens a connection, starts a per-test transaction, yields
    the client, rolls back at end. The transaction rollback
    drops every change the test made; the next test starts from
    schema state as the migrations left it.

    When coverage is enabled, the client's capture sink points at the
    session accumulator so every query this test runs is recorded.
    """
    with PgrlsTestClient.connect(pgrls_test_database_url) as client:
        accumulator = getattr(request.config, "_pgrls_coverage", None)
        if accumulator is not None:
            client._coverage_sink = accumulator.record
        with client.transaction():
            yield client
