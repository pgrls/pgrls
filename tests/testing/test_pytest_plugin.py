"""Unit tests for pgrls.testing.pytest_plugin.

We test the plugin's wiring two ways:

* directly — call the plugin's fixture functions with a
  fabricated request to verify their resolution logic;
* via pytest's pytester — run a synthetic pytest session and
  verify the fixture is auto-discovered through the pytest11
  entrypoint.
"""
from __future__ import annotations

import pytest

from pgrls.testing.errors import PgrlsTestConfigError


def test_pgrls_test_database_url_uses_explicit_env_var(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from pgrls.testing.pytest_plugin import _resolve_database_url

    monkeypatch.setenv(
        "PGRLS_TEST_DATABASE_URL",
        "postgresql://from-pgrls-env",
    )
    monkeypatch.setenv(
        "DATABASE_URL", "postgresql://from-fallback"
    )
    assert (
        _resolve_database_url()
        == "postgresql://from-pgrls-env"
    )


def test_pgrls_test_database_url_falls_back_to_database_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from pgrls.testing.pytest_plugin import _resolve_database_url

    monkeypatch.delenv("PGRLS_TEST_DATABASE_URL", raising=False)
    monkeypatch.setenv("DATABASE_URL", "postgresql://fallback")
    assert _resolve_database_url() == "postgresql://fallback"


def test_pgrls_test_database_url_raises_when_unconfigured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from pgrls.testing.pytest_plugin import _resolve_database_url

    monkeypatch.delenv("PGRLS_TEST_DATABASE_URL", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    with pytest.raises(PgrlsTestConfigError) as exc_info:
        _resolve_database_url()
    msg = str(exc_info.value)
    # Pin all three configuration paths so a regression dropping
    # any one of them surfaces here.
    assert "PGRLS_TEST_DATABASE_URL" in msg
    assert "DATABASE_URL" in msg
    assert "pgrls_test_database_url" in msg


def test_pgrls_test_database_url_fixture_returns_resolved_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The `pgrls_test_database_url` fixture's body simply returns
    # `_resolve_database_url()`. Call the undecorated function directly
    # (the resolution logic is unit-tested above; this pins the fixture
    # wrapper actually delegates to it).
    from pgrls.testing.pytest_plugin import pgrls_test_database_url

    monkeypatch.setenv(
        "PGRLS_TEST_DATABASE_URL", "postgresql://from-fixture"
    )
    assert (
        pgrls_test_database_url.__wrapped__()
        == "postgresql://from-fixture"
    )


def test_pgrls_db_fixture_yields_working_client(pg_url: str) -> None:
    # Drive the `pgrls_db` fixture's generator body in-process against
    # the session testcontainer: it opens a connection, starts a
    # transaction, yields a usable PgrlsTestClient, and rolls back on
    # exit. The synthetic-session test below also exercises this via
    # the pytest11 entrypoint, but that runs in a subprocess (so the
    # fixture body isn't seen by this process). Driving the generator
    # here pins the open/transaction/yield/rollback wiring directly.
    from pgrls.testing.client import PgrlsTestClient
    from pgrls.testing.pytest_plugin import pgrls_db

    # The fixture takes `request` (for the coverage accumulator) then the
    # DB-url fixture. Pass a stand-in request whose config has no
    # accumulator, so capture stays off for this direct-drive test.
    from types import SimpleNamespace

    fake_request = SimpleNamespace(config=SimpleNamespace())
    gen = pgrls_db.__wrapped__(fake_request, pg_url)
    client = next(gen)
    try:
        assert isinstance(client, PgrlsTestClient)
        assert client.fetchall("SELECT 1 AS x") == [{"x": 1}]
    finally:
        # Exhaust the generator so the transaction rollback + connection
        # close (the post-yield teardown) runs.
        with pytest.raises(StopIteration):
            next(gen)


def test_sessionfinish_swallows_artifact_write_oserror(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # R11 #10: a coverage-artifact write failure (read-only dir, ENOSPC,
    # permission denied) must NEVER fail the user's otherwise-green test
    # run — tests have already completed. pytest_sessionfinish catches
    # OSError, warns to stderr, and returns normally.
    from types import SimpleNamespace

    import pgrls.coverage as cov
    from pgrls.testing import pytest_plugin

    def _boom(*args: object, **kwargs: object) -> None:
        raise OSError("read-only file system")

    monkeypatch.setattr(cov, "write_artifact", _boom)
    monkeypatch.setenv("PGRLS_COVERAGE_PATH", "/nonexistent/dir/cov.json")

    session = SimpleNamespace(
        config=SimpleNamespace(
            _pgrls_coverage=SimpleNamespace(exercised={("public", "t")})
        )
    )
    # Must not raise.
    pytest_plugin.pytest_sessionfinish(session, exitstatus=0)  # type: ignore[arg-type]

    err = capsys.readouterr().err
    assert "could not write coverage artifact" in err


def test_plugin_registered_via_entrypoint() -> None:
    # Reading the installed distribution metadata is the most
    # reliable check that the pytest11 entrypoint is wired —
    # short of running pytest-in-pytest with --trace-config.
    import importlib.metadata

    eps = importlib.metadata.entry_points(group="pytest11")
    names = {ep.name for ep in eps}
    assert "pgrls" in names, (
        "Expected `pgrls` in the pytest11 entrypoint group; "
        f"got {sorted(names)}"
    )


def test_pgrls_db_fixture_in_synthetic_pytest_session(
    pytester: pytest.Pytester,
    pg_url: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # End-to-end: spin up a synthetic pytest session, write a
    # tiny test that uses the `pgrls_db` fixture, run pytest,
    # assert it passed. monkeypatch.setenv auto-cleans up
    # afterward so the env mutation doesn't leak.
    pytester.makepyfile(
        """
        def test_uses_pgrls_db(pgrls_db):
            rows = pgrls_db.fetchall("SELECT 1 AS x")
            assert rows == [{"x": 1}]
        """
    )
    monkeypatch.setenv("PGRLS_TEST_DATABASE_URL", pg_url)
    result = pytester.runpytest_subprocess("-v")
    result.assert_outcomes(passed=1)


def test_synthetic_session_writes_coverage_artifact(
    pytester: pytest.Pytester,
    pg_url: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The plugin writes .pgrls-coverage.json on session finish, recording
    # the relations each test queried. A query against pg_class gives a
    # real relation to capture.
    import json

    pytester.makepyfile(
        """
        def test_q(pgrls_db):
            pgrls_db.fetchall("SELECT relname FROM pg_class LIMIT 1")
        """
    )
    monkeypatch.setenv("PGRLS_TEST_DATABASE_URL", pg_url)
    result = pytester.runpytest_subprocess("-v")
    result.assert_outcomes(passed=1)

    artifact = pytester.path / ".pgrls-coverage.json"
    assert artifact.exists(), "coverage artifact should be written on session finish"
    data = json.loads(artifact.read_text())
    assert data["pgrls_coverage_version"] == 1
    relations = {row["relation"] for row in data["exercised"]}
    assert "pg_class" in relations


def test_coverage_artifact_opt_out_via_env(
    pytester: pytest.Pytester,
    pg_url: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # PGRLS_COVERAGE=off suppresses the artifact even though a query ran.
    pytester.makepyfile(
        """
        def test_q(pgrls_db):
            pgrls_db.fetchall("SELECT relname FROM pg_class LIMIT 1")
        """
    )
    monkeypatch.setenv("PGRLS_TEST_DATABASE_URL", pg_url)
    monkeypatch.setenv("PGRLS_COVERAGE", "off")
    result = pytester.runpytest_subprocess("-v")
    result.assert_outcomes(passed=1)
    assert not (pytester.path / ".pgrls-coverage.json").exists()
