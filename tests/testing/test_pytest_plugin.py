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
