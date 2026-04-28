from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session")
def pgrls_bin() -> str:
    binary = shutil.which("pgrls")
    if binary is None:
        # `skip` is friendlier than `fail` here: a fresh checkout
        # without `pip install -e .[dev]` shouldn't crash the
        # whole runner, just the e2e tests.
        pytest.skip("`pgrls` not on PATH; install with `pip install -e \".[dev]\"`")
    return binary


def test_subprocess_known_bad_exits_nonzero(
    pg_url: str, apply_sql, pgrls_bin: str
) -> None:
    apply_sql((FIXTURES_DIR / "known_bad.sql").read_text(encoding="utf-8"))
    result = subprocess.run(
        [pgrls_bin, "lint", "--database-url", pg_url],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=30,
    )
    assert result.returncode == 1, result.stdout + result.stderr
    assert "SEC001" in result.stdout
    assert "public.users" in result.stdout


def test_subprocess_clean_db_exits_zero(
    pg_url: str, apply_sql, pgrls_bin: str
) -> None:
    apply_sql(
        """
        CREATE TABLE public.t (id INT);
        ALTER TABLE public.t ENABLE ROW LEVEL SECURITY;
        ALTER TABLE public.t FORCE ROW LEVEL SECURITY;
        """
    )
    result = subprocess.run(
        [pgrls_bin, "lint", "--database-url", pg_url],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "no issues" in result.stdout.lower()
