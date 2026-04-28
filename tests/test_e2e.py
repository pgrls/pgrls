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
    # "Clean" means: every rule (SEC001-SEC011, PERF001-PERF002,
    # HYG001-HYG002) is satisfied, not just SEC001-SEC002. The
    # table needs policies that:
    #   - are scoped to a non-PUBLIC role (SEC003)
    #   - reference an own column (SEC005)
    #   - cover write-side commands with WITH CHECK (SEC006)
    #   - don't use placeholder names (HYG002)
    #   - don't have `OR true` branches (SEC011)
    #   - include at least one RESTRICTIVE policy (SEC007 info)
    # `DROP ROLE IF EXISTS` first because pg_conn resets schemas
    # but not roles between tests.
    apply_sql(
        """
        DROP ROLE IF EXISTS pgrls_test_role;
        CREATE ROLE pgrls_test_role;
        CREATE TABLE public.t (id INT NOT NULL);
        ALTER TABLE public.t ENABLE ROW LEVEL SECURITY;
        ALTER TABLE public.t FORCE ROW LEVEL SECURITY;
        CREATE POLICY tenant_scope ON public.t
            FOR ALL
            TO pgrls_test_role
            USING (id IS NOT NULL)
            WITH CHECK (id IS NOT NULL);
        CREATE POLICY tenant_floor ON public.t
            AS RESTRICTIVE
            FOR ALL
            TO pgrls_test_role
            USING (id IS NOT NULL)
            WITH CHECK (id IS NOT NULL);
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
