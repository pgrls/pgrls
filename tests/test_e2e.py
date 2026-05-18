from __future__ import annotations

import subprocess
import sys
from pathlib import Path

FIXTURES_DIR = Path(__file__).parent / "fixtures"

# Invoke the CLI via `python -m pgrls` against the test runner's
# own interpreter, not whatever `pgrls` happens to be on $PATH.
# Guarantees the subprocess sees the same `site-packages` (and
# therefore the same `pgrls` package) that the test process
# imported, so the e2e tests work in any env — venv, uv,
# tox, CI — without needing a separately-installed console script.
_PGRLS_CMD: tuple[str, ...] = (sys.executable, "-m", "pgrls")


def test_python_m_pgrls_help_works() -> None:
    # Pin that `python -m pgrls` is a supported entry point. The
    # `pgrls/__main__.py` module exists for callers that need to
    # bypass $PATH lookup of the console script (this test, the
    # other e2e tests, anyone running pgrls inside a venv that
    # didn't install console scripts onto $PATH).
    result = subprocess.run(
        [*_PGRLS_CMD, "--help"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=15,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    # Subcommands surface in the top-level --help: lint/fix/snapshot/diff.
    for sub in ("lint", "fix", "snapshot", "diff"):
        assert sub in result.stdout, f"{sub!r} missing from --help"


def test_python_m_pgrls_version_matches_package() -> None:
    # `python -m pgrls --version` must report the same string the
    # package's `__version__` exposes — pins the entry-point
    # contract in case a future refactor mounts a different `main`
    # callable behind `python -m pgrls`.
    from pgrls import __version__

    result = subprocess.run(
        [*_PGRLS_CMD, "--version"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=15,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert __version__ in result.stdout


def test_subprocess_known_bad_exits_nonzero(
    pg_url: str, apply_sql
) -> None:
    apply_sql((FIXTURES_DIR / "known_bad.sql").read_text(encoding="utf-8"))
    result = subprocess.run(
        [*_PGRLS_CMD, "lint", "--database-url", pg_url],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=30,
    )
    assert result.returncode == 1, result.stdout + result.stderr
    assert "SEC001" in result.stdout
    assert "public.users" in result.stdout


def test_subprocess_clean_db_exits_zero(
    pg_url: str, apply_sql
) -> None:
    # "Clean" means: every rule (SEC001-SEC021, PERF001-PERF003,
    # HYG001-HYG002, VIEW001-VIEW004) is satisfied, not just
    # SEC001-SEC002. SEC014, SEC015, and SEC017 are exercised by
    # absence — the fixture creates no SECURITY DEFINER functions
    # and no LEAKPROOF functions, so none of them has anything to
    # flag. SEC016 likewise: the fixture's `pgrls_test_role` is
    # created without BYPASSRLS, so there is no non-superuser
    # BYPASSRLS role to flag. SEC019 too: the policies use no
    # current_setting() call at all, so its one-arg form can't
    # appear. The table needs policies that:
    #   - are scoped to a non-PUBLIC role (SEC003)
    #   - reference an own column (SEC005)
    #   - cover write-side commands with WITH CHECK (SEC006)
    #   - don't use placeholder names (HYG002)
    #   - don't have `OR true` branches (SEC011)
    #   - include at least one RESTRICTIVE policy (SEC007 info)
    #   - don't compare a column against current_user/session_user
    #     (SEC018)
    #   - reference indexed columns (PERF003) — PRIMARY KEY on
    #     `id` creates the implicit B-tree the policy uses
    # `DROP ROLE IF EXISTS` first because pg_conn resets schemas
    # but not roles between tests.
    apply_sql(
        """
        DROP ROLE IF EXISTS pgrls_test_role;
        CREATE ROLE pgrls_test_role;
        CREATE TABLE public.t (id INT PRIMARY KEY);
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
        [*_PGRLS_CMD, "lint", "--database-url", pg_url],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "no issues" in result.stdout.lower()
