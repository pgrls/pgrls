"""Demo tests: run pgrls against the 15-use-case fixture.

Each test maps to one use case in `setup.sql` and asserts the rule
that case demonstrates either fires (for violation cases) or stays
silent (for clean cases). Read top-to-bottom as a guided tour of
what pgrls catches.

Run modes:
- `pytest demo/test_demo.py` (default): spin up a fresh Postgres via
  testcontainers and apply `setup.sql`.
- `DATABASE_URL=... pytest demo/test_demo.py`: apply `setup.sql` to
  an existing DB (e.g. the one started by `demo/run.sh`).
"""
from __future__ import annotations

import os
from collections.abc import Generator
from pathlib import Path

import psycopg
import pytest
from click.testing import CliRunner
from testcontainers.postgres import PostgresContainer

from pgrls.cli import main

DEMO_DIR = Path(__file__).parent
SETUP_SQL = DEMO_DIR / "setup.sql"
PGRLS_TOML = DEMO_DIR / "pgrls.toml"

_ALL_RULE_IDS = (
    "SEC001",
    "SEC002",
    "SEC003",
    "SEC004",
    "SEC005",
    "SEC006",
    "SEC007",
    "SEC008",
    "PERF001",
    "HYG001",
)


def _apply_setup(url: str) -> None:
    # psycopg3 / libpq supports multi-statement execute when there
    # are no parameters. This avoids hand-rolling a SQL splitter
    # that has to know about `--` line comments, `/* */` block
    # comments, single-quoted strings, and double-quoted identifiers.
    sql = SETUP_SQL.read_text()
    with psycopg.connect(url, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(sql)


@pytest.fixture(scope="module")
def demo_db() -> Generator[str, None, None]:
    """A connection URL with the demo fixture applied."""
    existing = os.environ.get("DATABASE_URL")
    if existing:
        _apply_setup(existing)
        yield existing
        return
    with PostgresContainer(
        "postgres:16-alpine",
        username="demo",
        password="demo",
        dbname="demo",
    ) as pg:
        url = pg.get_connection_url(driver=None)
        _apply_setup(url)
        yield url


@pytest.fixture(scope="module")
def lint_output(demo_db: str) -> str:
    runner = CliRunner()
    # The demo's pgrls.toml uses `database.url = "$DATABASE_URL"` to
    # show the env-var-expansion path. Set DATABASE_URL on the
    # invocation so config loading succeeds; --database-url still
    # overrides for the actual connection.
    result = runner.invoke(
        main,
        [
            "lint",
            "--database-url",
            demo_db,
            "--config",
            str(PGRLS_TOML),
        ],
        env={"DATABASE_URL": demo_db},
    )
    return result.output


# ============================================================
# Use case 01 — clean tenant table (no rule fires)
# ============================================================

def test_uc01_clean_tenant_table_passes_all_rules(
    lint_output: str,
) -> None:
    # Substring "X  app.documents" matches both the table-level
    # location and the policy-level location (`app.documents.tenant_isolation`).
    # Either kind of fire is unacceptable for the canonical clean
    # example.
    for rule_id in _ALL_RULE_IDS:
        line = f"{rule_id}  app.documents"
        assert line not in lint_output, (
            f"{rule_id} unexpectedly fired on app.documents:\n"
            f"{lint_output}"
        )


# ============================================================
# Use case 02 — reference table allowlisted
# ============================================================

def test_uc02_reference_table_silenced_by_allowlist(
    lint_output: str,
) -> None:
    # `app.countries` has no RLS but is in the SEC001 allowlist.
    assert "SEC001  app.countries" not in lint_output


# ============================================================
# Use cases 03-12 — one rule per case
# ============================================================

def test_uc03_missing_rls_fires_sec001(lint_output: str) -> None:
    assert "SEC001  app.legacy_orders\n" in lint_output


def test_uc04_missing_force_fires_sec002(lint_output: str) -> None:
    assert "SEC002  app.notes\n" in lint_output


def test_uc05_permissive_public_fires_sec003(lint_output: str) -> None:
    assert "SEC003  app.posts.everyone_reads\n" in lint_output


def test_uc06_inverted_auth_fires_sec004(lint_output: str) -> None:
    assert "SEC004  app.accounts.allow_unset_user\n" in lint_output


def test_uc07_session_state_only_fires_sec005(lint_output: str) -> None:
    assert "SEC005  app.singletons.admin_only\n" in lint_output


def test_uc08_update_without_with_check_fires_sec006(
    lint_output: str,
) -> None:
    assert "SEC006  app.invoices.update_without_check\n" in lint_output


def test_uc09_all_permissive_fires_sec007(lint_output: str) -> None:
    assert "SEC007  app.tags\n" in lint_output


def test_uc10_using_true_fires_sec008(lint_output: str) -> None:
    assert "SEC008  app.feature_flags.public_flags\n" in lint_output


def test_uc11_unwrapped_auth_fires_perf001(lint_output: str) -> None:
    assert "PERF001  app.messages.messages_owner\n" in lint_output


def test_uc12_orphaned_column_fires_hyg001(lint_output: str) -> None:
    assert "HYG001  app.comments.archived_filter\n" in lint_output


# ============================================================
# Use cases 13-15 — partition-aware paths
# ============================================================

def test_uc13_partitioned_parent_with_rls_keeps_all_silent(
    lint_output: str,
) -> None:
    # Parent has RLS; SEC001 walks each child's chain and finds
    # the RLS-enabled root, suppressing the child violation.
    # Neither parent nor any child should fire.
    for table in ("app.events", "app.events_2025", "app.events_2026"):
        assert f"SEC001  {table}\n" not in lint_output, (
            f"SEC001 unexpectedly fired on {table}"
        )


def test_uc14_cross_schema_partition_emits_unscoped_message(
    lint_output: str,
) -> None:
    # Parent in `private` (not in pgrls.toml `schemas`); child in
    # `app`. SEC001 fires on the child with the differentiated
    # "leaves the scanned schemas" message.
    assert "SEC001  app.audit_log_2026\n" in lint_output
    assert "leaves the scanned schemas" in lint_output


def test_uc15_visible_root_partition_message_names_the_root(
    lint_output: str,
) -> None:
    # Both parent and child are in scope and lack RLS. Parent
    # gets the classic message; child gets the visible-root
    # variant naming the parent.
    assert "SEC001  app.bare_metrics\n" in lint_output
    assert "SEC001  app.bare_metrics_2026\n" in lint_output
    assert "is a partition of app.bare_metrics" in lint_output


# ============================================================
# Tour-level sanity checks
# ============================================================

def test_lint_summary_shows_every_severity_class(
    lint_output: str,
) -> None:
    # Demo intentionally exercises all three severities; the
    # text formatter prints `N errors, M warnings, K infos.`
    # as the summary line.
    assert "errors" in lint_output
    assert "warnings" in lint_output
    assert "infos" in lint_output


def test_lint_exits_nonzero_on_demo_db(demo_db: str) -> None:
    # `fail_on = "error"` in pgrls.toml. The fixture has plenty
    # of error-severity violations (SEC001/2/3/4/6/HYG001), so
    # the exit code must be 1.
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "lint",
            "--database-url",
            demo_db,
            "--config",
            str(PGRLS_TOML),
        ],
        env={"DATABASE_URL": demo_db},
    )
    assert result.exit_code == 1
