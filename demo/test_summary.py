"""Whole-fixture sanity checks (not tied to one case)."""
from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from pgrls.cli import main


def test_lint_summary_shows_every_severity_class(
    lint_output: str,
) -> None:
    # Demo intentionally exercises all three severities; the
    # text formatter prints `N errors, M warnings, K infos.` as
    # the summary line. Pin that all three appear.
    assert "errors" in lint_output
    assert "warnings" in lint_output
    assert "infos" in lint_output


def test_lint_exits_nonzero_on_demo_db(
    demo_db: str, pgrls_toml: Path
) -> None:
    # `fail_on = "error"` in pgrls.toml. The fixture has plenty
    # of error-severity violations (SEC001/2/3/4/6/HYG001), so
    # the exit code must be 1.
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "lint",
            "--database-url", demo_db,
            "--config", str(pgrls_toml),
        ],
        env={"DATABASE_URL": demo_db},
    )
    assert result.exit_code == 1
