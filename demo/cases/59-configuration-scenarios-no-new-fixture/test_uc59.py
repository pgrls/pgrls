"""Use case 59: Configuration scenarios (no new fixture."""
from __future__ import annotations

from pathlib import Path  # noqa: F401
from click.testing import CliRunner
from pgrls.cli import main

def test_uc59_fail_on_warning_gates_exit_on_perf001(
    demo_db: str,
    tmp_path: Path,
    lint,
    base_config,
) -> None:
    # Default fail_on='error' lets warnings through without
    # affecting exit code. Setting fail_on='warning' makes
    # PERF001 (warning severity) cause a nonzero exit. The
    # `base_config` fixture already opens a `[lint]` block (for
    # the PERF003 demo-wide disable); append `fail_on` inside
    # that same block rather than declaring `[lint]` twice (TOML
    # forbids duplicate sections).
    cfg = tmp_path / "p.toml"
    cfg.write_text(
        base_config.replace(
            'disable = ["PERF003"]',
            'disable = ["PERF003"]\nfail_on = "warning"',
        )
    )
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["lint", "--database-url", demo_db, "--config", str(cfg)],
        env={"DATABASE_URL": demo_db},
    )
    assert result.exit_code == 1, "fail_on=warning should gate on warnings"
    assert "PERF001" in result.output


