"""Use case 60: Configuration scenarios (no new fixture."""
from __future__ import annotations

from pathlib import Path  # noqa: F401
from click.testing import CliRunner
from pgrls.cli import main

def test_uc60_fail_on_info_gates_exit_on_sec007(
    demo_db: str,
    tmp_path: Path,
    lint,
    base_config,
) -> None:
    # SEC007 is info-severity. fail_on='info' is the strictest
    # gate; even pure info violations cause exit=1.
    cfg = tmp_path / "p.toml"
    cfg.write_text(base_config + '[lint]\nfail_on = "info"\n')
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["lint", "--database-url", demo_db, "--config", str(cfg)],
        env={"DATABASE_URL": demo_db},
    )
    assert result.exit_code == 1
    assert "SEC007" in result.output


