"""Use case 63: Configuration scenarios (no new fixture."""
from __future__ import annotations

from pathlib import Path  # noqa: F401
from click.testing import CliRunner
from pgrls.cli import main

def test_uc63_bad_allowlist_type_emits_clear_error(
    demo_db: str,
    tmp_path: Path,
    lint,
    base_config,
) -> None:
    # `allowlist = "..."` (string instead of list) is caught
    # by the rule's `_parse_allowlist`, raises TypeError, and
    # the CLI converts that to a clean ClickException — no
    # Python traceback in the output.
    cfg = tmp_path / "p.toml"
    cfg.write_text(
        base_config
        + '[lint.rules.SEC001]\nallowlist = "app.countries"\n'
    )
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["lint", "--database-url", demo_db, "--config", str(cfg)],
        env={"DATABASE_URL": demo_db},
    )
    assert result.exit_code != 0
    assert "Traceback" not in result.output
    assert "allowlist" in result.output.lower()


