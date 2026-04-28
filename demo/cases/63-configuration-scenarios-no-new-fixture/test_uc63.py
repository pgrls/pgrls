"""Use case 63: Configuration scenarios (no new fixture."""
from __future__ import annotations

from pathlib import Path  # noqa: F401
from click.testing import CliRunner
from pgrls.cli import main

def test_uc63_bad_allowlist_type_emits_clear_error(
    demo_db: str,
    tmp_path: Path,
) -> None:
    # `allowlist = "..."` (string instead of list) is caught
    # by the rule's `_parse_allowlist`, raises TypeError, and
    # the CLI converts that to a clean ClickException — no
    # Python traceback in the output.
    #
    # Don't compose against `base_config` here: that fixture
    # already declares `[lint.rules.SEC001]`, and adding a second
    # `[lint.rules.SEC001]` block would trip Python's tomllib
    # with a "Cannot declare table twice" error BEFORE the
    # rule's allowlist parser even runs. We'd then be exercising
    # tomllib's parser, not pgrls's. Write a fresh, single-block
    # config that exercises the path we care about.
    cfg = tmp_path / "p.toml"
    cfg.write_text(
        '[database]\nschemas = ["app"]\n'
        '[lint.rules.SEC001]\nallowlist = "app.countries"\n'
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
    # Pin the SEC001 rule's parser as the source of the error,
    # not tomllib. Without this, a regression to "compose against
    # base_config" would silently revert to testing the wrong
    # path.
    assert "SEC001" in result.output


