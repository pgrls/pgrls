"""Use case 62: Configuration scenarios (no new fixture."""
from __future__ import annotations

from pathlib import Path  # noqa: F401

def test_uc62_multiple_disabled_rules_via_config(
    demo_db: str,
    tmp_path: Path,
    lint,
    base_config,
) -> None:
    # `[lint].disable = ["SEC005", "SEC008"]` — both rules
    # turn off in one config; neither appears in output.
    cfg = tmp_path / "p.toml"
    cfg.write_text(
        base_config
        + '[lint]\ndisable = ["SEC005", "SEC008"]\n'
    )
    out = lint(config=cfg)
    assert "SEC005" not in out
    assert "SEC008" not in out
    # Other rules remain.
    assert "SEC001" in out


