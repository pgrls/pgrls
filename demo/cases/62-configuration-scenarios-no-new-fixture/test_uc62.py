"""Use case 62: Configuration scenarios (no new fixture."""
from __future__ import annotations

from pathlib import Path  # noqa: F401

def test_uc62_multiple_disabled_rules_via_config(
    demo_db: str,
    tmp_path: Path,
    lint,
    base_config,
) -> None:
    # `[lint].disable = [..., "SEC005", "SEC008"]` — both rules
    # turn off in one config; neither appears in output. The
    # `base_config` fixture already opens a `[lint]` block (to
    # disable PERF003 demo-wide); we extend that same disable
    # list rather than declaring `[lint]` twice (TOML forbids
    # duplicate sections).
    cfg = tmp_path / "p.toml"
    cfg.write_text(
        base_config.replace(
            'disable = ["PERF003"]',
            'disable = ["PERF003", "SEC005", "SEC008"]',
        )
    )
    out = lint(config=cfg)
    assert "SEC005" not in out
    assert "SEC008" not in out
    # Other rules remain.
    assert "SEC001" in out


