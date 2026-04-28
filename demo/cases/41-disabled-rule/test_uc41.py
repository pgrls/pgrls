"""Use case 41: Disabled rule — SEC007 turned off via --disable."""
from __future__ import annotations

from pathlib import Path  # noqa: F401

def test_uc41_disable_via_config_turns_off_sec007(
    demo_db: str,
    tmp_path: Path,
    lint,
    base_config,
    pgrls_toml,
) -> None:
    # uc09's app.tags fires SEC007 in the default run. Adding
    # SEC007 to `[lint].disable` skips the rule entirely;
    # nothing in the output mentions it.
    default_out = lint(config=pgrls_toml)
    assert "SEC007  app.tags\n" in default_out

    cfg = tmp_path / "p.toml"
    cfg.write_text(
        base_config
        + '[lint]\ndisable = ["SEC007"]\n'
    )
    out = lint(config=cfg)
    assert "SEC007" not in out


