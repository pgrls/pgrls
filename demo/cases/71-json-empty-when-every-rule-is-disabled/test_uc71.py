"""Use case 71: json empty when every rule is disabled."""
from __future__ import annotations

from pathlib import Path  # noqa: F401

def test_uc71_json_empty_when_every_rule_is_disabled(
    demo_db: str,
    tmp_path: Path,
    lint,
    lint_json,
    base_config,
    all_rule_ids,
) -> None:
    # Disable every rule via config. Even with the demo DB's many
    # violating policies, the output must serialize to an empty
    # `violations[]` and an all-zero summary — a useful sanity
    # check for downstream parsers ("does our JSON consumer handle
    # the empty case?").
    cfg = tmp_path / "p.toml"
    # `base_config` already opens a `[lint]` block (to disable
    # PERF003 demo-wide); we replace that disable list with the
    # full set rather than declaring `[lint]` twice (TOML forbids
    # duplicate sections).
    cfg.write_text(
        base_config.replace(
            'disable = ["PERF003"]',
            'disable = ' + repr(list(all_rule_ids)),
        )
    )
    parsed = lint_json(config=cfg)
    assert parsed["violations"] == []
    assert parsed["summary"] == {
        "errors": 0, "warnings": 0, "infos": 0, "total": 0,
    }


