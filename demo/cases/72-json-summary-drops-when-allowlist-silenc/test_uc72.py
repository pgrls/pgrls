"""Use case 72: json summary drops when allowlist silences a rule."""
from __future__ import annotations

from pathlib import Path  # noqa: F401

def test_uc72_json_summary_drops_when_allowlist_silences_a_rule(
    demo_db: str,
    tmp_path: Path,
    lint,
    lint_json,
    base_config,
) -> None:
    # Run twice: default config, then a config that allowlists
    # `app.public_metadata.metadata_read` (the SEC003 violation
    # from uc43). The summary `errors` count must drop by exactly
    # the number of SEC003-on-public_metadata violations the
    # allowlist silenced (one). Demonstrates the JSON shape's
    # usefulness for "what changed?" diffs in CI.
    default = lint_json()

    cfg = tmp_path / "p.toml"
    cfg.write_text(
        base_config
        + '[lint.rules.SEC003]\n'
        'allowlist = ["app.public_metadata.metadata_read"]\n'
    )
    silenced = lint_json(config=cfg)

    silenced_violations = {
        (v["rule_id"], v["location"])
        for v in default["violations"]
    } - {
        (v["rule_id"], v["location"])
        for v in silenced["violations"]
    }
    assert silenced_violations == {
        ("SEC003", "app.public_metadata.metadata_read"),
    }
    assert silenced["summary"]["errors"] == default["summary"]["errors"] - 1
    assert silenced["summary"]["total"] == default["summary"]["total"] - 1


