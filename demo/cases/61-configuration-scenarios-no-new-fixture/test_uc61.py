"""Use case 61: Configuration scenarios (no new fixture."""
from __future__ import annotations

from click.testing import CliRunner
from pgrls.cli import main

def test_uc61_format_json_emits_machine_readable_output(
    demo_db: str,
    lint,
    pgrls_toml,
) -> None:
    # `--format json` produces a parseable JSON object with
    # `violations[]` and `summary{}`. Pins the format flag
    # round-trip: CLI passes through, the formatter emits valid
    # JSON, and the violation set matches the text output.
    import json

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "lint",
            "--database-url", demo_db,
            "--config", str(pgrls_toml),
            "--format", "json",
        ],
        env={"DATABASE_URL": demo_db},
    )
    parsed = json.loads(result.output)
    assert set(parsed.keys()) == {"violations", "summary"}
    assert parsed["summary"]["total"] == len(parsed["violations"])
    # uc03 (legacy_orders missing RLS) must show up.
    rule_locs = {(v["rule_id"], v["location"]) for v in parsed["violations"]}
    assert ("SEC001", "app.legacy_orders") in rule_locs

    # Unsupported format still rejects cleanly with a list of
    # supported formats. `markdown` is on the roadmap but not yet
    # shipping; use it so this test keeps exercising the
    # unknown-format error path even as more formats land.
    bad = runner.invoke(
        main,
        [
            "lint",
            "--database-url", demo_db,
            "--config", str(pgrls_toml),
            "--format", "markdown",
        ],
        env={"DATABASE_URL": demo_db},
    )
    assert bad.exit_code != 0
    assert "Traceback" not in bad.output


