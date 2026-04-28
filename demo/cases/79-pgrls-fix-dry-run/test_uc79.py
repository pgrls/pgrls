"""Use case 79: `pgrls fix` end-to-end against the demo DB."""
from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from pgrls.cli import main


def test_uc79_fix_dry_run_emits_alter_table_for_sec002(
    demo_db: str, pgrls_toml: Path
) -> None:
    # uc04's `app.notes` has RLS but no FORCE — SEC002. `pgrls fix`
    # should emit the ALTER TABLE remediation for it without
    # actually executing the statement (default mode is dry-run).
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "fix",
            "--database-url", demo_db,
            "--config", str(pgrls_toml),
            "--rule", "SEC002",
        ],
        env={"DATABASE_URL": demo_db},
    )
    assert result.exit_code == 0, result.output
    assert (
        "ALTER TABLE app.notes FORCE ROW LEVEL SECURITY;"
        in result.output
    )
    assert "dry-run" in result.output


def test_uc79_fix_dry_run_emits_alter_policy_for_perf001(
    demo_db: str, pgrls_toml: Path
) -> None:
    # uc11's `app.messages.messages_owner` has unwrapped
    # `current_setting(...)` in USING — PERF001. The fixer emits
    # an `ALTER POLICY … USING (... (SELECT current_setting(...))
    # ...)` statement.
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "fix",
            "--database-url", demo_db,
            "--config", str(pgrls_toml),
            "--rule", "PERF001",
        ],
        env={"DATABASE_URL": demo_db},
    )
    assert result.exit_code == 0, result.output
    assert (
        "ALTER POLICY messages_owner ON app.messages"
        in result.output
    )
    # The rewritten USING contains the wrapped call. pglast
    # uppercases boolean literals so check case-insensitively.
    out = result.output.lower()
    assert "(select current_setting(" in out


def test_uc79_fix_rule_filter_to_sec002_excludes_perf001(
    demo_db: str, pgrls_toml: Path
) -> None:
    # `--rule SEC002` should suppress PERF001 fixes entirely.
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "fix",
            "--database-url", demo_db,
            "--config", str(pgrls_toml),
            "--rule", "SEC002",
        ],
        env={"DATABASE_URL": demo_db},
    )
    assert result.exit_code == 0
    # Should not see any PERF001 ALTER POLICY lines.
    assert "[PERF001]" not in result.output
    assert "ALTER POLICY" not in result.output
