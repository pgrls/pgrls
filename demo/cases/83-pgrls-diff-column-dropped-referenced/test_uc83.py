"""Use case 83: pgrls diff REQUIRES_REVIEW — column dropped while still referenced.

PostgreSQL enforces that a column referenced in a policy predicate cannot be
dropped without CASCADE, which also drops the policy itself. To isolate the
column-drop detection rule from the policy-drop detection rule, this case
uses a file-based diff: the head snapshot is crafted to retain the policy
but omit the column — representing the state a developer's migration would
produce if the column were dropped while the policy (in the snapshot
captured before the migration) still references it.

Asserts DIFF_COLUMN_DROPPED_REFERENCED fires with severity=warning and that
`--fail-on requires-review` raises exit_code to 1.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from pgrls.cli import main


@pytest.fixture
def uc83_diff_runner(demo_db: str, tmp_path: Path):
    """Capture a live baseline snapshot, then build a head snapshot that
    retains the policy AST but removes `doomed_col` from the column list.
    Yields (base_path, head_path) — both are JSON files for a file-based diff.
    No teardown required because no live migration is applied."""
    runner = CliRunner()

    # 1. Capture live baseline snapshot (table has doomed_col + policy referencing it).
    base_path = tmp_path / "uc83_baseline.json"
    result = runner.invoke(
        main,
        [
            "snapshot",
            "--database-url", demo_db,
            "--schemas", "app",
            "-o", str(base_path),
        ],
    )
    assert result.exit_code == 0, result.output

    # 2. Build head snapshot: deep-copy the baseline, remove doomed_col from
    # app.uc83_invoices while leaving the policy (and its doomed_col reference)
    # intact. This models what the diff engine would see if the column was
    # dropped while the policy predicate still referenced it.
    base_snap = json.loads(base_path.read_text(encoding="utf-8"))
    head_snap = copy.deepcopy(base_snap)
    for table in head_snap["tables"]:
        if table["schema"] == "app" and table["name"] == "uc83_invoices":
            table["columns"] = [c for c in table["columns"] if c != "doomed_col"]
            break

    head_path = tmp_path / "uc83_head.json"
    head_path.write_text(json.dumps(head_snap), encoding="utf-8")

    yield base_path, head_path


def test_uc83_column_dropped_referenced_fires_requires_review(
    uc83_diff_runner,
) -> None:
    base_path, head_path = uc83_diff_runner
    runner = CliRunner()

    # Default --fail-on dangerous: REQUIRES_REVIEW is below the threshold.
    result = runner.invoke(
        main,
        [
            "diff",
            str(base_path),
            str(head_path),
            "--format", "json",
        ],
    )
    assert result.exit_code == 0, result.output

    payload = json.loads(result.output)
    rule_ids = {v["rule_id"] for v in payload["violations"]}

    # DIFF_COLUMN_DROPPED_REFERENCED must fire.
    assert "DIFF_COLUMN_DROPPED_REFERENCED" in rule_ids, payload

    # Severity maps REQUIRES_REVIEW → warning.
    severities = {
        v["severity"]
        for v in payload["violations"]
        if v["rule_id"] == "DIFF_COLUMN_DROPPED_REFERENCED"
    }
    assert severities == {"warning"}, payload


def test_uc83_fail_on_requires_review_exits_1(
    uc83_diff_runner,
) -> None:
    base_path, head_path = uc83_diff_runner
    runner = CliRunner()

    # With --fail-on requires-review the REQUIRES_REVIEW change triggers exit 1.
    result = runner.invoke(
        main,
        [
            "diff",
            str(base_path),
            str(head_path),
            "--format", "json",
            "--fail-on", "requires-review",
        ],
    )
    assert result.exit_code == 1, result.output
