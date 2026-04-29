"""Use case 84: pgrls diff BREAKING — PERMISSIVE policy dropped.

Captures a snapshot, drops a PERMISSIVE policy (which previously
granted SELECT to PUBLIC under a tenant-isolation predicate), runs
`pgrls diff`, asserts the dropped-PERMISSIVE detection fires with
classification BREAKING (severity=warning).

Rounds out the demo coverage matrix:
  case 81 → DANGEROUS (dropped RESTRICTIVE)
  case 82 → SAFE (added RESTRICTIVE)
  case 83 → REQUIRES_REVIEW (column dropped while referenced)
  case 84 → BREAKING (dropped PERMISSIVE)  ← this case

The fixture also exercises the `--fail-on breaking` threshold so
both the "default doesn't gate on BREAKING" and "explicit
--fail-on breaking does gate" paths are covered.
"""
from __future__ import annotations

import json
from pathlib import Path

import psycopg
import pytest
from click.testing import CliRunner

from pgrls.cli import main


@pytest.fixture
def uc84_diff_runner(demo_db: str, tmp_path: Path):
    """Capture baseline (with the PERMISSIVE policy in place), drop
    the policy, yield (base_path, demo_db) for the test, then
    recreate the policy in teardown."""
    base_path = tmp_path / "uc84_baseline.json"
    runner = CliRunner()

    # 1. Capture baseline snapshot of the current state (PERMISSIVE
    # policy present).
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

    # 2. Apply the "migration": drop the PERMISSIVE policy.
    # Removing a PERMISSIVE policy removes an OR-clause from the
    # row-visibility set — previously-visible rows may no longer be.
    # That's BREAKING per the v0.2 classification spec.
    with psycopg.connect(demo_db) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "DROP POLICY public_read ON app.uc84_invoices"
            )

    yield base_path, demo_db

    # 3. Recreate the policy so subsequent demos see the table in
    # its baseline state.
    with psycopg.connect(demo_db) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                CREATE POLICY public_read ON app.uc84_invoices
                    AS PERMISSIVE
                    FOR SELECT
                    TO PUBLIC
                    USING (
                        tenant_id = current_setting(
                            'request.jwt.claims', true
                        )::jsonb->>'tenant_id'
                    )
                """
            )


def test_uc84_drop_permissive_policy_fires_breaking_at_default_threshold(
    uc84_diff_runner,
) -> None:
    """Default --fail-on dangerous: BREAKING is below the threshold,
    so exit 0 even though a BREAKING change is detected."""
    base_path, demo_db = uc84_diff_runner
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "diff",
            str(base_path),
            "--database-url", demo_db,
            "--schemas", "app",
            "--format", "json",
        ],
    )
    # BREAKING is below the default `--fail-on dangerous` threshold,
    # so the exit code is 0 even though the rule fires.
    assert result.exit_code == 0, result.output

    payload = json.loads(result.output)
    rule_ids = {v["rule_id"] for v in payload["violations"]}

    # The dropped-PERMISSIVE rule should fire.
    assert "DIFF_POLICY_DROPPED_PERMISSIVE" in rule_ids, payload

    # Severity maps BREAKING → warning (not error).
    severities = {
        v["severity"]
        for v in payload["violations"]
        if v["rule_id"] == "DIFF_POLICY_DROPPED_PERMISSIVE"
    }
    assert severities == {"warning"}, payload

    # The inverse direction must not fire — sanity check.
    assert "DIFF_POLICY_ADDED_PERMISSIVE" not in rule_ids, payload


def test_uc84_drop_permissive_policy_gated_by_fail_on_breaking(
    uc84_diff_runner,
) -> None:
    """`--fail-on breaking` includes BREAKING in the threshold, so
    exit 1 — pin the threshold-walking semantics end-to-end."""
    base_path, demo_db = uc84_diff_runner
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "diff",
            str(base_path),
            "--database-url", demo_db,
            "--schemas", "app",
            "--fail-on", "breaking",
            "--format", "json",
        ],
    )
    assert result.exit_code == 1, result.output
