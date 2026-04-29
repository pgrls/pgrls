"""Use case 82: pgrls diff SAFE path — RESTRICTIVE policy added.

Captures a snapshot of a table that has RLS but no policies,
creates a RESTRICTIVE tenant_isolation policy, runs `pgrls diff`,
asserts the added-RESTRICTIVE detection fires with classification
SAFE (severity=info).
"""
from __future__ import annotations

import json
from pathlib import Path

import psycopg
import pytest
from click.testing import CliRunner

from pgrls.cli import main


@pytest.fixture
def uc82_diff_runner(demo_db: str, tmp_path: Path):
    """Capture a baseline snapshot (table without policy), add a RESTRICTIVE
    policy, yield a callable to invoke `pgrls diff base.json $DATABASE_URL`."""
    base_path = tmp_path / "uc82_baseline.json"
    runner = CliRunner()

    # 1. Capture baseline snapshot of the current state (no policy on the table).
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

    # 2. Apply the "migration": add a RESTRICTIVE tenant_isolation policy.
    # Adding a RESTRICTIVE policy tightens the row set — this is a SAFE change.
    with psycopg.connect(demo_db) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                CREATE POLICY tenant_isolation ON app.uc82_invoices
                    AS RESTRICTIVE
                    FOR ALL
                    TO PUBLIC
                    USING (
                        tenant_id = current_setting(
                            'request.jwt.claims', true
                        )::jsonb->>'tenant_id'
                    )
                """
            )

    yield base_path, demo_db

    # 3. Drop the policy so subsequent demos see the table in its baseline state.
    with psycopg.connect(demo_db) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "DROP POLICY tenant_isolation ON app.uc82_invoices"
            )


def test_uc82_add_restrictive_policy_fires_safe(
    uc82_diff_runner,
) -> None:
    base_path, demo_db = uc82_diff_runner
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
    # Exit 0: only SAFE changes — adding a RESTRICTIVE policy is below the
    # default `--fail-on dangerous` threshold.
    assert result.exit_code == 0, result.output

    payload = json.loads(result.output)
    rule_ids = {v["rule_id"] for v in payload["violations"]}

    # The added-RESTRICTIVE rule should fire.
    assert "DIFF_POLICY_ADDED_RESTRICTIVE" in rule_ids, payload

    # Severity maps SAFE → info.
    severities = {
        v["severity"]
        for v in payload["violations"]
        if v["rule_id"] == "DIFF_POLICY_ADDED_RESTRICTIVE"
    }
    assert severities == {"info"}, payload

    # The inverse direction (dropped RESTRICTIVE) must not fire — sanity check.
    assert "DIFF_POLICY_DROPPED_RESTRICTIVE" not in rule_ids, payload
