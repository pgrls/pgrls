"""Use case 81: pgrls diff end-to-end smoke.

Captures a snapshot, applies a "migration" (drops the RESTRICTIVE
tenant_isolation policy), runs `pgrls diff`, asserts the dropped-
policy detection fires DANGEROUS classification.
"""
from __future__ import annotations

import json
from pathlib import Path

import psycopg
import pytest
from click.testing import CliRunner

from pgrls.cli import main


@pytest.fixture
def uc81_diff_runner(demo_db: str, tmp_path: Path):
    """Capture a baseline snapshot, drop the RESTRICTIVE policy,
    yield a callable to invoke `pgrls diff base.json $DATABASE_URL`."""
    base_path = tmp_path / "uc81_baseline.json"
    runner = CliRunner()

    # 1. Capture baseline snapshot of the current state (with the
    # RESTRICTIVE policy in place).
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

    # 2. Apply the "migration": drop the RESTRICTIVE policy. This is
    # the dangerous change `pgrls diff` should flag.
    with psycopg.connect(demo_db) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "DROP POLICY tenant_isolation ON app.uc81_invoices"
            )

    yield base_path, demo_db

    # 3. Recreate the policy so subsequent demos see the table in
    # its baseline state.
    with psycopg.connect(demo_db) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                CREATE POLICY tenant_isolation ON app.uc81_invoices
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


def test_uc81_drop_restrictive_policy_fires_dangerous(
    uc81_diff_runner,
) -> None:
    base_path, demo_db = uc81_diff_runner
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
    # Exit 1 because a DANGEROUS change exists at the default
    # `--fail-on dangerous` threshold.
    assert result.exit_code == 1, result.output

    payload = json.loads(result.output)
    # The dropped-RESTRICTIVE rule should fire and project as
    # severity=error in the JSON output.
    rule_ids = {v["rule_id"] for v in payload["violations"]}
    assert "DIFF_POLICY_DROPPED_RESTRICTIVE" in rule_ids, payload
    severities = {
        v["severity"]
        for v in payload["violations"]
        if v["rule_id"] == "DIFF_POLICY_DROPPED_RESTRICTIVE"
    }
    assert severities == {"error"}, payload
