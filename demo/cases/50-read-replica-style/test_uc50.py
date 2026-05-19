"""Use case 50: Read-replica style — SEC022 flags the read-only shape."""
from __future__ import annotations


def test_uc50_read_replica_triggers_sec022(
    lint_output: str,
    all_rule_ids,
) -> None:
    # A read-only mirror: one RESTRICTIVE tenant floor + one
    # PERMISSIVE grant to a non-PUBLIC role, both FOR SELECT, and
    # zero write policies. SEC022 (info) flags exactly this shape —
    # the table has working read coverage but no INSERT/UPDATE/
    # DELETE policy, so writes by non-owner roles are denied. For a
    # deliberate read replica that is expected; you would allowlist
    # the table when the read-only surface is intentional.
    assert "SEC022  app.read_replica" in lint_output

    # SEC022 is the only finding on this table: there are no write
    # policies to validate (SEC006 silent) and the permissive grant
    # is to a specific role, not PUBLIC (SEC003 silent).
    for rule_id in all_rule_ids:
        if rule_id == "SEC022":
            continue
        line = f"{rule_id}  app.read_replica"
        assert line not in lint_output, (
            f"{rule_id} unexpectedly fired on app.read_replica"
        )
