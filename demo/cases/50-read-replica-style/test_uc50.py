"""Use case 50: Read-replica style — SELECT-only policies clean."""
from __future__ import annotations


def test_uc50_read_replica_clean(
    lint_output: str,
    all_rule_ids,
) -> None:
    # Read-only mirror: one RESTRICTIVE tenant floor + one
    # PERMISSIVE grant to a non-PUBLIC role. No write policies
    # to validate, so SEC006 is silent; SEC003 silent because
    # the permissive isn't TO PUBLIC.
    for rule_id in all_rule_ids:
        line = f"{rule_id}  app.read_replica"
        assert line not in lint_output, (
            f"{rule_id} unexpectedly fired on app.read_replica"
        )


