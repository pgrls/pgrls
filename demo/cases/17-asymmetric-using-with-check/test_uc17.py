"""Use case 17: Asymmetric USING / WITH CHECK — CLEAN."""
from __future__ import annotations


def test_uc17_asymmetric_using_with_check_clean(
    lint_output: str,
    all_rule_ids,
) -> None:
    # Read team's tickets, write only your own. USING and WITH
    # CHECK do different things by design; pgrls accepts that.
    for rule_id in all_rule_ids:
        line = f"{rule_id}  app.tickets"
        assert line not in lint_output, (
            f"{rule_id} unexpectedly fired on app.tickets"
        )


