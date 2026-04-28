"""Use case 76: SEC011 — `OR true` branch hidden in policy."""
from __future__ import annotations


def test_uc76_sec011_fires_on_or_true_buried_in_using(
    lint_output: str,
) -> None:
    # The policy's USING is `user_id = ... OR true`. The OR-true
    # branch admits every row regardless of the LHS. SEC011 catches
    # that without firing on the literal-true-at-top-level shape
    # (which is SEC008's territory).
    assert (
        "SEC011  app.or_true_table.debug_branch_left_in\n"
        in lint_output
    )
