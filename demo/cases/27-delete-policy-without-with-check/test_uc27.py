"""Use case 27: DELETE policy without WITH CHECK — CLEAN."""
from __future__ import annotations


def test_uc27_delete_policy_without_with_check_clean(
    lint_output: str,
    all_rule_ids,
) -> None:
    # DELETE is exempt from SEC006 by design — pin the contract
    # against a future regression that broadens SEC006 to all
    # write commands.
    for rule_id in all_rule_ids:
        line = f"{rule_id}  app.todos_archive"
        assert line not in lint_output, (
            f"{rule_id} unexpectedly fired on app.todos_archive"
        )


