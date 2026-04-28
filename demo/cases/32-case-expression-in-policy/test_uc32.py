"""Use case 32: CASE expression in policy — CLEAN."""
from __future__ import annotations


def test_uc32_case_expression_in_policy_clean(
    lint_output: str,
    all_rule_ids,
) -> None:
    # `CASE visibility WHEN 'public' THEN true WHEN 'private'
    # THEN user_id = ... END`. Pins that extract_column_refs
    # walks CASE branches — `visibility` and `user_id` are
    # both reachable, so SEC005 stays silent.
    for rule_id in all_rule_ids:
        line = f"{rule_id}  app.case_policy"
        assert line not in lint_output, (
            f"{rule_id} unexpectedly fired on app.case_policy"
        )


