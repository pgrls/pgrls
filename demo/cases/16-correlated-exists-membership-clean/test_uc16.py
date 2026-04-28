"""Use case 16: correlated exists membership clean."""
from __future__ import annotations


def test_uc16_correlated_exists_membership_clean(
    lint_output: str,
    all_rule_ids,
) -> None:
    # The C2 fix scenario: a correlated EXISTS that references the
    # outer table's column via correlation. Before the fix, SEC005
    # falsely fired here because exclude_sublinks=True discarded
    # the correlated own-col ref. The demo pins it as clean.
    for rule_id in all_rule_ids:
        line = f"{rule_id}  app.team_documents"
        assert line not in lint_output, (
            f"{rule_id} unexpectedly fired on app.team_documents"
        )


