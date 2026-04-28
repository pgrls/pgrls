"""Use case 46: Generated column referenced in policy — CLEAN."""
from __future__ import annotations


def test_uc46_generated_column_referenced_in_policy_clean(
    lint_output: str,
    all_rule_ids,
) -> None:
    # `GENERATED ALWAYS AS (...) STORED` columns appear in
    # pg_attribute alongside regular columns. HYG001 sees them
    # as present; SEC005 sees them as own-col refs.
    for rule_id in all_rule_ids:
        line = f"{rule_id}  app.gen_cols"
        assert line not in lint_output


