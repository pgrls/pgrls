"""Use case 47: ARRAY column with ANY() — CLEAN."""
from __future__ import annotations


def test_uc47_array_any_membership_clean(
    lint_output: str,
    all_rule_ids,
) -> None:
    # `<scalar> = ANY(array_col)` — pins that
    # extract_column_refs walks ArrayExpr / ANY arguments
    # so the `tags` column ref counts as own.
    for rule_id in all_rule_ids:
        line = f"{rule_id}  app.array_tags"
        assert line not in lint_output


