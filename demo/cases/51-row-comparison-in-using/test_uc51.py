"""Use case 51: ROW comparison in USING — CLEAN."""
from __future__ import annotations


def test_uc51_row_comparison_walks_tuple_arguments(
    lint_output: str,
    all_rule_ids,
) -> None:
    # `(tenant_id, env) = (..., ...)` parses as a row-compare
    # node. Pins extract_column_refs walking through the row
    # constructors so SEC005 sees both `tenant_id` and `env`.
    for rule_id in all_rule_ids:
        line = f"{rule_id}  app.row_comparison"
        assert line not in lint_output, (
            f"{rule_id} unexpectedly fired on app.row_comparison"
        )


