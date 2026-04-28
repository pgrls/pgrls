"""Use case 67: BETWEEN operator — CLEAN."""
from __future__ import annotations


def test_uc67_between_operator_clean(
    lint_output: str,
    all_rule_ids,
) -> None:
    # `created_at BETWEEN now() - INTERVAL ... AND now()`
    # parses as A_Expr-AEXPR_BETWEEN. Pins extract_column_refs
    # walking through it so SEC005 sees both `tenant_id` and
    # `created_at`.
    for rule_id in all_rule_ids:
        line = f"{rule_id}  app.recent_only"
        assert line not in lint_output, (
            f"{rule_id} unexpectedly fired on app.recent_only"
        )


