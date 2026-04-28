"""Use case 49: GDPR-style classification with ARRAY — CLEAN."""
from __future__ import annotations


def test_uc49_gdpr_classification_clean(
    lint_output: str,
    all_rule_ids,
) -> None:
    # Composite predicate: tenant AND CASE-on-classification
    # AND `(SELECT current_setting(...)) = ANY(visible_to)`.
    # Pins that ARRAY ANY + CASE branches + outer AND all walk
    # through extract correctly so SEC005 sees own-col refs.
    for rule_id in all_rule_ids:
        line = f"{rule_id}  app.gdpr_records"
        assert line not in lint_output, (
            f"{rule_id} unexpectedly fired on app.gdpr_records"
        )


