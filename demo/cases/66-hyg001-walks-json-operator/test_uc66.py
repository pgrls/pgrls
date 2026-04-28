"""Use case 66: HYG001 walks JSON `->>` operator — fires."""
from __future__ import annotations


def test_uc66_hyg001_does_not_confuse_json_keys_with_columns(
    lint_output: str,
    all_rule_ids,
) -> None:
    # `payload->>'visibility' = 'public'` — `'visibility'` is
    # a JSON path key, NOT a column name. The only column ref
    # in this expression is `payload`, which exists. Pin that
    # HYG001 doesn't false-fire by treating the JSON key as a
    # missing column.
    for rule_id in all_rule_ids:
        line = f"{rule_id}  app.json_access"
        assert line not in lint_output, (
            f"{rule_id} unexpectedly fired on app.json_access"
        )


