"""Use case 18: Soft-delete pattern — CLEAN."""
from __future__ import annotations


def test_uc18_soft_delete_pattern_clean(
    lint_output: str,
    all_rule_ids,
) -> None:
    # `deleted_at IS NULL` is a column-IS-NULL test, not an
    # `auth_func() IS NULL` — SEC004 must distinguish them.
    for rule_id in all_rule_ids:
        line = f"{rule_id}  app.users_v2"
        assert line not in lint_output, (
            f"{rule_id} unexpectedly fired on app.users_v2"
        )


