"""Use case 36: pg_has_role admin escape — CLEAN."""
from __future__ import annotations


def test_uc36_pg_has_role_admin_escape_clean(
    lint_output: str,
    all_rule_ids,
) -> None:
    # `pg_has_role(current_user, 'pg_read_all_data', 'MEMBER')`
    # is a built-in admin escape. Not in PERF001's default
    # auth_functions set, so unwrapped is fine. RESTRICTIVE
    # silences SEC003.
    for rule_id in all_rule_ids:
        line = f"{rule_id}  app.admin_overrides"
        assert line not in lint_output, (
            f"{rule_id} unexpectedly fired on app.admin_overrides"
        )


