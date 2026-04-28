"""Use case 44: SQLValueFunction `current_user` in policy —."""
from __future__ import annotations


def test_uc44_current_user_in_policy_does_not_fire_perf001(
    lint_output: str,
    all_rule_ids,
) -> None:
    # `current_user` is a SQLValueFunction (cheap); PERF001's
    # default auth_functions set deliberately excludes it.
    # Pin the asymmetry so a future "broaden the default set"
    # change is deliberate.
    assert "PERF001  app.current_user_check" not in lint_output
    # The whole table should be clean — `visibility` column
    # ref keeps SEC005 silent, RESTRICTIVE silences SEC003.
    for rule_id in all_rule_ids:
        line = f"{rule_id}  app.current_user_check"
        assert line not in lint_output


