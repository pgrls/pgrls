"""Use case 53: SEC004 inside a nested OR — false-negative pin."""
from __future__ import annotations


def test_uc53_sec004_silent_on_nested_or_documented_false_negative(
    lint_output: str,
) -> None:
    # `flag = 'system' OR ((SELECT auth.uid()) IS NULL OR
    # user_id = (SELECT auth.uid()))` — the auth IS NULL
    # disjunct is buried inside a nested OR. SEC004 splits at
    # the top level only (per top_level_disjuncts), so it
    # does NOT fire here. This is a documented false negative;
    # pin it so a future change to descend into nested ORs is
    # deliberate (and probably noisier on real schemas).
    assert "SEC004  app.nested_or_check" not in lint_output


