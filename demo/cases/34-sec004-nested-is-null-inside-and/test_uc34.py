"""Use case 34: SEC004 nested IS NULL inside AND — CLEAN."""
from __future__ import annotations


def test_uc34_sec004_nested_is_null_under_and_clean(
    lint_output: str,
) -> None:
    # The expression is `user_id = auth.uid() AND flag_name IS NOT NULL`.
    # SEC004 fires only on TOP-LEVEL OR disjuncts where one is
    # `auth_func() IS NULL`. Top-level AND with a column
    # IS-NOT-NULL stays silent. Pin the distinction.
    assert "SEC004  app.flags_table" not in lint_output


