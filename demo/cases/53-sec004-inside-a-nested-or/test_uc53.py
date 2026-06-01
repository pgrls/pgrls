"""Use case 53: SEC004 inside a nested OR — now caught (FN fixed)."""
from __future__ import annotations


def test_uc53_sec004_fires_on_nested_or(
    lint_output: str,
) -> None:
    # `flag = 'system' OR ((SELECT auth.uid()) IS NULL OR
    # user_id = (SELECT auth.uid()))` — the `auth() IS NULL`
    # disjunct is buried inside a parenthesized nested OR. OR is
    # associative, so this is the same anonymous-access hole as
    # the flat form `A OR B OR auth() IS NULL`. SEC004 now flattens
    # nested OR disjuncts (ast_utils.flatten_or_disjuncts) before
    # the IS NULL check, so it fires here — previously a documented
    # false negative pinned by this case.
    assert "SEC004  app.nested_or_check.nested_or\n" in lint_output
