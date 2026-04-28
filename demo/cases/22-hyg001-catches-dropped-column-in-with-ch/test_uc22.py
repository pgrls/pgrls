"""Use case 22: HYG001 catches dropped column in WITH CHECK."""
from __future__ import annotations


def test_uc22_hyg001_fires_on_orphan_in_with_check(
    lint_output: str,
) -> None:
    # The dropped column is referenced only in WITH CHECK. Pins
    # that HYG001 walks both clauses, not just USING.
    assert "HYG001  app.posts_v2.only_approved_writes\n" in lint_output


