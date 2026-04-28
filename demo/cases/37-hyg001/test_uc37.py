"""Use case 37: HYG001 — per-policy isolation."""
from __future__ import annotations


def test_uc37_hyg001_isolated_to_offending_policy(
    lint_output: str,
) -> None:
    # Two policies on `app.partial_orphan`: `clean_owner` (no
    # orphan) and `orphan_filter` (refs the dropped `gone`
    # column). HYG001 must fire ONLY on the offending policy.
    assert (
        "HYG001  app.partial_orphan.orphan_filter\n" in lint_output
    )
    assert (
        "HYG001  app.partial_orphan.clean_owner" not in lint_output
    )


