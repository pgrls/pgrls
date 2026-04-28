"""Use case 56: HYG001 with `gone IS TRUE` (BoolTest) — fires."""
from __future__ import annotations


def test_uc56_hyg001_walks_through_booltest(
    lint_output: str,
) -> None:
    # `gone IS TRUE` wraps a column ref in a BoolTest node.
    # extract_column_refs walks through BoolTest.arg so HYG001
    # still flags the dropped column.
    assert (
        "HYG001  app.booltest_orphan.bt_check\n" in lint_output
    )


