"""Use case 15: Partition family with no RLS anywhere —."""
from __future__ import annotations


def test_uc15_visible_root_partition_message_names_the_root(
    lint_output: str,
) -> None:
    # Both parent and child are in scope and lack RLS. Parent
    # gets the classic message; child gets the visible-root
    # variant naming the parent.
    assert "SEC001  app.bare_metrics\n" in lint_output
    assert "SEC001  app.bare_metrics_2026\n" in lint_output
    assert "is a partition of app.bare_metrics" in lint_output


