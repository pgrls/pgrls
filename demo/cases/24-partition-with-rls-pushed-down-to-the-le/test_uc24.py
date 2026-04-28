"""Use case 24: Partition with RLS pushed down to the leaf —."""
from __future__ import annotations


def test_uc24_partition_leaf_rls_only_fires_on_parent(
    lint_output: str,
) -> None:
    # Parent bare, leaf has its own RLS. Pin the asymmetry —
    # SEC001 must fire on the parent (no RLS there, no ancestor
    # to cover it) but stay silent on the leaf (rls_enabled=true
    # on the leaf itself).
    assert "SEC001  app.leaf_metrics\n" in lint_output
    assert "SEC001  app.leaf_metrics_2026" not in lint_output


