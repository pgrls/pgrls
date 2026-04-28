"""Use case 45: Default partition — CLEAN."""
from __future__ import annotations


def test_uc45_default_partition_inherits_rls_via_ancestor_walk(
    lint_output: str,
) -> None:
    # `PARTITION OF parent DEFAULT` is just another partition
    # (relispartition=true, inhparent=root). SEC001's ancestor
    # walk reaches the RLS-enabled root from any leaf, default
    # included.
    for table in (
        "app.region_metrics",
        "app.region_metrics_us",
        "app.region_metrics_default",
    ):
        assert f"SEC001  {table}\n" not in lint_output, (
            f"SEC001 unexpectedly fired on {table}"
        )


