"""Use case 23: Three-level partition with RLS at root — CLEAN."""
from __future__ import annotations


def test_uc23_three_level_partition_with_rls_root_silent(
    lint_output: str,
) -> None:
    # Sub-partitioning: deep_events -> deep_events_t1 ->
    # deep_events_t1_2026. RLS only on the root, but SEC001's
    # iterative ancestor walk reaches it from any depth.
    for table in (
        "app.deep_events",
        "app.deep_events_t1",
        "app.deep_events_t1_2026",
    ):
        assert f"SEC001  {table}\n" not in lint_output, (
            f"SEC001 unexpectedly fired on {table}"
        )


