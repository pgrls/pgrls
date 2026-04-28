"""Use case 13: Partitioned parent — CLEAN."""
from __future__ import annotations


def test_uc13_partitioned_parent_with_rls_keeps_all_silent(
    lint_output: str,
) -> None:
    # Parent has RLS; SEC001 walks each child's chain and finds
    # the RLS-enabled root, suppressing the child violation.
    # Neither parent nor any child should fire.
    for table in ("app.events", "app.events_2025", "app.events_2026"):
        assert f"SEC001  {table}\n" not in lint_output, (
            f"SEC001 unexpectedly fired on {table}"
        )


