"""Use case 12: Orphaned column reference — HYG001."""
from __future__ import annotations


def test_uc12_orphaned_column_fires_hyg001(
    lint_output: str,
) -> None:
    assert "HYG001  app.comments.archived_filter\n" in lint_output


