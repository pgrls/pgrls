"""Use case 9: All policies permissive — SEC007 (info)."""
from __future__ import annotations


def test_uc09_all_permissive_fires_sec007(
    lint_output: str,
) -> None:
    assert "SEC007  app.tags\n" in lint_output


