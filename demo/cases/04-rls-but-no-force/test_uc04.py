"""Use case 4: RLS but no FORCE — SEC002."""
from __future__ import annotations


def test_uc04_missing_force_fires_sec002(
    lint_output: str,
) -> None:
    assert "SEC002  app.notes\n" in lint_output


