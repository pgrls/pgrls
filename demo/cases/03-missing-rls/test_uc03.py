"""Use case 3: Missing RLS — SEC001."""
from __future__ import annotations


def test_uc03_missing_rls_fires_sec001(
    lint_output: str,
) -> None:
    assert "SEC001  app.legacy_orders\n" in lint_output


