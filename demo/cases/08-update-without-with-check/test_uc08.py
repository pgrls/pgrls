"""Use case 8: UPDATE without WITH CHECK — SEC006."""
from __future__ import annotations


def test_uc08_update_without_with_check_fires_sec006(
    lint_output: str,
) -> None:
    assert "SEC006  app.invoices.update_without_check\n" in lint_output


