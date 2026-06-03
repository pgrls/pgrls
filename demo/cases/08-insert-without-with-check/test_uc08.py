"""Use case 8: INSERT without WITH CHECK — SEC006."""
from __future__ import annotations


def test_uc08_insert_without_with_check_fires_sec006(
    lint_output: str,
) -> None:
    assert "SEC006  app.invoices.invoices_insert_open\n" in lint_output
