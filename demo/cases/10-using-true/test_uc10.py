"""Use case 10: USING (true) — SEC008."""
from __future__ import annotations


def test_uc10_using_true_fires_sec008(
    lint_output: str,
) -> None:
    assert "SEC008  app.feature_flags.public_flags\n" in lint_output


