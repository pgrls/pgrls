"""Use case 10: USING (true) — SEC008 (permissive) vs SEC031 (restrictive)."""
from __future__ import annotations


def test_uc10_permissive_using_true_fires_sec008(
    lint_output: str,
) -> None:
    # A permissive USING (true) admits every row.
    assert "SEC008  app.feature_flags.open_perm\n" in lint_output


def test_uc10_restrictive_using_true_fires_sec031(
    lint_output: str,
) -> None:
    # A restrictive USING (true) is a no-op floor — SEC031, not SEC008.
    assert "SEC031  app.feature_flags.public_flags\n" in lint_output
