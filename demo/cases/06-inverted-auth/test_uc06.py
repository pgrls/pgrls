"""Use case 6: Inverted auth — SEC004."""
from __future__ import annotations


def test_uc06_inverted_auth_fires_sec004(
    lint_output: str,
) -> None:
    assert "SEC004  app.accounts.allow_unset_user\n" in lint_output


