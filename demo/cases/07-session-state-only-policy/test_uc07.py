"""Use case 7: Session-state-only policy — SEC005."""
from __future__ import annotations


def test_uc07_session_state_only_fires_sec005(
    lint_output: str,
) -> None:
    assert "SEC005  app.singletons.admin_only\n" in lint_output


