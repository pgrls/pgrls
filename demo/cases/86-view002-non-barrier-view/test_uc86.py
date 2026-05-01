"""Use case 86: Non-`security_barrier` view over RLS table — VIEW002."""
from __future__ import annotations


def test_uc86_non_barrier_view_fires_view002(lint_output: str) -> None:
    assert "VIEW002  app.uc86_user_summary\n" in lint_output
