"""Use case 85: Non-`security_invoker` view over RLS table — VIEW001."""
from __future__ import annotations


def test_uc85_non_invoker_view_fires_view001(lint_output: str) -> None:
    assert "VIEW001  app.uc85_user_summary\n" in lint_output
