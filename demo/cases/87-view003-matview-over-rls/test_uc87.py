"""Use case 87: Materialized view over RLS table — VIEW003."""
from __future__ import annotations


def test_uc87_matview_over_rls_fires_view003(lint_output: str) -> None:
    assert "VIEW003  app.uc87_user_summary\n" in lint_output
