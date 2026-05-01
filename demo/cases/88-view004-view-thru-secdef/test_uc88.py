"""Use case 88: View through SECDEF function reading RLS table — VIEW004."""
from __future__ import annotations


def test_uc88_view_thru_secdef_fires_view004(lint_output: str) -> None:
    assert "VIEW004  app.uc88_user_summary\n" in lint_output
