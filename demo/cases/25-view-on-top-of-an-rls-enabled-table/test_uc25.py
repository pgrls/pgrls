"""Use case 25: View on top of an RLS-enabled table —."""
from __future__ import annotations


def test_uc25_view_invisible_to_introspector(
    lint_output: str,
) -> None:
    # The introspector filters to relkind IN ('r', 'p'). Views
    # (relkind='v') don't enter the table list, so no rule
    # mentions `app.documents_view` even though it sits on top
    # of an RLS-enabled table.
    assert "app.documents_view" not in lint_output


