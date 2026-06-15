"""Use case 92: partition child bypasses parent RLS — SEC041."""
from __future__ import annotations


def test_uc92_rls_off_child_fires_sec041(lint_output: str) -> None:
    # The parent enforces RLS but this child partition does not, so a direct
    # query on the child bypasses the parent's policy. SEC041 (warning) fires
    # on the live introspected child.
    assert "SEC041  app.uc92_events_t1\n" in lint_output


def test_uc92_rls_on_child_does_not_fire_sec041(lint_output: str) -> None:
    # SEC041's boundary: a child that enables its own RLS (and re-applies the
    # policy) is not directly bypassable, so SEC041 stays SILENT on it.
    assert "SEC041  app.uc92_events_t2\n" not in lint_output
