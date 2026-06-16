"""Use case 94: classic-inheritance child bypasses parent RLS — SEC043."""
from __future__ import annotations


def test_uc94_rls_off_child_fires_sec043(lint_output: str) -> None:
    # The parent enforces RLS but this classic-INHERITS child does not, so a
    # direct query on the child bypasses the parent's policy. SEC043 (warning)
    # fires on the live introspected child. (SEC001 also fires on it — the
    # documented double-report, since SEC001 does not walk classic
    # inheritance — but this test pins SEC043's firing.)
    assert "SEC043  app.uc94_events_legacy\n" in lint_output


def test_uc94_rls_on_child_does_not_fire_sec043(lint_output: str) -> None:
    # SEC043's boundary: a sibling child that enables its own RLS (and
    # re-applies the policy) is not directly bypassable, so SEC043 stays
    # SILENT on it — even though it carries the same direct grant.
    assert "SEC043  app.uc94_events_scoped\n" not in lint_output
