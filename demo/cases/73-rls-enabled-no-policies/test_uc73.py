"""Use case 73: RLS enabled, no policies — SEC009 (new in 0.0.6)."""
from __future__ import annotations


def test_uc73_sec009_fires_on_rls_with_no_policies(
    lint_output: str,
) -> None:
    # `app.deny_all_log` has RLS+FORCE but zero policies. Looks
    # protected, is actually deny-all. Pin SEC009 catching the
    # forgotten-policies migration.
    assert "SEC009  app.deny_all_log\n" in lint_output


