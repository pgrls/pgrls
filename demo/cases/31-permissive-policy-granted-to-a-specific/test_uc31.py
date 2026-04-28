"""Use case 31: Permissive policy granted to a specific role."""
from __future__ import annotations


def test_uc31_permissive_policy_to_specific_role_silences_sec003(
    lint_output: str,
) -> None:
    # The RESTRICTIVE tenant_floor is silent; the PERMISSIVE
    # auth_role_read is granted to `app_authenticated`
    # (NOT PUBLIC), so SEC003 doesn't fire on it. This is the
    # canonical fix for the SEC003 violation in uc26.
    assert "SEC003  app.scoped_views" not in lint_output


