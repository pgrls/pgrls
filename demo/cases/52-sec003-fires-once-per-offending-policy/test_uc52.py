"""Use case 52: SEC003 fires once per offending policy."""
from __future__ import annotations


def test_uc52_sec003_fires_per_offending_policy(
    lint_output: str,
) -> None:
    # Two PERMISSIVE PUBLIC policies → two SEC003 lines.
    # Pins per-policy reporting (one violation per policy,
    # not per table). SEC007 still fires on the table because
    # all policies are permissive.
    assert "SEC003  app.multi_perm.perm_a\n" in lint_output
    assert "SEC003  app.multi_perm.perm_b\n" in lint_output
    assert "SEC007  app.multi_perm\n" in lint_output


