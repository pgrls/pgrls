"""Use case 2: Reference data — ALLOWLISTED."""
from __future__ import annotations


def test_uc02_reference_table_silenced_by_allowlist(
    lint_output: str,
) -> None:
    # `app.countries` has no RLS but is in the SEC001 allowlist.
    assert "SEC001  app.countries" not in lint_output


