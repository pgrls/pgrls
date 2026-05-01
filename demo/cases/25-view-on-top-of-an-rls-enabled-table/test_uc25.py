"""Use case 25: View on top of an RLS-enabled table — CLEAN."""
from __future__ import annotations


def test_uc25_clean_view_over_rls_table_passes_all_rules(
    lint_output: str,
) -> None:
    # Table-level rules ignore views by relkind. The view-level
    # rules (VIEW001..VIEW004) DO inspect views, but this fixture
    # has both `security_invoker = true` and `security_barrier =
    # true` set and calls no SECDEF function, so it's the
    # canonical clean shape: no rule mentions `app.documents_view`.
    assert "app.documents_view" not in lint_output
