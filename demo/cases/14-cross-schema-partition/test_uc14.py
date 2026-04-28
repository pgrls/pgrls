"""Use case 14: Cross-schema partition — SEC001 unscoped variant."""
from __future__ import annotations


def test_uc14_cross_schema_partition_emits_unscoped_message(
    lint_output: str,
) -> None:
    # Parent in `private` (not in pgrls.toml `schemas`); child in
    # `app`. SEC001 fires on the child with the differentiated
    # "leaves the scanned schemas" message.
    assert "SEC001  app.audit_log_2026\n" in lint_output
    assert "leaves the scanned schemas" in lint_output


