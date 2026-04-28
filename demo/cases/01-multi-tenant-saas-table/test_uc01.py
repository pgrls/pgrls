"""Use case 1: Multi-tenant SaaS table — CLEAN."""
from __future__ import annotations


def test_uc01_clean_tenant_table_passes_all_rules(
    lint_output: str,
    all_rule_ids,
) -> None:
    # Substring "X  app.documents" matches both the table-level
    # location and the policy-level location (`app.documents.tenant_isolation`).
    # Either kind of fire is unacceptable for the canonical clean
    # example.
    for rule_id in all_rule_ids:
        line = f"{rule_id}  app.documents"
        assert line not in lint_output, (
            f"{rule_id} unexpectedly fired on app.documents:\n"
            f"{lint_output}"
        )


