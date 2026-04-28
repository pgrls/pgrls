"""Use case 30: Composite tenant key — CLEAN."""
from __future__ import annotations


def test_uc30_composite_tenant_key_clean(
    lint_output: str,
    all_rule_ids,
) -> None:
    # Multi-column tenancy: `tenant_id = ... AND env = ...`.
    # Both columns are own-table refs.
    for rule_id in all_rule_ids:
        line = f"{rule_id}  app.composite_tenant"
        assert line not in lint_output, (
            f"{rule_id} unexpectedly fired on app.composite_tenant"
        )


