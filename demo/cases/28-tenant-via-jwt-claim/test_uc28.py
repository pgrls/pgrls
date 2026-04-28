"""Use case 28: Tenant via JWT claim — CLEAN."""
from __future__ import annotations


def test_uc28_jwt_based_tenant_clean(
    lint_output: str,
    all_rule_ids,
) -> None:
    # `auth.jwt()` is wrapped via `(SELECT auth.jwt())` — pin
    # that PERF001 doesn't fire on the wrapped form even when
    # combined with the `->>` JSON extractor.
    for rule_id in all_rule_ids:
        line = f"{rule_id}  app.jwt_documents"
        assert line not in lint_output, (
            f"{rule_id} unexpectedly fired on app.jwt_documents"
        )


