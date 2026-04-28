"""Use case 29: Public-or-tenant mix — CLEAN."""
from __future__ import annotations


def test_uc29_public_or_tenant_mix_clean(
    lint_output: str,
    all_rule_ids,
) -> None:
    # `is_public OR tenant_id = ...` — both branches reference
    # table columns; SEC005 stays silent (own-col present).
    for rule_id in all_rule_ids:
        line = f"{rule_id}  app.kb_articles"
        assert line not in lint_output, (
            f"{rule_id} unexpectedly fired on app.kb_articles"
        )


