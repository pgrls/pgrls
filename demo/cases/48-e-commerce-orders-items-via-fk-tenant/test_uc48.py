"""Use case 48: E-commerce orders + items via FK tenant — CLEAN."""
from __future__ import annotations


def test_uc48_ec_orders_via_fk_clean(
    lint_output: str,
    all_rule_ids,
) -> None:
    # Two-table FK relation: orders own tenant; items inherit
    # tenant scope by EXISTS-joining the parent. Pins that the
    # SubLink walk correctly correlates `order_id` against the
    # outer items table.
    for table in ("app.ec_orders", "app.ec_order_items"):
        for rule_id in all_rule_ids:
            line = f"{rule_id}  {table}"
            assert line not in lint_output, (
                f"{rule_id} unexpectedly fired on {table}"
            )


