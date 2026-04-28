"""Use case 54: SEC005 with TypeCast wrapping a column ref —."""
from __future__ import annotations


def test_uc54_sec005_walks_through_typecast(
    lint_output: str,
    all_rule_ids,
) -> None:
    # `email::text = ...` — the column ref is inside a
    # TypeCast. Pins that extract_column_refs descends into
    # `TypeCast.arg`, so SEC005 still sees `email` and stays
    # silent.
    for rule_id in all_rule_ids:
        line = f"{rule_id}  app.typecast_email"
        assert line not in lint_output, (
            f"{rule_id} unexpectedly fired on app.typecast_email"
        )


