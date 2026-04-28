"""Use case 55: SEC008 with `USING (NOT false)` — CLEAN."""
from __future__ import annotations


def test_uc55_using_not_false_fires_sec005_not_sec008(
    lint_output: str,
) -> None:
    # `USING (NOT false)` is logically `true` but the AST is a
    # BoolExpr (NOT) over `A_Const(false)`, NOT a literal True.
    # SEC008 specifically detects the literal-True A_Const, so
    # this shape stays silent on SEC008 — and fires SEC005
    # because there are no own-col refs.
    assert "SEC005  app.not_false_table.not_false\n" in lint_output
    assert "SEC008  app.not_false_table" not in lint_output


