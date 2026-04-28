"""Use case 35: SEC005 with literal `USING (1=1)` — fires."""
from __future__ import annotations


def test_uc35_using_one_eq_one_fires_sec005_not_sec008(
    lint_output: str,
) -> None:
    # `USING (1=1)` is logically equivalent to `USING (true)`
    # but the AST is different — SEC008 keys on the literal
    # Boolean A_Const, not on the runtime value. Pin both:
    # SEC005 fires (no own-col ref), SEC008 stays silent.
    assert "SEC005  app.always_open.trivially_open\n" in lint_output
    assert "SEC008  app.always_open" not in lint_output


