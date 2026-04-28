"""Use case 74: USING (false) deny-all anti-pattern — SEC010."""
from __future__ import annotations


def test_uc74_sec010_fires_on_using_false_deny_all(
    lint_output: str,
) -> None:
    # `USING (false)` denies every row. SEC010 catches the
    # anti-pattern. SEC005 also fires (no column ref); pin both
    # — the demo's primary rule for this case is SEC010 but
    # cross-firing is realistic.
    assert "SEC010  app.deny_via_false.block_all\n" in lint_output
    assert "SEC005  app.deny_via_false.block_all\n" in lint_output


