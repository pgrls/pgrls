"""Use case 58: PERF001 with auth wrapped in COALESCE — fires."""
from __future__ import annotations


def test_uc58_perf001_through_coalesce_on_auth_call(
    lint_output: str,
) -> None:
    # `COALESCE(auth.uid(), '...uuid...')` — auth call nested
    # inside another function. Pins find_func_calls walking
    # function args.
    assert "PERF001  app.coalesce_auth.coalesced\n" in lint_output


