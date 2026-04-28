"""Use case 57: PERF001 with auth wrapped in TypeCast — fires."""
from __future__ import annotations


def test_uc57_perf001_through_typecast_on_auth_call(
    lint_output: str,
) -> None:
    # `auth.uid()::text` — the auth call is inside a TypeCast.
    # Pins find_func_calls descending into TypeCast.arg.
    assert "PERF001  app.typecast_auth.auth_cast\n" in lint_output


