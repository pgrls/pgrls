"""Use case 38: PERF001 with `auth.jwt() ->> 'sub'` unwrapped."""
from __future__ import annotations


def test_uc38_perf001_on_unwrapped_jwt_json_access(
    lint_output: str,
) -> None:
    # `auth.jwt() ->> 'sub'` — the `->>` operator wraps the
    # auth call. Pin that find_func_calls walks operator
    # arguments correctly.
    assert (
        "PERF001  app.jwt_unwrapped.jwt_unwrapped_owner\n" in lint_output
    )


