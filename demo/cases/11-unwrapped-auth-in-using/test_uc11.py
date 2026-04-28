"""Use case 11: Unwrapped auth in USING — PERF001."""
from __future__ import annotations


def test_uc11_unwrapped_auth_fires_perf001(
    lint_output: str,
) -> None:
    assert "PERF001  app.messages.messages_owner\n" in lint_output


