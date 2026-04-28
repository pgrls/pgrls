"""Use case 20: Supabase auth.uid() unwrapped — PERF001."""
from __future__ import annotations


def test_uc20_supabase_auth_uid_unwrapped_fires_perf001(
    lint_output: str,
) -> None:
    assert "PERF001  app.todos.todos_owner\n" in lint_output


