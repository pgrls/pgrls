"""Use case 19: Supabase auth.uid() inverted — SEC004."""
from __future__ import annotations


def test_uc19_supabase_auth_uid_inverted_fires_sec004(
    lint_output: str,
) -> None:
    assert "SEC004  app.profiles.allow_anon\n" in lint_output


