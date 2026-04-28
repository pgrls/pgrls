"""Use case 5: Permissive PUBLIC — SEC003."""
from __future__ import annotations


def test_uc05_permissive_public_fires_sec003(
    lint_output: str,
) -> None:
    assert "SEC003  app.posts.everyone_reads\n" in lint_output


