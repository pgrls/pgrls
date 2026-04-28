"""Use case 26: Blog with admin-role override — CLEAN."""
from __future__ import annotations


def test_uc26_blog_admin_override_fires_sec003_on_public_permissive(
    lint_output: str,
) -> None:
    # The RESTRICTIVE tenant floor is silent. The PERMISSIVE
    # admin-or-author SELECT policy is granted to PUBLIC, so
    # SEC003 fires on it — uc31 demos the canonical fix.
    assert (
        "SEC003  app.blog_posts.blog_admin_or_author_read\n" in lint_output
    )
    assert "SEC003  app.blog_posts.blog_tenant_floor" not in lint_output


