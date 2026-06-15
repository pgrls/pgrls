"""Use case 93: anon-executable SECURITY DEFINER RPC bypasses RLS — SEC042."""
from __future__ import annotations


def test_uc93_default_public_secdef_fires_sec042(lint_output: str) -> None:
    # SECURITY DEFINER, RLS-exempt (superuser) owner, default EXECUTE TO
    # PUBLIC — an unauthenticated caller runs owner-privileged, RLS-exempt
    # code. SEC042 fires on the live introspected function.
    assert "SEC042  app.uc93_all_secrets\n" in lint_output


def test_uc93_revoked_public_secdef_does_not_fire_sec042(lint_output: str) -> None:
    # SEC042's boundary: same SECURITY DEFINER function, but EXECUTE revoked
    # from PUBLIC and granted only to a trusted role — no longer an anonymous
    # endpoint, so SEC042 stays SILENT.
    assert "SEC042  app.uc93_trusted_secrets\n" not in lint_output
