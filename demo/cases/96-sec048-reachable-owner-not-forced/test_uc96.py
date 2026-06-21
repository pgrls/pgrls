"""Use case 96: a low-trust role reaches a non-FORCE'd owner — SEC048."""
from __future__ import annotations


def test_uc96_member_of_non_forced_owner_fires_sec048(
    lint_output: str,
) -> None:
    # `app_authenticated` is a member of `demo_table_owner`, which OWNS
    # `app.owner_reachable_ledger` (RLS ENABLEd, NOT FORCE'd). Owner privileges
    # are inherited through membership, so the member bypasses RLS on the
    # owner's not-forced table. SEC048 (warning) fires at the member role name.
    assert "SEC048  app_authenticated\n" in lint_output


def test_uc96_cofire_with_sec002_on_the_owned_table(lint_output: str) -> None:
    # SEC048 (role side) and SEC002 (table side) are mutually independent and
    # co-fire on the same missing-FORCE misconfig by design: SEC002 reports the
    # not-forced table, SEC048 reports each role that can reach its owner.
    assert "SEC002  app.owner_reachable_ledger\n" in lint_output
