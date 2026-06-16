"""Use case 95: default privileges expose future tables to PUBLIC — SEC044."""
from __future__ import annotations


def test_uc95_default_privileges_to_public_fires_sec044(
    lint_output: str,
) -> None:
    # A standing `ALTER DEFAULT PRIVILEGES IN SCHEMA app GRANT SELECT ON
    # TABLES TO PUBLIC` auto-grants SELECT to PUBLIC on every future table in
    # schema app, so any new table created without RLS is immediately exposed.
    # SEC044 (warning) fires on the live pg_default_acl entry, location `app`.
    assert "SEC044  app\n" in lint_output


def test_uc95_anon_default_would_be_silent_by_default(lint_output: str) -> None:
    # SEC044's boundary: the only default-privilege finding here is the PUBLIC
    # one. A default privilege to the named `anon` role (the RLS-gated
    # Supabase pattern) is silent under the default {PUBLIC} grantee set — so
    # SEC044 fires exactly once in schema app, on the PUBLIC entry.
    assert lint_output.count("SEC044  app\n") == 1
