"""Use case 90: anonymous-role write policy — SEC039."""
from __future__ import annotations


def test_uc90_anon_write_policy_fires_sec039(lint_output: str) -> None:
    # A permissive INSERT policy granting the unauthenticated `anon`
    # role lets anonymous clients write rows — SEC039 (error).
    assert (
        "SEC039  app.public_submissions.public_submissions_anon_write\n"
        in lint_output
    )


def test_uc90_anon_read_policy_does_not_fire_sec039(lint_output: str) -> None:
    # SEC039's defining write-only scope: a public READ (FOR SELECT TO
    # anon) is a legitimate public-data pattern, so SEC039 stays SILENT
    # on it. Pins the exemption through the live introspection path (the
    # unit tests pin it on hand-built ASTs; this is the production path).
    assert (
        "SEC039  app.public_submissions.public_submissions_anon_read\n"
        not in lint_output
    )
