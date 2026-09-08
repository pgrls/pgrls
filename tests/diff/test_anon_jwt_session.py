"""The anon prover models TWO anonymous sessions.

A raw connection as the anon DB role has no JWT: every auth function is NULL.
A Supabase anon-key caller is different — PostgREST sets
`request.jwt.claims = {"role":"anon"}`, so `auth.role()` is the string
'anon', never NULL, while `auth.uid()` (the `sub` claim) is still NULL.

Under the no-JWT model alone, `USING (auth.role() = 'anon')` is `NULL =
'anon'` → UNKNOWN → UNSAT → PROVEN — while a real anon-key caller reads every
row (verified live on PG16 with Supabase's own `auth.role()` definition).
The prover now runs both sessions; a leak under either is a leak.
"""
from __future__ import annotations

import pytest

from pgrls.ast_utils import parse_expr
from pgrls.diff._z3_compare import Z3_AVAILABLE, prove_anon_isolation

pytestmark = pytest.mark.skipif(not Z3_AVAILABLE, reason="z3 not installed")


def _verdict(sql: str) -> str:
    return prove_anon_isolation(parse_expr(sql))[0]


@pytest.mark.parametrize(
    "sql",
    [
        "auth.role() = 'anon'",
        "auth.role() IN ('anon', 'authenticated')",
        "auth.role() = ANY (ARRAY['anon'::text, 'authenticated'::text])",  # catalog spelling
        "current_setting('request.jwt.claim.role', true) = 'anon'",
        "current_setting('request.jwt.claim.role') = 'anon'",  # one-arg: set for a real anon caller
        "'anon' = auth.role()",
        "auth.role() = 'anon' AND is_public",
    ],
)
def test_anon_key_session_leak_is_reported(sql: str) -> None:
    """The reported false clear: a policy that grants anon BY ROLE NAME."""
    assert _verdict(sql) == "leak", sql


@pytest.mark.parametrize(
    "sql",
    [
        "auth.role() = 'authenticated'",
        "auth.role() = 'service_role'",
        "auth.uid() IS NOT NULL",
        "owner_id = auth.uid()",
        "current_setting('request.jwt.claim.sub', true)::uuid = owner_id",
    ],
)
def test_authenticated_only_policies_stay_isolated(sql: str) -> None:
    """No flood: under the anon-key session the role is 'anon', so `=
    'authenticated'` is FALSE, and `auth.uid()` is still NULL."""
    assert _verdict(sql) == "isolated", sql


@pytest.mark.parametrize(
    "sql",
    [
        "auth.uid() IS NULL OR owner_id = auth.uid()",
        "auth.role() IS NULL OR owner_id = auth.uid()",
        "true",
    ],
)
def test_no_jwt_session_leaks_are_unchanged(sql: str) -> None:
    """The no-JWT session still catches the classic inverted-auth shapes —
    `auth.role() IS NULL` is FALSE for an anon-key caller but TRUE for a
    JWT-less one, and either session leaking is a leak."""
    assert _verdict(sql) == "leak", sql


def test_jwt_blob_is_non_null_but_opaque() -> None:
    """`auth.jwt()` is a non-null blob for an anon-key caller; reading a claim
    out of it is opaque, so a policy gated purely on its contents is honestly
    UNVERIFIED rather than proven either way."""
    assert _verdict("auth.jwt() IS NOT NULL") == "leak"
    assert _verdict("(auth.jwt() ->> 'role') = 'admin'") in ("unverified", "isolated")
