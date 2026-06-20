"""Unit tests for SEC045 — a sensitive/PII column is column-GRANTed to a
low-trust role.

SEC045 (warning) flags a column-level GRANT of a content privilege
(SELECT/INSERT/UPDATE) on a PII/secret-named column to a low-trust grantee
(default set ``{PUBLIC, anon}``). Column grants are rare and deliberate, so the
finding is high-signal; it is a least-privilege / defense-in-depth posture
finding (fires on the grant itself, like SEC044), distinct from SEC003 (a
PUBLIC *policy*) and SEC001 (a no-RLS *table*). The PII match is a curated
case-insensitive substring set, extendable via ``patterns``; a deliberate
public column is silenced by its ``schema.table.column`` id in ``allowlist``.
"""
from __future__ import annotations

import pytest

from pgrls.model import ColumnGrant, Schema, Table
from pgrls.rules.sec045 import SEC045


def _table(*column_grants: ColumnGrant, name: str = "users") -> Table:
    return Table(
        schema="public",
        name=name,
        rls_enabled=True,
        force_rls=True,
        policies=(),
        column_grants=column_grants,
    )


def _check(*column_grants: ColumnGrant, options: dict | None = None) -> list:
    return SEC045().check(
        Schema(tables=(_table(*column_grants),)), options=options or {}
    )


def _cg(
    *, role: str = "anon", column: str = "email", privileges: tuple[str, ...] = ("SELECT",)
) -> ColumnGrant:
    return ColumnGrant(role=role, column=column, privileges=privileges)


# --- positives -------------------------------------------------------------


def test_pii_column_granted_to_anon_fires() -> None:
    out = _check(_cg(role="anon", column="email"))
    assert [v.location for v in out] == ["public.users.email"]
    assert out[0].rule_id == "SEC045"
    assert out[0].severity == "warning"


def test_pii_column_granted_to_public_fires() -> None:
    out = _check(_cg(role="PUBLIC", column="ssn"))
    assert [v.location for v in out] == ["public.users.ssn"]


def test_update_privilege_on_pii_column_fires() -> None:
    # A column-level UPDATE of a sensitive field to a low-trust role is also an
    # over-share (write to the field), not just SELECT.
    out = _check(_cg(role="anon", column="password", privileges=("UPDATE",)))
    assert len(out) == 1
    assert "UPDATE" in out[0].message


def test_message_names_column_role_and_revoke() -> None:
    out = _check(_cg(role="anon", column="credit_card"))
    msg = out[0].message
    assert "credit_card" in msg and "anon" in msg and "REVOKE" in msg


def test_multiple_pii_columns_each_fire() -> None:
    out = _check(
        _cg(role="anon", column="email"),
        _cg(role="anon", column="phone"),
    )
    assert {v.location for v in out} == {
        "public.users.email",
        "public.users.phone",
    }


# --- false-positive controls ----------------------------------------------


def test_authenticated_not_flagged_by_default() -> None:
    # `authenticated` is not in the default low-trust set — a column grant to
    # every-logged-in-user is common enough to require opt-in.
    assert _check(_cg(role="authenticated", column="email")) == []


def test_non_pii_column_not_flagged() -> None:
    assert _check(_cg(role="anon", column="id")) == []
    assert _check(_cg(role="anon", column="created_at")) == []
    assert _check(_cg(role="anon", column="status")) == []


@pytest.mark.parametrize(
    "column",
    [
        "headphone_model",  # 'phone' is a substring but not a whole token
        "saxophone_count",
        "smartphone_os",
        "secretary_id",  # 'secret' ⊂ 'secretary' — not a token
        "doberman_name",  # 'dob' ⊂ 'doberman' — not a token
        "syntax_idea",  # 'tax_id' substring but not token-aligned
    ],
)
def test_token_boundary_avoids_unrelated_word_collisions(column: str) -> None:
    # Token-boundary matching must NOT fire on words that merely contain a PII
    # token as an incidental substring.
    assert _check(_cg(role="anon", column=column)) == []


@pytest.mark.parametrize(
    "column",
    [
        "phone_number",
        "user_phone",
        "mfa_secret",
        "user_email",
        "email_verified",  # shares the whole 'email' token → still fires
        "dob",
        "applicant_tax_id",
        "credit_card_last4",
    ],
)
def test_token_boundary_still_matches_real_pii(column: str) -> None:
    assert [v.location for v in _check(_cg(role="anon", column=column))] == [
        f"public.users.{column}"
    ]


def test_references_only_not_flagged() -> None:
    # A column-level REFERENCES exposes no row content → not an over-share.
    assert _check(_cg(role="anon", column="email", privileges=("REFERENCES",))) == []


def test_table_grant_not_inspected() -> None:
    # SEC045 looks only at column_grants; a table-level grant of a table that
    # happens to contain a PII column is SEC003/SEC001's domain, not SEC045's.
    from pgrls.model import Grant

    table = Table(
        schema="public",
        name="users",
        rls_enabled=False,
        force_rls=False,
        policies=(),
        grants=(Grant(role="anon", privileges=("SELECT",)),),
        column_grants=(),
    )
    assert SEC045().check(Schema(tables=(table,)), options={}) == []


# --- config ----------------------------------------------------------------


def test_allowlist_silences_a_deliberate_public_column() -> None:
    out = _check(
        _cg(role="anon", column="email"),
        options={"allowlist": ["public.users.email"]},
    )
    assert out == []


def test_grantees_config_widens_to_authenticated() -> None:
    out = _check(
        _cg(role="authenticated", column="email"),
        options={"grantees": ["authenticated"]},
    )
    assert [v.location for v in out] == ["public.users.email"]


def test_grantees_config_normalizes_public() -> None:
    out = _check(
        _cg(role="PUBLIC", column="email"),
        options={"grantees": ["public"]},  # lowercase normalizes to PUBLIC
    )
    assert len(out) == 1


def test_patterns_config_adds_custom_pii_token() -> None:
    out = _check(
        _cg(role="anon", column="mrn"),  # medical record number
        options={"patterns": ["mrn"]},
    )
    assert [v.location for v in out] == ["public.users.mrn"]


def test_custom_patterns_extend_not_replace_defaults() -> None:
    # Adding a custom pattern must not drop the built-in ones.
    out = _check(
        _cg(role="anon", column="email"),
        _cg(role="anon", column="mrn"),
        options={"patterns": ["mrn"]},
    )
    assert {v.location for v in out} == {
        "public.users.email",
        "public.users.mrn",
    }


def test_malformed_grantees_config_raises() -> None:
    with pytest.raises(TypeError):
        _check(_cg(), options={"grantees": "PUBLIC"})  # must be a list


def test_malformed_patterns_config_raises() -> None:
    with pytest.raises(TypeError):
        _check(_cg(), options={"patterns": "ssn"})


def test_malformed_allowlist_config_raises() -> None:
    with pytest.raises(TypeError):
        _check(_cg(), options={"allowlist": "public.users.email"})


# --- abstention ------------------------------------------------------------


def test_no_column_grants_no_findings() -> None:
    # A pre-column-grant snapshot round-trips to column_grants=() → no findings.
    assert SEC045().check(Schema(tables=(_table(),)), options={}) == []
