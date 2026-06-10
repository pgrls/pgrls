"""Unit tests for SEC039.

SEC039 (error) fires when a PERMISSIVE policy for a write command
(INSERT / UPDATE / DELETE / ALL) lists the unauthenticated ``anon`` role,
letting anonymous PostgREST/Supabase clients modify rows. Anonymous
*read* (SELECT) is a legitimate public-data pattern and is not flagged;
``TO PUBLIC`` is SEC003's job, so SEC039 covers only the named role(s).
"""
from __future__ import annotations

import pytest

from pgrls.ast_utils import parse_expr
from pgrls.model import Policy, Schema, Table
from pgrls.rules.sec039 import SEC039


def _policy(
    *,
    command: str = "INSERT",
    roles: tuple[str, ...] = ("anon",),
    permissive: bool = True,
    name: str = "p",
    using: str | None = None,
    with_check: str | None = None,
) -> Policy:
    return Policy(
        name=name,
        command=command,  # type: ignore[arg-type]
        permissive=permissive,
        roles=roles,
        using_sql=using,
        with_check_sql=with_check,
        using_ast=parse_expr(using) if using else None,
        with_check_ast=parse_expr(with_check) if with_check else None,
    )


def _wrap(policy: Policy) -> Schema:
    return Schema(
        tables=(
            Table(
                schema="public",
                name="t",
                rls_enabled=True,
                force_rls=True,
                policies=(policy,),
                columns=("id", "body"),
            ),
        )
    )


# ──────────────────────────────────────────────────────────────────────
# Fires — a permissive write policy grants the anon role
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("command", ["INSERT", "UPDATE", "DELETE", "ALL"])
def test_fires_on_each_write_command(command: str) -> None:
    schema = _wrap(_policy(command=command, name="anon_write"))
    violations = SEC039().check(schema, {})
    assert len(violations) == 1, command
    v = violations[0]
    assert v.rule_id == "SEC039"
    assert v.severity == "error"
    assert v.location == "public.t.anon_write"
    assert "anon" in v.message
    assert command in v.message  # the command is named


def test_fires_when_anon_among_several_roles() -> None:
    # `TO anon, authenticated` still lets anon write → fires.
    schema = _wrap(_policy(command="UPDATE", roles=("anon", "authenticated")))
    assert len(SEC039().check(schema, {})) == 1


def test_fires_regardless_of_clause() -> None:
    # The grant of anon write is the signal (mirrors SEC003's TO-PUBLIC
    # check, which fires regardless of USING). A constraining clause does
    # not make anonymous write acceptable.
    schema = _wrap(
        _policy(command="INSERT", with_check="(true)", name="anon_open_insert")
    )
    assert len(SEC039().check(schema, {})) == 1


# ──────────────────────────────────────────────────────────────────────
# Silent — read-only, non-anon, restrictive, or PUBLIC (SEC003's job)
# ──────────────────────────────────────────────────────────────────────


def test_silent_on_anon_select() -> None:
    # Public read via anon is a deliberate, common pattern — not flagged.
    assert SEC039().check(_wrap(_policy(command="SELECT")), {}) == []


@pytest.mark.parametrize("command", ["INSERT", "UPDATE", "DELETE", "ALL"])
def test_silent_when_role_is_authenticated(command: str) -> None:
    schema = _wrap(_policy(command=command, roles=("authenticated",)))
    assert SEC039().check(schema, {}) == []


def test_silent_on_restrictive_anon_write() -> None:
    # A RESTRICTIVE policy narrows access; it does not GRANT anon write.
    schema = _wrap(_policy(command="INSERT", permissive=False))
    assert SEC039().check(schema, {}) == []


def test_silent_on_public_pseudo_role() -> None:
    # `TO PUBLIC` is SEC003's domain (the PUBLIC pseudo-role, not the named
    # `anon` role); SEC039 stays silent so the two don't double-report.
    schema = _wrap(_policy(command="INSERT", roles=("PUBLIC",)))
    assert SEC039().check(schema, {}) == []


def test_silent_on_service_role_write() -> None:
    schema = _wrap(_policy(command="DELETE", roles=("service_role",)))
    assert SEC039().check(schema, {}) == []


# ──────────────────────────────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────────────────────────────


def test_anon_roles_override_extends_set() -> None:
    # Add a second unauthenticated role — a `TO guest INSERT` now fires.
    schema = _wrap(_policy(command="INSERT", roles=("guest",)))
    options = {"anon_roles": ["anon", "guest"]}
    assert len(SEC039().check(schema, options)) == 1


def test_anon_roles_override_replaces_default() -> None:
    # Replace the default entirely: `anon` is no longer flagged, `webuser` is.
    options = {"anon_roles": ["webuser"]}
    assert SEC039().check(_wrap(_policy(command="INSERT", roles=("anon",))), options) == []
    assert len(SEC039().check(_wrap(_policy(command="INSERT", roles=("webuser",))), options)) == 1


def test_allowlist_exempts_specific_policy() -> None:
    schema = _wrap(_policy(command="INSERT", name="legacy_anon_insert"))
    options = {"allowlist": ["public.t.legacy_anon_insert"]}
    assert SEC039().check(schema, options) == []


def test_rejects_malformed_anon_roles_option() -> None:
    with pytest.raises(TypeError) as exc:
        SEC039().check(_wrap(_policy(command="INSERT")), {"anon_roles": "anon"})
    assert "role-name" in str(exc.value)
