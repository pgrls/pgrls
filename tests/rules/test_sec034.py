"""Unit tests for SEC034.

SEC034 (warning) fires when a policy's USING / WITH CHECK
expression contains an `auth.email()` call (or any configured
email-context function). The hazard is silent denial of service —
email-based scoping breaks on email change, case differences, and
plus-addressing — not privilege escalation, hence warning rather
than error. Allowlist exists for audit / display-only cases.
"""
from __future__ import annotations

import pytest

from pgrls.ast_utils import parse_expr
from pgrls.model import Policy, Schema, Table
from pgrls.rules.sec034 import SEC034


def _policy(
    using: str | None = None,
    *,
    name: str = "p",
    command: str = "SELECT",
    with_check: str | None = None,
    roles: tuple[str, ...] = ("authenticated",),
) -> Policy:
    return Policy(
        name=name,
        command=command,  # type: ignore[arg-type]
        permissive=True,
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
                columns=("id", "owner_email", "body"),
            ),
        )
    )


# ──────────────────────────────────────────────────────────────────────
# Fires — auth.email() referenced in policy
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "expr",
    [
        # Direct equality (the canonical bad shape)
        "owner_email = auth.email()",
        "auth.email() = owner_email",
        # PERF-friendly wrap doesn't change the hazard
        "owner_email = (SELECT auth.email())",
        # Top-level boolean — still references auth.email()
        "owner_email = auth.email() AND deleted_at IS NULL",
        # Email used in an EXISTS sub-select (the hazard travels with
        # the call site, not the surrounding shape)
        (
            "EXISTS (SELECT 1 FROM auth.users "
            "WHERE id = auth.uid() AND email = auth.email())"
        ),
    ],
)
def test_fires_on_auth_email_call(expr: str) -> None:
    schema = _wrap(_policy(f"({expr})", name="email_scoped"))
    violations = SEC034().check(schema, {})
    assert len(violations) == 1, expr
    assert violations[0].rule_id == "SEC034"
    assert violations[0].severity == "warning"
    assert violations[0].location == "public.t.email_scoped"
    assert "auth.email" in violations[0].message


def test_fires_in_with_check_clause() -> None:
    schema = _wrap(
        _policy(
            command="INSERT",
            with_check="(owner_email = auth.email())",
            name="email_only_insert",
        )
    )
    violations = SEC034().check(schema, {})
    assert len(violations) == 1
    assert violations[0].location == "public.t.email_only_insert"


def test_fires_once_per_policy_with_multiple_auth_email_calls() -> None:
    expr = (
        "owner_email = auth.email() "
        "OR delegate_email = auth.email()"
    )
    schema = _wrap(_policy(f"({expr})", name="dual_email"))
    violations = SEC034().check(schema, {})
    assert len(violations) == 1


# ──────────────────────────────────────────────────────────────────────
# Silent — no auth.email() call; alternatives that are fine
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "expr",
    [
        # The canonical correct shape — scope by uid
        "owner_id = auth.uid()",
        # JWT-claim shape that doesn't read email
        "owner_id = (auth.jwt() ->> 'sub')::uuid",
        # GUC-based scoping
        "owner_id::text = current_setting('app.uid', true)",
        # An `email` column on the same row being read is fine —
        # this is just a column reference, not auth.email()
        "owner_email IS NOT NULL",
        # `auth.uid()` and an email column comparison without
        # auth.email() — silent (we only fire on the FuncCall)
        "owner_id = auth.uid() AND owner_email LIKE '%@example.com'",
    ],
)
def test_silent_on_safe_shapes(expr: str) -> None:
    schema = _wrap(_policy(f"({expr})", name="safe"))
    assert SEC034().check(schema, {}) == [], expr


def test_silent_when_no_policy_predicate() -> None:
    schema = _wrap(_policy(using=None, name="open"))
    assert SEC034().check(schema, {}) == []


# ──────────────────────────────────────────────────────────────────────
# Configuration paths
# ──────────────────────────────────────────────────────────────────────


def test_allowlist_exempts_specific_policy() -> None:
    schema = _wrap(
        _policy(
            "(owner_email = auth.email())",
            name="audit_trail_email",
        )
    )
    options = {"allowlist": ["public.t.audit_trail_email"]}
    assert SEC034().check(schema, options) == []


def test_email_functions_override_replaces_default() -> None:
    # Setting only `app.user_email` means `auth.email()` no longer
    # fires — list-replace, not list-merge.
    schema = _wrap(
        _policy(
            "(owner_email = auth.email())",
            name="default_helper",
        )
    )
    options = {"email_functions": ["app.user_email"]}
    assert SEC034().check(schema, options) == []

    # And the custom helper IS detected when used.
    schema2 = _wrap(
        _policy(
            "(owner_email = app.user_email())",
            name="custom_helper",
        )
    )
    violations = SEC034().check(schema2, options)
    assert len(violations) == 1


def test_email_functions_can_include_multiple_helpers() -> None:
    schema = _wrap(
        _policy(
            "(owner_email = auth.email() OR alt_email = app.user_email())",
            name="dual_helper",
        )
    )
    options = {"email_functions": ["auth.email", "app.user_email"]}
    violations = SEC034().check(schema, options)
    # Still one violation per policy regardless of how many helpers
    # appear (the recommended fix is the same).
    assert len(violations) == 1


def test_rejects_malformed_email_functions_option() -> None:
    with pytest.raises(TypeError) as exc:
        SEC034().check(
            _wrap(_policy("(true)")),
            {"email_functions": "auth.email"},
        )
    assert "list" in str(exc.value)


def test_rejects_email_functions_with_non_string_entry() -> None:
    with pytest.raises(TypeError) as exc:
        SEC034().check(
            _wrap(_policy("(true)")),
            {"email_functions": ["auth.email", 7]},
        )
    assert "function names" in str(exc.value)


# ──────────────────────────────────────────────────────────────────────
# Multi-policy fan-out
# ──────────────────────────────────────────────────────────────────────


def test_emits_one_violation_per_offending_policy() -> None:
    p_bad1 = _policy("(owner_email = auth.email())", name="bad1")
    p_bad2 = _policy(
        "(EXISTS (SELECT 1 FROM auth.users "
        "WHERE id = auth.uid() AND email = auth.email()))",
        name="bad2",
    )
    p_good = _policy("(owner_id = auth.uid())", name="good")
    schema = Schema(
        tables=(
            Table(
                schema="public",
                name="docs",
                rls_enabled=True,
                force_rls=True,
                policies=(p_bad1, p_bad2, p_good),
                columns=("id", "owner_id", "owner_email"),
            ),
        )
    )
    violations = SEC034().check(schema, {})
    assert len(violations) == 2
    assert {v.location for v in violations} == {
        "public.docs.bad1",
        "public.docs.bad2",
    }
