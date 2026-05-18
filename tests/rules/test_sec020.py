"""Unit tests for SEC020 — WITH CHECK (true) alongside a restrictive USING.

SEC020 (warning) fires when a policy has both a USING and a WITH
CHECK clause, the USING clause is a real predicate, and the WITH
CHECK clause is the literal `true`. That asymmetry lets a caller
write rows its USING clause would never let it read.
"""
from __future__ import annotations

import pytest

from pgrls.ast_utils import parse_expr
from pgrls.model import Policy, Schema, Table
from pgrls.rules.sec020 import SEC020


def _policy(
    using: str | None = None,
    *,
    name: str = "p",
    command: str = "ALL",
    with_check: str | None = None,
) -> Policy:
    return Policy(
        name=name,
        command=command,  # type: ignore[arg-type]
        permissive=True,
        roles=("app",),
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
                columns=("id", "tenant_id"),
            ),
        )
    )


# --- fires ---------------------------------------------------------------


def test_sec020_fires_on_with_check_true_with_restrictive_using() -> None:
    schema = _wrap(_policy("tenant_id = 1", with_check="true"))
    [v] = SEC020().check(schema, {})
    assert v.rule_id == "SEC020"
    assert v.severity == "warning"
    assert v.location == "public.t.p"
    assert "WITH CHECK" in v.message
    assert "[lint.rules.SEC020]" in v.message


def test_sec020_fires_on_with_check_true_uppercase() -> None:
    schema = _wrap(_policy("tenant_id = 1", with_check="TRUE"))
    assert len(SEC020().check(schema, {})) == 1


def test_sec020_fires_on_double_paren_with_check_true() -> None:
    # Pglast usually elides parens; many ORMs emit ((true)).
    schema = _wrap(_policy("tenant_id = 1", with_check="((true))"))
    assert len(SEC020().check(schema, {})) == 1


def test_sec020_fires_on_for_update_policy() -> None:
    # A FOR UPDATE policy carries both clauses; WITH CHECK (true)
    # there lets the caller move a row it owns to another tenant.
    schema = _wrap(
        _policy("tenant_id = 1", command="UPDATE", with_check="true")
    )
    assert len(SEC020().check(schema, {})) == 1


def test_sec020_fires_on_each_offending_policy_independently() -> None:
    schema = Schema(
        tables=(
            Table(
                schema="public",
                name="t",
                rls_enabled=True,
                force_rls=True,
                columns=("id", "tenant_id"),
                policies=(
                    _policy(
                        "tenant_id = 1", name="bad_a", with_check="true"
                    ),
                    _policy(
                        "tenant_id = 1",
                        name="good",
                        with_check="tenant_id = 1",
                    ),
                    _policy(
                        "tenant_id = 2", name="bad_b", with_check="TRUE"
                    ),
                ),
            ),
        )
    )
    locations = sorted(v.location for v in SEC020().check(schema, {}))
    assert locations == ["public.t.bad_a", "public.t.bad_b"]


# --- silent --------------------------------------------------------------


def test_sec020_silent_when_with_check_mirrors_using() -> None:
    # WITH CHECK is a real predicate — read and write sides match.
    schema = _wrap(_policy("tenant_id = 1", with_check="tenant_id = 1"))
    assert SEC020().check(schema, {}) == []


def test_sec020_silent_when_with_check_omitted() -> None:
    # No explicit WITH CHECK — Postgres reuses USING. That is SEC006's
    # concern (missing WITH CHECK), not SEC020's.
    schema = _wrap(_policy("tenant_id = 1"))
    assert SEC020().check(schema, {}) == []


def test_sec020_silent_when_using_is_constant_true() -> None:
    # USING (true) + WITH CHECK (true) is a fully-open policy — no
    # asymmetry. SEC008 owns the constant-true USING; SEC020 needs a
    # real USING for the gap to exist.
    schema = _wrap(_policy("true", with_check="true"))
    assert SEC020().check(schema, {}) == []


def test_sec020_silent_when_using_omitted() -> None:
    # A FOR INSERT policy has no USING — no read side to diverge from.
    schema = _wrap(_policy(None, command="INSERT", with_check="true"))
    assert SEC020().check(schema, {}) == []


def test_sec020_silent_on_with_check_false() -> None:
    schema = _wrap(_policy("tenant_id = 1", with_check="false"))
    assert SEC020().check(schema, {}) == []


def test_sec020_silent_on_with_check_one_eq_one_tautology() -> None:
    # Deliberately narrow, mirroring SEC008: only the literal `true`
    # matches. Semantic tautologies like `1 = 1` are out of scope.
    schema = _wrap(_policy("tenant_id = 1", with_check="1 = 1"))
    assert SEC020().check(schema, {}) == []


def test_sec020_silent_when_policy_has_no_clauses() -> None:
    schema = _wrap(_policy(using=None, with_check=None))
    assert SEC020().check(schema, {}) == []


# --- allowlist / metadata ------------------------------------------------


def test_sec020_allowlist_exempts_qualified_policy_id() -> None:
    schema = _wrap(_policy("tenant_id = 1", with_check="true"))
    assert SEC020().check(schema, {"allowlist": ["public.t.p"]}) == []


def test_sec020_bad_allowlist_type_raises_clearly() -> None:
    schema = _wrap(_policy("tenant_id = 1", with_check="true"))
    with pytest.raises(TypeError, match="allowlist"):
        SEC020().check(schema, {"allowlist": "public.t.p"})  # type: ignore[dict-item]


def test_sec020_message_explains_fix() -> None:
    schema = _wrap(_policy("tenant_id = 1", with_check="true"))
    [v] = SEC020().check(schema, {})
    assert "Mirror the USING" in v.message
    assert "allowlist" in v.message


def test_sec020_metadata_present() -> None:
    rule = SEC020()
    assert rule.id == "SEC020"
    assert rule.severity == "warning"
    assert rule.title
