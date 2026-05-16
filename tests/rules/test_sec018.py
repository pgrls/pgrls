"""Unit tests for SEC018 — current_user / session_user in a policy.

SEC018 flags policies whose USING / WITH CHECK expression keys off
`current_user` (or its `current_role` / `user` aliases) or
`session_user`. Those identify the session's Postgres role, which
isolates tenants only under a role-per-tenant deployment — pooled
application code shares one role, so the predicate is a constant.
"""
from __future__ import annotations

import pytest

from pgrls.ast_utils import parse_expr
from pgrls.model import Policy, Schema, Table
from pgrls.rules.sec018 import SEC018


def _policy(
    using: str | None = None,
    *,
    name: str = "p",
    command: str = "SELECT",
    with_check: str | None = None,
) -> Policy:
    return Policy(
        name=name,
        command=command,  # type: ignore[arg-type]
        permissive=True,
        roles=("PUBLIC",),
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
                columns=("id", "owner_role"),
            ),
        )
    )


def test_sec018_fires_on_current_user_in_using() -> None:
    schema = _wrap(_policy("owner_role = current_user"))
    [v] = SEC018().check(schema, {})
    assert v.rule_id == "SEC018"
    assert v.severity == "warning"
    assert v.location == "public.t.p"
    assert "current_user" in v.message
    assert "[lint.rules.SEC018]" in v.message


def test_sec018_fires_on_session_user() -> None:
    schema = _wrap(_policy("owner_role = session_user"))
    assert len(SEC018().check(schema, {})) == 1


def test_sec018_fires_on_current_role_alias() -> None:
    # `current_role` is a spelling of `current_user`.
    schema = _wrap(_policy("owner_role = current_role"))
    assert len(SEC018().check(schema, {})) == 1


def test_sec018_fires_on_user_keyword_alias() -> None:
    # The bare `user` keyword is also `current_user` — Postgres
    # parses it as the same SQLValueFunction.
    schema = _wrap(_policy("owner_role = user"))
    assert len(SEC018().check(schema, {})) == 1


def test_sec018_fires_when_only_in_with_check() -> None:
    p = _policy(with_check="owner_role = current_user", command="INSERT")
    assert len(SEC018().check(_wrap(p), {})) == 1


def test_sec018_fires_on_current_user_inside_subquery() -> None:
    # A current_user reference nested in a sub-select still makes
    # the policy role-identity-based — find_func_calls walks
    # subselects by default, so SEC018 catches it.
    schema = _wrap(
        _policy("id IN (SELECT doc_id FROM acl WHERE grantee = current_user)")
    )
    assert len(SEC018().check(schema, {})) == 1


def test_sec018_silent_on_current_setting_policy() -> None:
    # The recommended pattern — a per-request session GUC — must
    # NOT fire. This is exactly what SEC018 steers operators toward.
    schema = _wrap(
        _policy("owner_role = current_setting('app.tenant_id')")
    )
    assert SEC018().check(schema, {}) == []


def test_sec018_silent_on_plain_column_predicate() -> None:
    schema = _wrap(_policy("id = 1"))
    assert SEC018().check(schema, {}) == []


def test_sec018_allowlist_exempts_qualified_policy_id() -> None:
    # Role-per-tenant deployments legitimately key off current_user;
    # the allowlist is how they silence SEC018 after confirming the
    # deployment model.
    schema = _wrap(_policy("owner_role = current_user"))
    assert SEC018().check(schema, {"allowlist": ["public.t.p"]}) == []


def test_sec018_fires_once_per_policy_with_multiple_references() -> None:
    schema = _wrap(
        _policy("owner_role = current_user OR editor_role = current_user")
    )
    assert len(SEC018().check(schema, {})) == 1


def test_sec018_fires_on_each_offending_policy_independently() -> None:
    schema = Schema(
        tables=(
            Table(
                schema="public",
                name="t",
                rls_enabled=True,
                force_rls=True,
                columns=("id", "owner_role"),
                policies=(
                    _policy("owner_role = current_user", name="bad_a"),
                    _policy("id = 1", name="ok"),
                    _policy("owner_role = session_user", name="bad_b"),
                ),
            ),
        )
    )
    locations = sorted(v.location for v in SEC018().check(schema, {}))
    assert locations == ["public.t.bad_a", "public.t.bad_b"]


def test_sec018_bad_allowlist_type_raises_clearly() -> None:
    schema = _wrap(_policy("owner_role = current_user"))
    with pytest.raises(TypeError, match="allowlist"):
        SEC018().check(schema, {"allowlist": "public.t.p"})  # type: ignore[dict-item]


def test_sec018_message_recommends_session_guc() -> None:
    # The message must point operators at the fix (a session GUC /
    # JWT claim) and acknowledge the role-per-tenant exception.
    schema = _wrap(_policy("owner_role = current_user"))
    [v] = SEC018().check(schema, {})
    assert "current_setting" in v.message
    assert "role-per-tenant" in v.message


def test_sec018_metadata_present() -> None:
    rule = SEC018()
    assert rule.id == "SEC018"
    assert rule.severity == "warning"
    assert rule.title
