"""Unit tests for SEC004 — inverted auth check (Lovable CVE pattern)."""
from __future__ import annotations

from pgrls.ast_utils import parse_expr
from pgrls.model import Policy, Schema, Table
from pgrls.rules.sec004 import SEC004


def _policy_with_using(using: str) -> Policy:
    return Policy(
        name="p",
        command="SELECT",
        permissive=True,
        roles=("authenticated",),
        using_sql=using,
        with_check_sql=None,
        using_ast=parse_expr(using),
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
            ),
        )
    )


def test_sec004_fires_on_auth_uid_is_null_disjunct() -> None:
    schema = _wrap(
        _policy_with_using("auth.uid() IS NULL OR user_id = '1'")
    )
    violations = SEC004().check(schema, {})
    assert len(violations) == 1
    assert violations[0].rule_id == "SEC004"
    assert violations[0].location == "public.t.p"


def test_sec004_fires_on_current_setting_is_null_disjunct() -> None:
    schema = _wrap(
        _policy_with_using(
            "current_setting('jwt.uid', true) IS NULL OR user_id = '1'"
        )
    )
    assert len(SEC004().check(schema, {})) == 1


def test_sec004_fires_on_current_user_is_null_disjunct() -> None:
    schema = _wrap(
        _policy_with_using("current_user IS NULL OR user_id = '1'")
    )
    assert len(SEC004().check(schema, {})) == 1


def test_sec004_does_not_fire_on_is_not_null() -> None:
    schema = _wrap(
        _policy_with_using("auth.uid() IS NOT NULL AND user_id = '1'")
    )
    assert SEC004().check(schema, {}) == []


def test_sec004_does_not_fire_on_plain_equality() -> None:
    schema = _wrap(_policy_with_using("auth.uid() = user_id"))
    assert SEC004().check(schema, {}) == []


def test_sec004_does_not_fire_on_coalesce_wrapper() -> None:
    # Documented blind spot — coalesce variants aren't shaped as IS NULL.
    schema = _wrap(
        _policy_with_using(
            "coalesce(auth.uid(), '') = '' OR user_id = '1'"
        )
    )
    assert SEC004().check(schema, {}) == []


def test_sec004_does_not_fire_when_only_inside_subquery() -> None:
    # Subquery-internal IS NULL is not a top-level disjunct.
    schema = _wrap(
        _policy_with_using(
            "user_id IN (SELECT id FROM users WHERE auth.uid() IS NULL)"
        )
    )
    assert SEC004().check(schema, {}) == []


def test_sec004_skips_policy_without_using_ast() -> None:
    schema = _wrap(
        Policy(
            name="p",
            command="SELECT",
            permissive=True,
            roles=("authenticated",),
            using_sql=None,
            with_check_sql=None,
            using_ast=None,
        )
    )
    assert SEC004().check(schema, {}) == []


def test_sec004_auth_functions_config_overrides_default() -> None:
    schema = _wrap(
        _policy_with_using("auth.uid() IS NULL OR user_id = '1'")
    )
    # Override removes auth.uid from the auth set; rule should not fire.
    assert SEC004().check(
        schema, {"auth_functions": ["my.custom_auth"]}
    ) == []


def test_sec004_bad_auth_functions_type_raises_clearly() -> None:
    import pytest
    schema = _wrap(_policy_with_using("auth.uid() IS NULL OR a = 1"))
    with pytest.raises(TypeError, match="auth_functions"):
        SEC004().check(
            schema, {"auth_functions": "auth.uid"}  # type: ignore[dict-item]
        )
