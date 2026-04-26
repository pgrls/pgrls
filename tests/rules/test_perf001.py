"""Unit tests for PERF001 — unwrapped auth function in USING."""
from __future__ import annotations

import pytest

from pgrls.ast_utils import parse_expr
from pgrls.model import Policy, Schema, Table
from pgrls.rules.perf001 import PERF001


def _policy(
    using: str | None,
    *,
    name: str = "p",
    command: str = "SELECT",
    with_check: str | None = None,
) -> Policy:
    return Policy(
        name=name,
        command=command,  # type: ignore[arg-type]
        permissive=True,
        roles=("authenticated",),
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
                columns=("id", "user_id"),
            ),
        )
    )


def test_perf001_fires_on_unwrapped_auth_uid() -> None:
    schema = _wrap(_policy("auth.uid() = user_id"))
    violations = PERF001().check(schema, {})
    assert len(violations) == 1
    assert violations[0].rule_id == "PERF001"
    assert violations[0].location == "public.t.p"


def test_perf001_does_not_fire_on_wrapped_auth_uid() -> None:
    schema = _wrap(_policy("(SELECT auth.uid()) = user_id"))
    assert PERF001().check(schema, {}) == []


def test_perf001_does_not_fire_on_in_subquery_wrap() -> None:
    # Any SubLink ancestor counts as wrapped — IN/EXISTS work too.
    schema = _wrap(_policy("user_id IN (SELECT auth.uid())"))
    assert PERF001().check(schema, {}) == []


def test_perf001_fires_on_unwrapped_current_setting() -> None:
    schema = _wrap(
        _policy("current_setting('app.user') = user_id")
    )
    assert len(PERF001().check(schema, {})) == 1


def test_perf001_does_not_fire_on_current_user() -> None:
    # current_user is in SEC004's set but NOT PERF001's default — Postgres
    # evaluates the SQLValueFunction cheaply, so wrapping buys nothing.
    schema = _wrap(_policy("current_user = 'admin'"))
    assert PERF001().check(schema, {}) == []


def test_perf001_does_not_fire_on_session_user() -> None:
    schema = _wrap(_policy("session_user = 'admin'"))
    assert PERF001().check(schema, {}) == []


def test_perf001_emits_only_one_violation_per_policy() -> None:
    # Multiple unwrapped calls in one policy → still one violation.
    schema = _wrap(
        _policy(
            "auth.uid() = user_id OR auth.uid() IS NULL"
        )
    )
    assert len(PERF001().check(schema, {})) == 1


def test_perf001_does_not_fire_on_with_check_only() -> None:
    # Rule is USING-only by design.
    schema = _wrap(
        _policy(
            None,
            command="INSERT",
            with_check="auth.uid() = user_id",
        )
    )
    assert PERF001().check(schema, {}) == []


def test_perf001_does_not_fire_when_using_is_none() -> None:
    schema = _wrap(_policy(None, command="INSERT", with_check="true"))
    assert PERF001().check(schema, {}) == []


def test_perf001_default_set_covers_auth_role() -> None:
    schema = _wrap(_policy("auth.role() = 'admin'"))
    assert len(PERF001().check(schema, {})) == 1


def test_perf001_default_set_covers_auth_jwt() -> None:
    schema = _wrap(_policy("auth.jwt() ->> 'sub' = '1'"))
    assert len(PERF001().check(schema, {})) == 1


def test_perf001_allowlist_exempts_qualified_policy_id() -> None:
    schema = _wrap(_policy("auth.uid() = user_id"))
    assert PERF001().check(
        schema, {"allowlist": ["public.t.p"]}
    ) == []


def test_perf001_auth_functions_override_replaces_default() -> None:
    # Override = replace, not extend. auth.uid is gone unless re-listed.
    schema = _wrap(_policy("auth.uid() = user_id"))
    options = {"auth_functions": ["my.custom"]}
    assert PERF001().check(schema, options) == []


def test_perf001_auth_functions_override_finds_custom_func() -> None:
    schema = _wrap(_policy("my.custom() = user_id"))
    options = {"auth_functions": ["my.custom"]}
    assert len(PERF001().check(schema, options)) == 1


def test_perf001_empty_auth_functions_never_fires() -> None:
    schema = _wrap(_policy("auth.uid() = user_id"))
    assert PERF001().check(schema, {"auth_functions": []}) == []


def test_perf001_bad_allowlist_type_raises_clearly() -> None:
    schema = _wrap(_policy("auth.uid() = user_id"))
    with pytest.raises(TypeError, match="allowlist"):
        PERF001().check(schema, {"allowlist": "public.t.p"})  # type: ignore[dict-item]


def test_perf001_bad_auth_functions_type_raises_clearly() -> None:
    schema = _wrap(_policy("auth.uid() = user_id"))
    with pytest.raises(TypeError, match="auth_functions"):
        PERF001().check(schema, {"auth_functions": "auth.uid"})  # type: ignore[dict-item]


def test_perf001_bad_auth_functions_item_type_raises_clearly() -> None:
    schema = _wrap(_policy("auth.uid() = user_id"))
    with pytest.raises(TypeError, match="auth_functions"):
        PERF001().check(
            schema, {"auth_functions": ["auth.uid", 42]}  # type: ignore[list-item]
        )


def test_perf001_fires_on_each_offending_policy_independently() -> None:
    schema = Schema(
        tables=(
            Table(
                schema="public",
                name="t",
                rls_enabled=True,
                force_rls=True,
                columns=("id", "user_id"),
                policies=(
                    _policy("auth.uid() = user_id", name="bad_a"),
                    _policy(
                        "(SELECT auth.uid()) = user_id", name="good"
                    ),
                    _policy(
                        "current_setting('app.u') = user_id",
                        name="bad_b",
                    ),
                ),
            ),
        )
    )
    locations = sorted(v.location for v in PERF001().check(schema, {}))
    assert locations == ["public.t.bad_a", "public.t.bad_b"]
