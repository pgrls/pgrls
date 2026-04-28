"""Unit tests for SEC008 — `USING (true)`."""
from __future__ import annotations

import pytest

from pgrls.ast_utils import parse_expr
from pgrls.model import Policy, Schema, Table
from pgrls.rules.sec008 import SEC008


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
                columns=("id",),
            ),
        )
    )


def test_sec008_fires_on_using_true_lowercase() -> None:
    schema = _wrap(_policy("true"))
    violations = SEC008().check(schema, {})
    assert len(violations) == 1
    assert violations[0].rule_id == "SEC008"
    assert violations[0].location == "public.t.p"


def test_sec008_fires_on_using_true_uppercase() -> None:
    schema = _wrap(_policy("TRUE"))
    assert len(SEC008().check(schema, {})) == 1


def test_sec008_fires_on_double_paren_true() -> None:
    # Pglast typically elides parens, but be defensive — many ORMs
    # generate ((true)).
    schema = _wrap(_policy("((true))"))
    assert len(SEC008().check(schema, {})) == 1


def test_sec008_does_not_fire_on_using_false() -> None:
    schema = _wrap(_policy("false"))
    assert SEC008().check(schema, {}) == []


def test_sec008_does_not_fire_on_one_eq_one_tautology() -> None:
    # By design, the rule is narrowly lexical — semantic tautologies
    # like `1=1` are out of scope.
    schema = _wrap(_policy("1 = 1"))
    assert SEC008().check(schema, {}) == []


def test_sec008_does_not_fire_on_real_predicate() -> None:
    schema = _wrap(_policy("id IS NOT NULL"))
    assert SEC008().check(schema, {}) == []


def test_sec008_does_not_fire_when_using_is_none() -> None:
    # INSERT-only policies have no USING — rule must skip cleanly.
    schema = _wrap(_policy(None, command="INSERT", with_check="true"))
    assert SEC008().check(schema, {}) == []


def test_sec008_does_not_fire_on_with_check_true_alone() -> None:
    # Rule is USING-only by design.
    schema = _wrap(
        _policy(None, command="INSERT", with_check="true")
    )
    assert SEC008().check(schema, {}) == []


def test_sec008_allowlist_exempts_qualified_policy_id() -> None:
    schema = _wrap(_policy("true"))
    assert SEC008().check(schema, {"allowlist": ["public.t.p"]}) == []


def test_sec008_bad_allowlist_type_raises_clearly() -> None:
    schema = _wrap(_policy("true"))
    with pytest.raises(TypeError, match="allowlist"):
        SEC008().check(schema, {"allowlist": "public.t.p"})  # type: ignore[dict-item]


def test_sec008_bad_allowlist_item_type_raises_clearly() -> None:
    schema = _wrap(_policy("true"))
    with pytest.raises(TypeError, match="allowlist"):
        SEC008().check(schema, {"allowlist": ["public.t.p", 0]})  # type: ignore[list-item]


def test_sec008_fires_on_each_offending_policy_independently() -> None:
    schema = Schema(
        tables=(
            Table(
                schema="public",
                name="t",
                rls_enabled=True,
                force_rls=True,
                columns=("id",),
                policies=(
                    _policy("true", name="bad_a"),
                    _policy("id IS NOT NULL", name="good"),
                    _policy("TRUE", name="bad_b"),
                ),
            ),
        )
    )
    locations = sorted(v.location for v in SEC008().check(schema, {}))
    assert locations == ["public.t.bad_a", "public.t.bad_b"]
