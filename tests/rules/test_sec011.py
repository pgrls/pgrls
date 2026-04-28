"""Unit tests for SEC011 — `OR true` branch hidden in policy USING."""
from __future__ import annotations

import pytest

from pgrls.ast_utils import parse_expr
from pgrls.model import Policy, Schema, Table
from pgrls.rules.sec011 import SEC011


def _policy(
    using: str | None,
    *,
    name: str = "p",
    command: str = "SELECT",
) -> Policy:
    return Policy(
        name=name,
        command=command,  # type: ignore[arg-type]
        permissive=True,
        roles=("PUBLIC",),
        using_sql=using,
        with_check_sql=None,
        using_ast=parse_expr(using) if using else None,
        with_check_ast=None,
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


def test_sec011_fires_on_simple_or_true() -> None:
    schema = _wrap(_policy("id = 1 OR true"))
    violations = SEC011().check(schema, {})
    assert len(violations) == 1
    v = violations[0]
    assert v.rule_id == "SEC011"
    assert v.severity == "warning"
    assert v.location == "public.t.p"
    assert "OR true" in v.message or "true" in v.message.lower()


def test_sec011_fires_on_nested_or_true() -> None:
    # `OR true` buried inside an outer AND. The walk descends into
    # every BoolExpr.
    schema = _wrap(_policy("id = 1 AND (id = 2 OR true)"))
    assert len(SEC011().check(schema, {})) == 1


def test_sec011_silent_on_clean_or() -> None:
    schema = _wrap(_policy("id = 1 OR id = 2"))
    assert SEC011().check(schema, {}) == []


def test_sec011_silent_on_top_level_literal_true_alone() -> None:
    # `USING (true)` is SEC008's territory, not SEC011's. SEC011
    # specifically looks for the OR-with-true *combination* — a
    # bare literal at the top level isn't an OR branch.
    schema = _wrap(_policy("true"))
    assert SEC011().check(schema, {}) == []


def test_sec011_silent_when_using_is_none() -> None:
    schema = _wrap(_policy(None, command="INSERT"))
    assert SEC011().check(schema, {}) == []


def test_sec011_silent_on_or_with_complex_predicates() -> None:
    # `OR id IS NULL` is a real predicate, not literal true.
    # `1 = 1` is a tautology but not the literal A_Const(true).
    # SEC011's detection is narrow on purpose — semantic-equivalent
    # tautologies fall to SEC005's "no own-col" framing instead.
    schema = _wrap(_policy("id = 1 OR id IS NULL"))
    assert SEC011().check(schema, {}) == []
    schema = _wrap(_policy("id = 1 OR 1 = 1"))
    assert SEC011().check(schema, {}) == []


def test_sec011_fires_when_or_true_is_in_with_check() -> None:
    p = Policy(
        name="p",
        command="ALL",
        permissive=True,
        roles=("PUBLIC",),
        using_sql="id = 1",
        with_check_sql="id = 1 OR true",
        using_ast=parse_expr("id = 1"),
        with_check_ast=parse_expr("id = 1 OR true"),
    )
    schema = _wrap(p)
    violations = SEC011().check(schema, {})
    assert len(violations) == 1


def test_sec011_allowlist_exempts_qualified_policy_id() -> None:
    schema = _wrap(_policy("id = 1 OR true"))
    options = {"allowlist": ["public.t.p"]}
    assert SEC011().check(schema, options) == []


def test_sec011_bad_allowlist_type_raises_clearly() -> None:
    schema = _wrap(_policy("id = 1 OR true"))
    with pytest.raises(TypeError, match="allowlist"):
        SEC011().check(schema, {"allowlist": "public.t.p"})  # type: ignore[dict-item]


def test_sec011_fires_once_per_offending_policy() -> None:
    # Two OR-true branches in one expression → still ONE violation
    # for the policy. The rule is "this policy contains the
    # pattern", not "count occurrences".
    schema = _wrap(_policy("(id = 1 OR true) AND (id = 2 OR true)"))
    assert len(SEC011().check(schema, {})) == 1


def test_sec011_fires_on_each_offending_policy_independently() -> None:
    schema = Schema(
        tables=(
            Table(
                schema="public",
                name="t",
                rls_enabled=True,
                force_rls=True,
                columns=("id",),
                policies=(
                    _policy("id = 1 OR true", name="bad_a"),
                    _policy("id = 1 OR id = 2", name="ok"),
                    _policy("id = 1 AND (id = 2 OR true)", name="bad_b"),
                ),
            ),
        )
    )
    locations = sorted(v.location for v in SEC011().check(schema, {}))
    assert locations == ["public.t.bad_a", "public.t.bad_b"]


def test_sec011_metadata_present() -> None:
    rule = SEC011()
    assert rule.id == "SEC011"
    assert rule.severity == "warning"
    assert rule.title
