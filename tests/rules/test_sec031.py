"""Unit tests for SEC031 — restrictive policy with constant-true USING.

SEC031 (warning) fires for a RESTRICTIVE policy whose USING is the
literal `true`. Restrictive policies AND-combine, so `USING (true)` is
a no-op floor — it looks like a security boundary but enforces none.
It is the restrictive counterpart of SEC008 (permissive USING true);
the two are disjoint by policy kind.
"""
from __future__ import annotations

import pytest

from pgrls.ast_utils import parse_expr
from pgrls.model import Policy, Schema, Table
from pgrls.rules.sec031 import SEC031


def _policy(
    using: str | None,
    *,
    name: str = "p",
    permissive: bool = False,
    with_check: str | None = None,
) -> Policy:
    return Policy(
        name=name,
        command="SELECT",
        permissive=permissive,
        roles=("PUBLIC",),
        using_sql=using,
        with_check_sql=with_check,
        using_ast=parse_expr(using) if using else None,
        with_check_ast=parse_expr(with_check) if with_check else None,
    )


def _wrap(*policies: Policy) -> Schema:
    return Schema(
        tables=(
            Table(
                schema="public",
                name="t",
                rls_enabled=True,
                force_rls=True,
                policies=policies,
                columns=("id",),
            ),
        )
    )


def test_sec031_fires_on_restrictive_using_true() -> None:
    [v] = SEC031().check(_wrap(_policy("true")), {})
    assert v.rule_id == "SEC031"
    assert v.severity == "warning"
    assert v.location == "public.t.p"
    assert "restrict" in v.message.lower()


def test_sec031_fires_on_uppercase_and_double_paren_true() -> None:
    assert len(SEC031().check(_wrap(_policy("TRUE")), {})) == 1
    assert len(SEC031().check(_wrap(_policy("((true))")), {})) == 1


def test_sec031_does_not_fire_on_permissive_using_true() -> None:
    # Permissive USING (true) is SEC008's "admits every row" case.
    assert SEC031().check(_wrap(_policy("true", permissive=True)), {}) == []


def test_sec031_does_not_fire_on_real_restrictive_predicate() -> None:
    schema = _wrap(_policy("tenant_id = current_setting('app.t')"))
    assert SEC031().check(schema, {}) == []


def test_sec031_does_not_fire_on_using_false() -> None:
    assert SEC031().check(_wrap(_policy("false")), {}) == []


def test_sec031_does_not_fire_on_restrictive_with_check_true_alone() -> None:
    # A restrictive WITH CHECK (true) with a real USING is not a
    # no-op read floor — SEC031 inspects USING only.
    schema = _wrap(_policy("tenant_id = 1", with_check="true"))
    assert SEC031().check(schema, {}) == []


def test_sec031_does_not_fire_when_using_is_none() -> None:
    assert SEC031().check(_wrap(_policy(None, with_check="true")), {}) == []


def test_sec031_allowlist_exempts_qualified_policy_id() -> None:
    schema = _wrap(_policy("true"))
    assert (
        SEC031().check(schema, {"allowlist": ["public.t.p"]}) == []
    )


def test_sec031_bad_allowlist_type_raises_clearly() -> None:
    with pytest.raises(TypeError):
        SEC031().check(_wrap(_policy("true")), {"allowlist": "public.t.p"})


def test_sec031_fires_per_offending_policy() -> None:
    schema = _wrap(
        _policy("true", name="floor_a"),
        _policy("true", name="floor_b"),
        _policy("tenant_id = 1", name="real"),
    )
    locs = {v.location for v in SEC031().check(schema, {})}
    assert locs == {"public.t.floor_a", "public.t.floor_b"}
