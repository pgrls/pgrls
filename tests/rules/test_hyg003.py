"""Unit tests for HYG003 — duplicate / redundant policy on a table.

HYG003 (info) fires when two policies on one table are identical
in everything but their name — same command, role set, permissive
flag, and USING / WITH CHECK predicates. The name-sorted-first
policy is treated as the original; the rest are flagged redundant.
"""
from __future__ import annotations

import pytest

from pgrls.model import Policy, Schema, Table
from pgrls.rules.hyg003 import HYG003


def _policy(
    name: str,
    *,
    command: str = "ALL",
    permissive: bool = True,
    roles: tuple[str, ...] = ("app",),
    using: str | None = "tenant_id = 1",
    with_check: str | None = None,
) -> Policy:
    return Policy(
        name=name,
        command=command,  # type: ignore[arg-type]
        permissive=permissive,
        roles=roles,
        using_sql=using,
        with_check_sql=with_check,
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
                columns=("id", "tenant_id"),
            ),
        )
    )


def _table(name: str, *policies: Policy) -> Table:
    return Table(
        schema="public",
        name=name,
        rls_enabled=True,
        force_rls=True,
        policies=policies,
        columns=("id", "tenant_id"),
    )


# --- fires ---------------------------------------------------------------


def test_hyg003_fires_on_two_identical_policies() -> None:
    schema = _wrap(_policy("alpha"), _policy("beta"))
    [v] = HYG003().check(schema, {})
    assert v.rule_id == "HYG003"
    assert v.severity == "info"
    # The name-sorted-first ("alpha") is the original; "beta" flagged.
    assert v.location == "public.t.beta"
    assert "alpha" in v.message
    assert "[lint.rules.HYG003]" in v.message


def test_hyg003_flags_all_but_the_first_of_three() -> None:
    schema = _wrap(_policy("a"), _policy("b"), _policy("c"))
    locations = sorted(v.location for v in HYG003().check(schema, {}))
    assert locations == ["public.t.b", "public.t.c"]


def test_hyg003_fires_on_identical_policies_with_with_check() -> None:
    schema = _wrap(
        _policy("p1", with_check="tenant_id = 1"),
        _policy("p2", with_check="tenant_id = 1"),
    )
    assert len(HYG003().check(schema, {})) == 1


def test_hyg003_roles_compared_as_a_set() -> None:
    # `TO app, admin` and `TO admin, app` are the same role set —
    # a duplicate regardless of the stored tuple order.
    schema = _wrap(
        _policy("p1", roles=("app", "admin")),
        _policy("p2", roles=("admin", "app")),
    )
    assert len(HYG003().check(schema, {})) == 1


def test_hyg003_fires_on_each_table_independently() -> None:
    schema = Schema(
        tables=(
            _table("a", _policy("x"), _policy("y")),
            _table("b", _policy("x"), _policy("y")),
        )
    )
    locations = sorted(v.location for v in HYG003().check(schema, {}))
    assert locations == ["public.a.y", "public.b.y"]


# --- silent --------------------------------------------------------------


def test_hyg003_silent_on_single_policy() -> None:
    assert HYG003().check(_wrap(_policy("only")), {}) == []


def test_hyg003_silent_on_distinct_using_predicates() -> None:
    schema = _wrap(
        _policy("p1", using="tenant_id = 1"),
        _policy("p2", using="tenant_id = 2"),
    )
    assert HYG003().check(schema, {}) == []


def test_hyg003_silent_when_command_differs() -> None:
    schema = _wrap(
        _policy("p1", command="SELECT"),
        _policy("p2", command="UPDATE"),
    )
    assert HYG003().check(schema, {}) == []


def test_hyg003_silent_when_permissive_differs() -> None:
    # A permissive + restrictive pair with the same predicate is
    # NOT redundant — they do different things.
    schema = _wrap(
        _policy("p1", permissive=True),
        _policy("p2", permissive=False),
    )
    assert HYG003().check(schema, {}) == []


def test_hyg003_silent_when_roles_differ() -> None:
    schema = _wrap(
        _policy("p1", roles=("app",)),
        _policy("p2", roles=("admin",)),
    )
    assert HYG003().check(schema, {}) == []


def test_hyg003_silent_when_with_check_differs() -> None:
    schema = _wrap(
        _policy("p1", with_check="tenant_id = 1"),
        _policy("p2", with_check="tenant_id = 2"),
    )
    assert HYG003().check(schema, {}) == []


def test_hyg003_silent_when_no_policies() -> None:
    schema = Schema(tables=(_table("t"),))
    assert HYG003().check(schema, {}) == []


# --- allowlist / metadata ------------------------------------------------


def test_hyg003_allowlist_exempts_the_redundant_policy_id() -> None:
    schema = _wrap(_policy("alpha"), _policy("beta"))
    assert HYG003().check(schema, {"allowlist": ["public.t.beta"]}) == []


def test_hyg003_bad_allowlist_type_raises_clearly() -> None:
    schema = _wrap(_policy("alpha"), _policy("beta"))
    with pytest.raises(TypeError, match="allowlist"):
        HYG003().check(schema, {"allowlist": "public.t.beta"})  # type: ignore[dict-item]


def test_hyg003_metadata_present() -> None:
    rule = HYG003()
    assert rule.id == "HYG003"
    assert rule.severity == "info"
    assert rule.title
