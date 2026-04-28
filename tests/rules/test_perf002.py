"""Unit tests for PERF002 — VOLATILE function used in policy."""
from __future__ import annotations

import pytest

from pgrls.ast_utils import parse_expr
from pgrls.model import Policy, Schema, Table
from pgrls.rules.perf002 import PERF002


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
                columns=("id",),
            ),
        )
    )


def test_perf002_fires_on_random_in_using() -> None:
    schema = _wrap(_policy("random() < 0.5"))
    violations = PERF002().check(schema, {})
    assert len(violations) == 1
    assert violations[0].rule_id == "PERF002"
    assert violations[0].severity == "warning"
    assert violations[0].location == "public.t.p"


def test_perf002_fires_on_clock_timestamp() -> None:
    schema = _wrap(_policy("created_at < clock_timestamp()"))
    assert len(PERF002().check(schema, {})) == 1


def test_perf002_fires_on_nextval() -> None:
    schema = _wrap(_policy("id = nextval('public.s')"))
    assert len(PERF002().check(schema, {})) == 1


def test_perf002_silent_on_now_stable() -> None:
    # `now()` is STABLE (its result is fixed within a transaction).
    # Not in PERF002's volatile set.
    schema = _wrap(_policy("created_at < now()"))
    assert PERF002().check(schema, {}) == []


def test_perf002_silent_on_current_setting() -> None:
    # `current_setting` is STABLE; PERF001's territory, not PERF002's.
    schema = _wrap(_policy("id = current_setting('app.id')::INT"))
    assert PERF002().check(schema, {}) == []


def test_perf002_silent_on_real_predicate() -> None:
    schema = _wrap(_policy("id = 1"))
    assert PERF002().check(schema, {}) == []


def test_perf002_fires_when_volatile_in_with_check_only() -> None:
    # Non-determinism in WITH CHECK is just as bad as in USING —
    # the predicate gates writes inconsistently across rows.
    p = _policy(
        with_check="random() < 0.5",
        command="INSERT",
    )
    schema = _wrap(p)
    assert len(PERF002().check(schema, {})) == 1


def test_perf002_default_set_does_not_include_stable_now() -> None:
    schema = _wrap(_policy("id = 1 AND created_at < now()"))
    assert PERF002().check(schema, {}) == []


def test_perf002_allowlist_exempts_qualified_policy_id() -> None:
    schema = _wrap(_policy("random() < 0.5"))
    options = {"allowlist": ["public.t.p"]}
    assert PERF002().check(schema, options) == []


def test_perf002_volatile_functions_override_replaces_default() -> None:
    # Override REPLACES default (matches PERF001's auth_functions
    # convention). `random` is gone unless re-listed.
    schema = _wrap(_policy("random() < 0.5"))
    out = PERF002().check(schema, {"volatile_functions": ["my.custom"]})
    assert out == []
    # And a custom function gets caught:
    schema2 = _wrap(_policy("id = my.custom()"))
    out2 = PERF002().check(
        schema2, {"volatile_functions": ["my.custom"]}
    )
    assert len(out2) == 1


def test_perf002_empty_volatile_functions_never_fires() -> None:
    schema = _wrap(_policy("random() < 0.5"))
    assert PERF002().check(schema, {"volatile_functions": []}) == []


def test_perf002_bad_allowlist_type_raises_clearly() -> None:
    schema = _wrap(_policy("random() < 0.5"))
    with pytest.raises(TypeError, match="allowlist"):
        PERF002().check(schema, {"allowlist": "public.t.p"})  # type: ignore[dict-item]


def test_perf002_bad_volatile_functions_type_raises_clearly() -> None:
    schema = _wrap(_policy("random() < 0.5"))
    with pytest.raises(TypeError, match="volatile_functions"):
        PERF002().check(schema, {"volatile_functions": "random"})  # type: ignore[dict-item]


def test_perf002_fires_on_each_offending_policy_independently() -> None:
    schema = Schema(
        tables=(
            Table(
                schema="public",
                name="t",
                rls_enabled=True,
                force_rls=True,
                columns=("id",),
                policies=(
                    _policy("random() < 0.5", name="bad_a"),
                    _policy("id = 1", name="ok"),
                    _policy("id < nextval('s')", name="bad_b"),
                ),
            ),
        )
    )
    locations = sorted(v.location for v in PERF002().check(schema, {}))
    assert locations == ["public.t.bad_a", "public.t.bad_b"]


def test_perf002_fires_only_once_per_policy_with_multiple_volatile_calls() -> None:
    # Two volatile calls in one expression → one violation.
    schema = _wrap(_policy("random() < 0.5 AND clock_timestamp() > '2026-01-01'"))
    assert len(PERF002().check(schema, {})) == 1


def test_perf002_metadata_present() -> None:
    rule = PERF002()
    assert rule.id == "PERF002"
    assert rule.severity == "warning"
    assert rule.title


def test_perf002_fires_on_volatile_inside_subquery() -> None:
    # Deliberate divergence from SEC011: PERF002 walks
    # SubLink.subselect because a VOLATILE call inside any
    # subquery is still non-deterministic at evaluation. Pin the
    # behavior so a future "consistency" refactor that aligns
    # PERF002 with SEC011's narrow scope fails this test loudly.
    schema = _wrap(
        _policy("id IN (SELECT random()::INT FROM generate_series(1,10))")
    )
    assert len(PERF002().check(schema, {})) == 1
