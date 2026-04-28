"""Unit tests for SEC009 — RLS enabled but no policies defined."""
from __future__ import annotations

import pytest

from pgrls.model import Policy, Schema, Table
from pgrls.rules.sec009 import SEC009


def _table(
    name: str,
    *,
    rls: bool = True,
    schema: str = "public",
    policies: tuple[Policy, ...] = (),
) -> Table:
    return Table(
        schema=schema,
        name=name,
        rls_enabled=rls,
        force_rls=rls,  # mirror RLS so SEC002 isn't a confound
        policies=policies,
    )


def _policy(name: str = "p") -> Policy:
    return Policy(
        name=name,
        command="SELECT",
        permissive=True,
        roles=("authenticated",),
        using_sql="true",
        with_check_sql=None,
    )


def test_sec009_fires_when_rls_enabled_and_no_policies() -> None:
    schema = Schema(tables=(_table("audit_log"),))
    violations = SEC009().check(schema, {})
    assert len(violations) == 1
    v = violations[0]
    assert v.rule_id == "SEC009"
    assert v.severity == "warning"
    assert v.location == "public.audit_log"
    assert "audit_log" in v.message


def test_sec009_silent_when_rls_disabled() -> None:
    # SEC001 covers the rls=False case; SEC009 must not double up.
    schema = Schema(tables=(_table("orders", rls=False),))
    assert SEC009().check(schema, {}) == []


def test_sec009_silent_when_at_least_one_policy_exists() -> None:
    schema = Schema(
        tables=(_table("invoices", policies=(_policy(),)),)
    )
    assert SEC009().check(schema, {}) == []


def test_sec009_allowlist_accepts_qualified_name() -> None:
    schema = Schema(
        tables=(
            _table("audit_log", schema="private"),
            _table("scratch"),
        )
    )
    options = {"allowlist": ["private.audit_log"]}
    locations = sorted(v.location for v in SEC009().check(schema, options))
    assert locations == ["public.scratch"]


def test_sec009_allowlist_accepts_unqualified_name() -> None:
    # Match SEC001/SEC002's unqualified-or-qualified shape so users
    # don't have to remember a different convention per rule.
    schema = Schema(tables=(_table("audit_log"), _table("scratch")))
    options = {"allowlist": ["audit_log"]}
    locations = sorted(v.location for v in SEC009().check(schema, options))
    assert locations == ["public.scratch"]


def test_sec009_bad_allowlist_type_raises_clearly() -> None:
    schema = Schema(tables=(_table("audit_log"),))
    with pytest.raises(TypeError, match="allowlist"):
        SEC009().check(schema, {"allowlist": "audit_log"})  # type: ignore[dict-item]


def test_sec009_bad_allowlist_item_type_raises_clearly() -> None:
    schema = Schema(tables=(_table("audit_log"),))
    with pytest.raises(TypeError, match="allowlist"):
        SEC009().check(
            schema,
            {"allowlist": ["audit_log", 42]},  # type: ignore[list-item]
        )


def test_sec009_fires_on_each_offending_table_independently() -> None:
    schema = Schema(
        tables=(
            _table("a"),
            _table("b", policies=(_policy(),)),
            _table("c"),
        )
    )
    locations = sorted(v.location for v in SEC009().check(schema, {}))
    assert locations == ["public.a", "public.c"]


def test_sec009_fires_on_partition_child_with_rls_but_no_policies() -> None:
    # A partition child whose parent has policies but the child has
    # rls=True (explicit user opt-in) and no own policies is a
    # deny-all on direct access. Pin that SEC009 fires here even
    # when an ancestor has policies — the user opted in on this
    # specific child and likely forgot to add child-specific
    # policies. They can allowlist if it's intentional.
    parent = _table("events", policies=(_policy(),))
    child = Table(
        schema="public",
        name="events_2026",
        rls_enabled=True,
        force_rls=True,
        policies=(),
        partition_of=("public", "events"),
    )
    schema = Schema(tables=(parent, child))
    locations = sorted(v.location for v in SEC009().check(schema, {}))
    assert locations == ["public.events_2026"]


def test_sec009_metadata_present() -> None:
    rule = SEC009()
    assert rule.id == "SEC009"
    assert rule.severity == "warning"
    assert rule.title
