"""Unit tests for SEC032 — table has policies but RLS is not enabled.

SEC032 (error) fires for a table with `rls_enabled = False` that
carries at least one policy: the policies are dormant (Postgres
ignores them until RLS is switched on) and the table is wide open. It
is the policy-bearing complement of SEC001 (RLS off, no policies);
SEC001 cedes policy-bearing tables to SEC032 so they are disjoint.
"""
from __future__ import annotations

from pgrls.model import Policy, Schema, Table
from pgrls.rules.sec032 import SEC032


def _policy(name: str = "p") -> Policy:
    return Policy(
        name=name,
        command="ALL",
        permissive=True,
        roles=("PUBLIC",),
        using_sql="tenant_id = current_setting('app.t')",
        with_check_sql=None,
        using_ast=None,
        with_check_ast=None,
    )


def _table(
    name: str = "documents",
    *,
    rls: bool,
    policies: tuple[Policy, ...] = (),
    schema: str = "public",
    partition_of: tuple[str, str] | None = None,
) -> Table:
    return Table(
        schema=schema,
        name=name,
        rls_enabled=rls,
        force_rls=False,
        policies=policies,
        partition_of=partition_of,
    )


def test_sec032_fires_when_rls_off_and_policies_present() -> None:
    schema = Schema(tables=(_table(rls=False, policies=(_policy(),)),))
    [v] = SEC032().check(schema, options={})
    assert v.rule_id == "SEC032"
    assert v.severity == "error"
    assert v.location == "public.documents"
    assert "not enabled" in v.message
    assert "ENABLE ROW LEVEL SECURITY" in v.message


def test_sec032_silent_when_rls_enabled() -> None:
    schema = Schema(tables=(_table(rls=True, policies=(_policy(),)),))
    assert SEC032().check(schema, options={}) == []


def test_sec032_silent_when_no_policies() -> None:
    # RLS off with no policies is SEC001's surface, not SEC032's.
    schema = Schema(tables=(_table(rls=False, policies=()),))
    assert SEC032().check(schema, options={}) == []


def test_sec032_counts_multiple_policies_in_message() -> None:
    schema = Schema(
        tables=(
            _table(rls=False, policies=(_policy("a"), _policy("b"))),
        )
    )
    [v] = SEC032().check(schema, options={})
    assert "2 policies" in v.message


def test_sec032_single_policy_message_is_singular() -> None:
    schema = Schema(tables=(_table(rls=False, policies=(_policy(),)),))
    [v] = SEC032().check(schema, options={})
    assert "1 policy" in v.message


def test_sec032_respects_bare_and_qualified_allowlist() -> None:
    schema = Schema(tables=(_table(rls=False, policies=(_policy(),)),))
    assert SEC032().check(schema, {"allowlist": ["documents"]}) == []
    assert (
        SEC032().check(schema, {"allowlist": ["public.documents"]}) == []
    )


def test_sec032_skips_partition_child_when_ancestor_has_rls() -> None:
    # A child with dormant policies whose parent has RLS is covered for
    # parent-routed queries — not a hole, so SEC032 stays quiet.
    schema = Schema(
        tables=(
            _table("parent", rls=True),
            _table(
                "child",
                rls=False,
                policies=(_policy(),),
                partition_of=("public", "parent"),
            ),
        )
    )
    assert SEC032().check(schema, options={}) == []


def test_sec032_fires_on_partition_child_when_ancestor_lacks_rls() -> None:
    schema = Schema(
        tables=(
            _table("parent", rls=False),
            _table(
                "child",
                rls=False,
                policies=(_policy(),),
                partition_of=("public", "parent"),
            ),
        )
    )
    locs = {v.location for v in SEC032().check(schema, options={})}
    assert "public.child" in locs
