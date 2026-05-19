"""Unit tests for SEC022 — RLS-enabled table with read-only policies.

SEC022 (info) fires when a table has RLS enabled and at least one
policy, but every policy is `FOR SELECT` — so no policy covers
INSERT, UPDATE, or DELETE and writes by non-owner roles are denied.
Detection is purely command-based; a `FOR ALL` policy of any kind
counts as write coverage and silences the rule.
"""
from __future__ import annotations

import pytest

from pgrls.model import Policy, Schema, Table
from pgrls.rules.sec022 import SEC022


def _policy(
    name: str = "p",
    *,
    command: str = "SELECT",
    permissive: bool = True,
) -> Policy:
    # SEC022 inspects only `.command`; the predicate text is
    # irrelevant to it, so a generic USING is fine for every shape.
    return Policy(
        name=name,
        command=command,  # type: ignore[arg-type]
        permissive=permissive,
        roles=("app",),
        using_sql="tenant_id = 1",
        with_check_sql=None,
    )


def _table(
    name: str = "t",
    *policies: Policy,
    rls: bool = True,
    schema: str = "public",
    partition_of: tuple[str, str] | None = None,
) -> Table:
    return Table(
        schema=schema,
        name=name,
        rls_enabled=rls,
        force_rls=True,
        policies=policies,
        columns=("id", "tenant_id"),
        partition_of=partition_of,
    )


# --- fires ---------------------------------------------------------------


def test_sec022_fires_when_only_select_policy() -> None:
    schema = Schema(tables=(_table("t", _policy("read")),))
    [v] = SEC022().check(schema, {})
    assert v.rule_id == "SEC022"
    assert v.severity == "info"
    assert v.location == "public.t"


def test_sec022_fires_with_multiple_select_policies() -> None:
    # Two FOR SELECT policies — still zero write coverage, one finding.
    schema = Schema(
        tables=(
            _table("t", _policy("read_a"), _policy("read_b")),
        )
    )
    assert len(SEC022().check(schema, {})) == 1


def test_sec022_fires_with_permissive_and_restrictive_select_mix() -> None:
    # A permissive FOR SELECT policy (working reads) alongside a
    # restrictive FOR SELECT policy — still zero write coverage.
    schema = Schema(
        tables=(
            _table(
                "t",
                _policy("read", permissive=True),
                _policy("floor", permissive=False),
            ),
        )
    )
    assert len(SEC022().check(schema, {})) == 1


def test_sec022_fires_on_each_table_independently() -> None:
    schema = Schema(
        tables=(
            _table("a", _policy("read")),
            _table("b", _policy("read")),
        )
    )
    locations = sorted(v.location for v in SEC022().check(schema, {}))
    assert locations == ["public.a", "public.b"]


# --- silent --------------------------------------------------------------


def test_sec022_silent_when_rls_disabled() -> None:
    # RLS off is SEC001's surface — policies are not enforced at all.
    schema = Schema(
        tables=(_table("t", _policy("read"), rls=False),)
    )
    assert SEC022().check(schema, {}) == []


def test_sec022_silent_when_no_policies() -> None:
    # RLS on with zero policies is deny-by-default (reads denied too)
    # — a different signal, not "read-only coverage".
    schema = Schema(tables=(_table("t"),))
    assert SEC022().check(schema, {}) == []


def test_sec022_silent_when_all_policies_restrictive() -> None:
    # A restrictive-only table denies reads too (the permissive
    # group is empty), so it is not a read-only surface — that is
    # SEC012's "restrictive-only policy set" finding. SEC022 stays
    # quiet and leaves it to SEC012.
    schema = Schema(
        tables=(
            _table(
                "t",
                _policy("a", permissive=False),
                _policy("b", permissive=False),
            ),
        )
    )
    assert SEC022().check(schema, {}) == []


@pytest.mark.parametrize("command", ["ALL", "INSERT", "UPDATE", "DELETE"])
def test_sec022_silent_when_a_policy_covers_writes(command: str) -> None:
    # Any one write-covering command on any policy silences the rule.
    schema = Schema(
        tables=(_table("t", _policy("w", command=command)),)
    )
    assert SEC022().check(schema, {}) == []


def test_sec022_silent_when_select_plus_write_policy_mixed() -> None:
    # A FOR SELECT read policy alongside a FOR INSERT write policy —
    # write coverage exists, so the rule stays quiet.
    schema = Schema(
        tables=(
            _table(
                "t",
                _policy("read", command="SELECT"),
                _policy("write", command="INSERT"),
            ),
        )
    )
    assert SEC022().check(schema, {}) == []


def test_sec022_silent_with_restrictive_for_all_policy() -> None:
    # A restrictive FOR ALL policy still carries the ALL command, so
    # it counts as write coverage — the rule does not analyse
    # permissive-vs-restrictive write-grant semantics.
    schema = Schema(
        tables=(
            _table("t", _policy("a", command="ALL", permissive=False)),
        )
    )
    assert SEC022().check(schema, {}) == []


def test_sec022_evaluates_partition_parent_but_skips_child() -> None:
    # A partition child's writes route through the parent; flagging
    # the child would be a false positive. The parent is evaluated.
    parent = _table("events", _policy("read"))
    child = _table(
        "events_2026",
        _policy("read"),
        partition_of=("public", "events"),
    )
    schema = Schema(tables=(parent, child))
    locations = [v.location for v in SEC022().check(schema, {})]
    assert locations == ["public.events"]


def test_sec022_skips_partitions_at_every_level() -> None:
    # Multi-level hierarchy root -> mid -> leaf. `partition_of` is
    # set on both the mid-level partition and the leaf, so both are
    # skipped — a partition's writes route through the root whatever
    # its depth. Only the root (not itself a partition) is evaluated.
    root = _table("events", _policy("read"))
    mid = _table(
        "events_2026",
        _policy("read"),
        partition_of=("public", "events"),
    )
    leaf = _table(
        "events_2026_q1",
        _policy("read"),
        partition_of=("public", "events_2026"),
    )
    schema = Schema(tables=(root, mid, leaf))
    locations = [v.location for v in SEC022().check(schema, {})]
    assert locations == ["public.events"]


# --- allowlist / metadata ------------------------------------------------


def test_sec022_allowlist_exempts_by_qualified_name() -> None:
    schema = Schema(tables=(_table("t", _policy("read")),))
    assert SEC022().check(schema, {"allowlist": ["public.t"]}) == []


def test_sec022_allowlist_exempts_by_bare_name() -> None:
    schema = Schema(tables=(_table("t", _policy("read")),))
    assert SEC022().check(schema, {"allowlist": ["t"]}) == []


def test_sec022_bad_allowlist_type_raises_clearly() -> None:
    schema = Schema(tables=(_table("t", _policy("read")),))
    with pytest.raises(TypeError, match="allowlist"):
        SEC022().check(schema, {"allowlist": "public.t"})  # type: ignore[dict-item]


def test_sec022_metadata_present() -> None:
    rule = SEC022()
    assert rule.id == "SEC022"
    assert rule.severity == "info"
    assert rule.title


# --- message -------------------------------------------------------------


def test_sec022_message_names_table_and_allowlist_hint() -> None:
    schema = Schema(tables=(_table("t", _policy("read")),))
    [v] = SEC022().check(schema, {})
    assert "public.t" in v.message
    assert "[lint.rules.SEC022]" in v.message
    # The remediation surfaces both the read-only-intent escape
    # hatch and the write-policy fix.
    assert "INSERT" in v.message


def test_sec022_message_uses_singular_for_one_policy() -> None:
    one = Schema(tables=(_table("t", _policy("read")),))
    [v1] = SEC022().check(one, {})
    assert "1 policy" in v1.message

    two = Schema(
        tables=(_table("t", _policy("a"), _policy("b")),)
    )
    [v2] = SEC022().check(two, {})
    assert "2 policies" in v2.message
