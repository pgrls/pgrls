"""Unit tests for SEC041 — partition child bypasses the parent's RLS.

SEC041 (warning) fires when a table has RLS disabled, no policies of its
own, an ancestor in its `partition_of` chain has RLS enabled, AND the child
is directly granted to a non-owner role (so it is reachable by name — a
grant on the parent does not cascade to a child for direct access). It is
the complement of SEC001, which deliberately skips the parent-covered case;
the has-own-policies case is ceded to SEC032; an un-granted child (e.g.
`pgrls generate`'s output) is reachable only through the parent, so it is
not flagged.
"""
from __future__ import annotations

from pgrls.model import Grant, Policy, Schema, Table
from pgrls.rules.sec041 import SEC041

_GRANT = (Grant(role="app_authenticated", privileges=("SELECT",)),)


def _t(
    name: str,
    *,
    rls: bool,
    partition_of: tuple[str, str] | None = None,
    policies: tuple[Policy, ...] = (),
    granted: bool = True,
    schema: str = "public",
) -> Table:
    return Table(
        schema=schema,
        name=name,
        rls_enabled=rls,
        force_rls=rls,
        policies=policies,
        columns=("tenant_id", "body"),
        column_details=(),
        partition_of=partition_of,
        grants=_GRANT if granted else (),
    )


def _check(*tables: Table, options: dict | None = None) -> list:
    return SEC041().check(Schema(tables=tables), options=options or {})


def _bare_policy() -> Policy:
    return Policy(
        name="p",
        command="ALL",
        permissive=True,
        roles=("authenticated",),
        using_sql="tenant_id = 1",
        with_check_sql=None,
        using_ast=None,
        with_check_ast=None,
    )


# --- firing --------------------------------------------------------------


def test_fires_on_granted_rls_off_child_of_rls_parent() -> None:
    parent = _t("events", rls=True)
    child = _t("events_t1", rls=False, partition_of=("public", "events"))
    [v] = _check(parent, child)
    assert v.rule_id == "SEC041"
    assert v.severity == "warning"
    assert v.location == "public.events_t1"
    assert "public.events" in v.message
    assert "bypass" in v.message.lower()


def test_fires_on_each_granted_rls_off_child() -> None:
    parent = _t("events", rls=True)
    c1 = _t("events_t1", rls=False, partition_of=("public", "events"))
    c2 = _t("events_t2", rls=False, partition_of=("public", "events"))
    locs = sorted(v.location for v in _check(parent, c1, c2))
    assert locs == ["public.events_t1", "public.events_t2"]


def test_fires_when_rls_ancestor_is_a_grandparent() -> None:
    gp = _t("events", rls=True)
    mid = _t("events_2024", rls=False, partition_of=("public", "events"))
    leaf = _t("events_2024_01", rls=False, partition_of=("public", "events_2024"))
    locs = sorted(v.location for v in _check(gp, mid, leaf))
    assert locs == ["public.events_2024", "public.events_2024_01"]


def test_message_names_the_nearest_rls_ancestor() -> None:
    gp = _t("root", rls=True)
    mid = _t("mid", rls=False, partition_of=("public", "root"))
    leaf = _t("leaf", rls=False, partition_of=("public", "mid"))
    [v] = [v for v in _check(gp, mid, leaf) if v.location == "public.leaf"]
    assert "public.root" in v.message


def test_fires_on_public_grant() -> None:
    # A PUBLIC grant makes the child reachable by everyone — still a bypass.
    parent = _t("events", rls=True)
    child = Table(
        schema="public",
        name="events_t1",
        rls_enabled=False,
        force_rls=False,
        policies=(),
        columns=("tenant_id", "body"),
        column_details=(),
        partition_of=("public", "events"),
        grants=(Grant(role="PUBLIC", privileges=("SELECT",)),),
    )
    [v] = _check(parent, child)
    assert v.location == "public.events_t1"


# --- not firing ----------------------------------------------------------


def test_silent_when_child_not_directly_granted() -> None:
    # No grant on the child → not reachable by name (a grant on the parent
    # does not cascade to a child). Only reachable through the parent, where
    # the parent's RLS applies — no bypass. This is `pgrls generate`'s output
    # (parent secured, children un-granted) and must stay silent.
    parent = _t("events", rls=True)
    child = _t("events_t1", rls=False, partition_of=("public", "events"), granted=False)
    assert _check(parent, child) == []


def test_silent_when_child_has_rls_enabled() -> None:
    parent = _t("events", rls=True)
    child = _t("events_t1", rls=True, partition_of=("public", "events"))
    assert _check(parent, child) == []


def test_silent_on_standalone_rls_off_table() -> None:
    # No partition_of, no ancestor → SEC001's case, not SEC041's.
    assert _check(_t("standalone", rls=False)) == []


def test_silent_when_no_ancestor_has_rls() -> None:
    # Parent ALSO has RLS off → no RLS-enforcing ancestor. SEC001 owns this;
    # SEC041 stays silent (granted child, but nothing to bypass).
    parent = _t("events", rls=False)
    child = _t("events_t1", rls=False, partition_of=("public", "events"))
    assert _check(parent, child) == []


def test_silent_when_child_has_own_policies_ceded_to_sec032() -> None:
    parent = _t("events", rls=True)
    child = _t(
        "events_t1",
        rls=False,
        partition_of=("public", "events"),
        policies=(_bare_policy(),),
    )
    assert _check(parent, child) == []


def test_silent_on_the_rls_enabled_parent_itself() -> None:
    parent = _t("events", rls=True)
    child = _t("events_t1", rls=True, partition_of=("public", "events"))
    assert "public.events" not in [v.location for v in _check(parent, child)]


# --- configuration -------------------------------------------------------


def test_allowlist_qualified_exempts_child() -> None:
    parent = _t("events", rls=True)
    child = _t("events_t1", rls=False, partition_of=("public", "events"))
    assert _check(parent, child, options={"allowlist": ["public.events_t1"]}) == []


def test_allowlist_unqualified_exempts_child() -> None:
    parent = _t("events", rls=True)
    child = _t("events_t1", rls=False, partition_of=("public", "events"))
    assert _check(parent, child, options={"allowlist": ["events_t1"]}) == []


def test_metadata() -> None:
    rule = SEC041()
    assert rule.id == "SEC041"
    assert rule.severity == "warning"
    assert rule.title
