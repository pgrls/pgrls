"""Unit tests for SEC041 — partition child bypasses the parent's RLS.

SEC041 (warning) fires when a table has RLS disabled, an ancestor in its
`partition_of` chain has RLS enabled, AND the child carries a direct
row-access grant (table- or column-level SELECT / INSERT / UPDATE / DELETE)
to a non-owner role, so it is reachable by name — a grant on the parent does
not cascade to a child for direct access. It fires regardless of whether the
child carries its own policies: while RLS is off those policies are dormant,
so the child still returns every row (and SEC032 cedes any child with an RLS
ancestor, so SEC041 must own this case or it falls through both rules). It is
the complement of SEC001/SEC032, which deliberately skip the parent-covered
case; SEC041 cedes to them only when there is no RLS ancestor (nothing to
bypass). An un-granted child (e.g. `pgrls generate`'s output), or one granted
only a non-row-access privilege (REFERENCES/TRIGGER/TRUNCATE), is reachable
only through the parent, so it is not flagged.
"""
from __future__ import annotations

from pgrls.model import ColumnGrant, Grant, Policy, Schema, Table
from pgrls.rules.sec041 import SEC041

_SELECT_GRANT = (Grant(role="app_authenticated", privileges=("SELECT",)),)


def _t(
    name: str,
    *,
    rls: bool,
    partition_of: tuple[str, str] | None = None,
    policies: tuple[Policy, ...] = (),
    grants: tuple[Grant, ...] = _SELECT_GRANT,
    column_grants: tuple[ColumnGrant, ...] = (),
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
        grants=grants,
        column_grants=column_grants,
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
    # TWO RLS-enabled ancestors: the message must name the NEAREST (mid),
    # not the farther root — pins the nearest-first `next(...)` selection
    # (a regression here would otherwise be invisible if only one ancestor
    # ever had RLS on).
    gp = _t("root", rls=True)
    mid = _t("mid", rls=True, partition_of=("public", "root"))
    leaf = _t("leaf", rls=False, partition_of=("public", "mid"))
    [v] = [v for v in _check(gp, mid, leaf) if v.location == "public.leaf"]
    assert "public.mid" in v.message
    assert "public.root" not in v.message


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


def test_fires_on_column_level_grant_only() -> None:
    # No table grant, but a column-level SELECT grant makes the child
    # readable by name (`SELECT body FROM child`) — a real bypass that the
    # table-grant-only gate would have missed.
    parent = _t("events", rls=True)
    child = _t(
        "events_t1",
        rls=False,
        partition_of=("public", "events"),
        grants=(),
        column_grants=(
            ColumnGrant(role="app_authenticated", column="body", privileges=("SELECT",)),
        ),
    )
    [v] = _check(parent, child)
    assert v.location == "public.events_t1"


def test_fires_on_public_column_level_grant() -> None:
    # A PUBLIC column grant is the PostgREST/anon threat in the docstring:
    # anyone can read the named column of the whole partition by name.
    parent = _t("events", rls=True)
    child = _t(
        "events_t1",
        rls=False,
        partition_of=("public", "events"),
        grants=(),
        column_grants=(
            ColumnGrant(role="PUBLIC", column="body", privileges=("SELECT",)),
        ),
    )
    [v] = _check(parent, child)
    assert v.location == "public.events_t1"


def test_fires_on_write_only_grant() -> None:
    # INSERT/UPDATE/DELETE are row-access too: with no RLS on the child a
    # caller can write rows the parent's WITH CHECK / USING would reject.
    parent = _t("events", rls=True)
    child = _t(
        "events_t1",
        rls=False,
        partition_of=("public", "events"),
        grants=(Grant(role="app_authenticated", privileges=("INSERT",)),),
    )
    [v] = _check(parent, child)
    assert v.location == "public.events_t1"


def test_fires_on_dormant_policy_child_under_rls_parent() -> None:
    # A granted, RLS-off child that carries its OWN policies under an RLS
    # parent is still bypassable: the policies are dormant while RLS is off,
    # so the child returns every row. SEC032 cedes any child with an RLS
    # ancestor, so SEC041 must own this (else it falls through BOTH rules).
    # This is the more dangerous shape — the dormant policy makes the child
    # look scoped in code review while enforcing nothing.
    parent = _t("events", rls=True)
    child = _t(
        "events_t1",
        rls=False,
        partition_of=("public", "events"),
        policies=(_bare_policy(),),
    )
    [v] = _check(parent, child)
    assert v.location == "public.events_t1"


def test_message_carries_all_three_remediations() -> None:
    parent = _t("events", rls=True)
    child = _t("events_t1", rls=False, partition_of=("public", "events"))
    [v] = _check(parent, child)
    assert "Enable RLS" in v.message
    assert "revoke" in v.message.lower()
    assert "allowlist" in v.message.lower()


# --- not firing ----------------------------------------------------------


def test_silent_when_child_not_directly_granted() -> None:
    # No grant on the child → not reachable by name (a grant on the parent
    # does not cascade to a child). Only reachable through the parent, where
    # the parent's RLS applies — no bypass. This is `pgrls generate`'s output
    # (parent secured, children un-granted) and must stay silent.
    parent = _t("events", rls=True)
    child = _t("events_t1", rls=False, partition_of=("public", "events"), grants=())
    assert _check(parent, child) == []


def test_silent_on_non_row_access_table_grant() -> None:
    # REFERENCES / TRIGGER / TRUNCATE neither read nor write row contents,
    # so they are not a bypass — a REFERENCES grantee is still "permission
    # denied" on a plain SELECT.
    parent = _t("events", rls=True)
    for privs in [("REFERENCES",), ("TRIGGER",), ("TRUNCATE",), ("REFERENCES", "TRIGGER")]:
        child = _t(
            "events_t1",
            rls=False,
            partition_of=("public", "events"),
            grants=(Grant(role="app_authenticated", privileges=privs),),
        )
        assert _check(parent, child) == [], privs


def test_silent_on_references_only_column_grant() -> None:
    # A column-level REFERENCES grant is likewise not row access.
    parent = _t("events", rls=True)
    child = _t(
        "events_t1",
        rls=False,
        partition_of=("public", "events"),
        grants=(),
        column_grants=(
            ColumnGrant(
                role="app_authenticated", column="tenant_id", privileges=("REFERENCES",)
            ),
        ),
    )
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


def test_silent_on_dormant_policy_child_without_rls_ancestor() -> None:
    # RLS-off child with its OWN dormant policies but NO RLS ancestor: SEC032
    # owns this (the policy-bearing complement of SEC001). SEC041 cedes —
    # there is nothing upstream to bypass. This is the ONLY case SEC041 cedes
    # to SEC032, and it is where SEC032 actually fires.
    parent = _t("events", rls=False)
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
