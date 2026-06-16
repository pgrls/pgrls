"""Unit tests for SEC043 — legacy-inheritance child bypasses the parent's RLS.

SEC043 (warning) is the classic-`INHERITS` analogue of SEC041 (declarative
partitions). It fires when a table has RLS disabled, an ancestor in its
`inherits` DAG has RLS enabled, AND the child carries a direct row-access
grant (table- or column-level SELECT / INSERT / UPDATE / DELETE) to a
non-owner role, so it is reachable by name — a grant on the parent does not
cascade to a classic-inheritance child for direct access. It fires regardless
of whether the child carries its own (dormant) policies. Unlike a partition's
single parent, a classic-inheritance child may have MULTIPLE parents (a DAG),
so it fires if ANY ancestor enforces RLS.

Unlike SEC041, SEC043 does NOT cede to SEC001/SEC032 on the RLS-ancestor case:
those rules don't walk classic inheritance, so SEC001 (and SEC032 for a
dormant-policy child) ALSO fires on the same child — a deliberate over-report
pointing to the same fix. These unit tests scope SEC043 in isolation; the
combined-fixture test (tests/test_cli.py) asserts the cross-rule co-firing.
An un-granted child, or one granted only a non-row-access privilege
(REFERENCES/TRIGGER/TRUNCATE), is reachable only through the parent, so it is
not flagged.
"""
from __future__ import annotations

from pgrls.model import ColumnGrant, Grant, Policy, Schema, Table
from pgrls.rules.sec043 import SEC043

_SELECT_GRANT = (Grant(role="app_authenticated", privileges=("SELECT",)),)


def _t(
    name: str,
    *,
    rls: bool,
    inherits: tuple[tuple[str, str], ...] = (),
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
        inherits=inherits,
        grants=grants,
        column_grants=column_grants,
    )


def _check(*tables: Table, options: dict | None = None) -> list:
    return SEC043().check(Schema(tables=tables), options=options or {})


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
    child = _t("events_legacy", rls=False, inherits=(("public", "events"),))
    [v] = _check(parent, child)
    assert v.rule_id == "SEC043"
    assert v.severity == "warning"
    assert v.location == "public.events_legacy"
    assert "public.events" in v.message
    assert "bypass" in v.message.lower()
    assert "INHERITS" in v.message


def test_fires_on_each_granted_rls_off_child() -> None:
    parent = _t("events", rls=True)
    c1 = _t("events_c1", rls=False, inherits=(("public", "events"),))
    c2 = _t("events_c2", rls=False, inherits=(("public", "events"),))
    locs = sorted(v.location for v in _check(parent, c1, c2))
    assert locs == ["public.events_c1", "public.events_c2"]


def test_fires_when_rls_ancestor_is_a_grandparent() -> None:
    gp = _t("events", rls=True)
    mid = _t("events_mid", rls=False, inherits=(("public", "events"),))
    leaf = _t("events_leaf", rls=False, inherits=(("public", "events_mid"),))
    locs = sorted(v.location for v in _check(gp, mid, leaf))
    assert locs == ["public.events_leaf", "public.events_mid"]


def test_fires_with_multiple_parents_one_has_rls() -> None:
    # The DAG case a partition's single-parent chain can't reach: the child
    # inherits from two parents, only one of which enforces RLS. The child is
    # still directly bypassable, so SEC043 fires and names the RLS parent.
    rls_parent = _t("audited", rls=True)
    plain_parent = _t("timestamped", rls=False)
    child = _t(
        "records",
        rls=False,
        inherits=(("public", "timestamped"), ("public", "audited")),
    )
    [v] = _check(rls_parent, plain_parent, child)
    assert v.location == "public.records"
    assert "public.audited" in v.message


def test_message_names_the_first_rls_ancestor_found() -> None:
    # Two RLS-enabled ancestors via a single chain: the message names the
    # NEAREST (mid), pinning the nearest-first `next(...)` selection over the
    # DFS walk (depth-first yields mid before root).
    root = _t("root", rls=True)
    mid = _t("mid", rls=True, inherits=(("public", "root"),))
    leaf = _t("leaf", rls=False, inherits=(("public", "mid"),))
    [v] = [v for v in _check(root, mid, leaf) if v.location == "public.leaf"]
    assert "public.mid" in v.message
    assert "public.root" not in v.message


def test_fires_on_public_grant() -> None:
    parent = _t("events", rls=True)
    child = Table(
        schema="public",
        name="events_legacy",
        rls_enabled=False,
        force_rls=False,
        policies=(),
        columns=("tenant_id", "body"),
        column_details=(),
        inherits=(("public", "events"),),
        grants=(Grant(role="PUBLIC", privileges=("SELECT",)),),
    )
    [v] = _check(parent, child)
    assert v.location == "public.events_legacy"


def test_fires_on_column_level_grant_only() -> None:
    # No table grant, but a column-level SELECT grant makes the child readable
    # by name (`SELECT body FROM child`) — a real bypass.
    parent = _t("events", rls=True)
    child = _t(
        "events_legacy",
        rls=False,
        inherits=(("public", "events"),),
        grants=(),
        column_grants=(
            ColumnGrant(
                role="app_authenticated", column="body", privileges=("SELECT",)
            ),
        ),
    )
    [v] = _check(parent, child)
    assert v.location == "public.events_legacy"


def test_fires_on_write_only_grant() -> None:
    # INSERT/UPDATE/DELETE are row-access too: with no RLS on the child a
    # caller can write rows the parent's WITH CHECK / USING would reject.
    parent = _t("events", rls=True)
    child = _t(
        "events_legacy",
        rls=False,
        inherits=(("public", "events"),),
        grants=(Grant(role="app_authenticated", privileges=("INSERT",)),),
    )
    [v] = _check(parent, child)
    assert v.location == "public.events_legacy"


def test_fires_on_dormant_policy_child_under_rls_parent() -> None:
    # A granted, RLS-off child that carries its OWN policies under an RLS
    # ancestor is still bypassable: the policies are dormant while RLS is off,
    # so the child returns every row. (SEC032 also fires on it — these unit
    # tests scope SEC043 alone.)
    parent = _t("events", rls=True)
    child = _t(
        "events_legacy",
        rls=False,
        inherits=(("public", "events"),),
        policies=(_bare_policy(),),
    )
    [v] = _check(parent, child)
    assert v.location == "public.events_legacy"


def test_message_carries_all_three_remediations() -> None:
    parent = _t("events", rls=True)
    child = _t("events_legacy", rls=False, inherits=(("public", "events"),))
    [v] = _check(parent, child)
    assert "Enable RLS" in v.message
    assert "revoke" in v.message.lower()
    assert "allowlist" in v.message.lower()


# --- not firing ----------------------------------------------------------


def test_silent_when_child_not_directly_granted() -> None:
    # No grant on the child → not reachable by name (a grant on the parent
    # does not cascade to an inheritance child). Only reachable through the
    # parent, where the parent's RLS applies — no bypass.
    parent = _t("events", rls=True)
    child = _t(
        "events_legacy", rls=False, inherits=(("public", "events"),), grants=()
    )
    assert _check(parent, child) == []


def test_silent_on_non_row_access_table_grant() -> None:
    # REFERENCES / TRIGGER / TRUNCATE neither read nor write row contents,
    # so they are not a bypass.
    parent = _t("events", rls=True)
    for privs in [
        ("REFERENCES",),
        ("TRIGGER",),
        ("TRUNCATE",),
        ("REFERENCES", "TRIGGER"),
    ]:
        child = _t(
            "events_legacy",
            rls=False,
            inherits=(("public", "events"),),
            grants=(Grant(role="app_authenticated", privileges=privs),),
        )
        assert _check(parent, child) == [], privs


def test_silent_on_references_only_column_grant() -> None:
    parent = _t("events", rls=True)
    child = _t(
        "events_legacy",
        rls=False,
        inherits=(("public", "events"),),
        grants=(),
        column_grants=(
            ColumnGrant(
                role="app_authenticated",
                column="tenant_id",
                privileges=("REFERENCES",),
            ),
        ),
    )
    assert _check(parent, child) == []


def test_silent_when_child_has_rls_enabled() -> None:
    parent = _t("events", rls=True)
    child = _t("events_legacy", rls=True, inherits=(("public", "events"),))
    assert _check(parent, child) == []


def test_silent_on_standalone_rls_off_table() -> None:
    # No inherits, no ancestor → SEC001's case, not SEC043's.
    assert _check(_t("standalone", rls=False)) == []


def test_silent_when_no_ancestor_has_rls() -> None:
    # Parent ALSO has RLS off → no RLS-enforcing ancestor. SEC001 owns this;
    # SEC043 stays silent (granted child, but nothing to bypass).
    parent = _t("events", rls=False)
    child = _t("events_legacy", rls=False, inherits=(("public", "events"),))
    assert _check(parent, child) == []


def test_silent_when_no_parent_has_rls_in_multi_parent_dag() -> None:
    # All parents in the DAG have RLS off → nothing to bypass.
    p1 = _t("audited", rls=False)
    p2 = _t("timestamped", rls=False)
    child = _t(
        "records",
        rls=False,
        inherits=(("public", "audited"), ("public", "timestamped")),
    )
    assert _check(p1, p2, child) == []


def test_silent_on_partition_child_not_inheritance_child() -> None:
    # A declarative partition child (partition_of set, inherits empty) is
    # SEC041's case — SEC043 must not touch it (mutual exclusivity).
    parent = _t("events", rls=True)
    part_child = Table(
        schema="public",
        name="events_p1",
        rls_enabled=False,
        force_rls=False,
        policies=(),
        columns=("tenant_id", "body"),
        column_details=(),
        partition_of=("public", "events"),
        inherits=(),
        grants=_SELECT_GRANT,
    )
    assert _check(parent, part_child) == []


def test_silent_on_the_rls_enabled_parent_itself() -> None:
    parent = _t("events", rls=True)
    child = _t("events_legacy", rls=True, inherits=(("public", "events"),))
    assert "public.events" not in [v.location for v in _check(parent, child)]


# --- configuration -------------------------------------------------------


def test_allowlist_qualified_exempts_child() -> None:
    parent = _t("events", rls=True)
    child = _t("events_legacy", rls=False, inherits=(("public", "events"),))
    assert (
        _check(parent, child, options={"allowlist": ["public.events_legacy"]})
        == []
    )


def test_allowlist_unqualified_exempts_child() -> None:
    parent = _t("events", rls=True)
    child = _t("events_legacy", rls=False, inherits=(("public", "events"),))
    assert (
        _check(parent, child, options={"allowlist": ["events_legacy"]}) == []
    )


def test_metadata() -> None:
    rule = SEC043()
    assert rule.id == "SEC043"
    assert rule.severity == "warning"
    assert rule.title
