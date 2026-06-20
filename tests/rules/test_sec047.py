"""Unit tests for SEC047 — FK to an RLS parent is a cross-tenant oracle.

SEC047 (warning) flags a FOREIGN KEY whose *parent* (referenced) table has RLS
enabled when a *low-trust role can write the child*: FK validation runs as a
system integrity check that bypasses RLS, so a low-trust caller can probe
whether a guessed parent row exists (write succeeds) or not (FK-violation
error) even though RLS hides that row from its own SELECT — the FK-validation
analog of SEC035's UNIQUE-index existence oracle (live-proven on PG16).

The detection is deliberately narrow (FKs to RLS parents are ubiquitous): it
fires only when the parent has ``rls_enabled`` AND the child is low-trust-
writable (a table-level INSERT/UPDATE/ALL grant to the low-trust role, AND the
child either has RLS off OR a permissive INSERT/UPDATE/ALL policy literally
listing that role). It is a posture over-approximation — it does NOT prove the
role's RLS visibility on the parent is narrower than all rows (unsound; a role
with table SELECT still leaks RLS-scoped rows) — and abstains (fail-closed)
when the parent can't be resolved in the snapshot.
"""
from __future__ import annotations

import pytest

from pgrls.model import ForeignKey, Grant, Policy, Schema, Table
from pgrls.rules.sec047 import SEC047


def _fk(
    *,
    name: str = "child_fk",
    columns: tuple[str, ...] = ("parent_id",),
    ref_schema: str = "public",
    ref_table: str = "parent",
    ref_columns: tuple[str, ...] = ("id",),
) -> ForeignKey:
    return ForeignKey(
        name=name,
        columns=columns,
        ref_schema=ref_schema,
        ref_table=ref_table,
        ref_columns=ref_columns,
    )


def _policy(
    *,
    name: str = "ins",
    command: str = "INSERT",
    permissive: bool = True,
    roles: tuple[str, ...] = ("anon",),
) -> Policy:
    return Policy(
        name=name,
        command=command,  # type: ignore[arg-type]
        permissive=permissive,
        roles=roles,
        using_sql=None,
        with_check_sql="true" if command in ("INSERT", "UPDATE", "ALL") else None,
        using_ast=None,
        with_check_ast=None,
    )


def _parent(
    *, schema: str = "public", name: str = "parent", rls_enabled: bool = True
) -> Table:
    return Table(
        schema=schema,
        name=name,
        rls_enabled=rls_enabled,
        force_rls=False,
        policies=(),
    )


def _child(
    *,
    schema: str = "public",
    name: str = "child",
    rls_enabled: bool = False,
    policies: tuple[Policy, ...] = (),
    grants: tuple[Grant, ...] = (Grant(role="anon", privileges=("INSERT",)),),
    foreign_keys: tuple[ForeignKey, ...] | None = None,
) -> Table:
    return Table(
        schema=schema,
        name=name,
        rls_enabled=rls_enabled,
        force_rls=False,
        policies=policies,
        grants=grants,
        foreign_keys=foreign_keys if foreign_keys is not None else (_fk(),),
    )


def _check(*tables: Table, options: dict | None = None) -> list:
    return SEC047().check(Schema(tables=tables), options=options or {})


# --- firing --------------------------------------------------------------


def test_fires_rls_parent_anon_grant_rls_off_child() -> None:
    # The core case: RLS parent + child writable by anon (table INSERT grant,
    # child RLS off → write lands unconditionally).
    [v] = _check(_parent(), _child())
    assert v.rule_id == "SEC047"
    assert v.severity == "warning"
    assert v.location == "public.child (child_fk)"
    assert "public.parent" in v.message
    assert "anon" in v.message
    assert "existence oracle" in v.message
    assert "SEC035" in v.message  # arc relationship surfaced


def test_fires_rls_parent_child_rls_on_with_anon_insert_policy() -> None:
    # Child has RLS on but a permissive INSERT policy literally lists anon, and
    # anon holds the table INSERT grant → still writable, still an oracle.
    child = _child(rls_enabled=True, policies=(_policy(command="INSERT"),))
    [v] = _check(_parent(), child)
    assert v.location == "public.child (child_fk)"


def test_fires_anon_grant_public_write_policy() -> None:
    # PUBLIC subsumption (review MED): anon holds the INSERT grant and a
    # permissive INSERT policy applies to PUBLIC — e.g. a `FOR INSERT WITH
    # CHECK` with NO `TO` clause, the most common idiom, which Postgres stores
    # as roles=['PUBLIC']. PUBLIC admits anon, so anon can write → must fire.
    child = _child(
        rls_enabled=True,
        policies=(_policy(command="INSERT", roles=("PUBLIC",)),),
    )
    [v] = _check(_parent(), child)
    assert v.location == "public.child (child_fk)"


def test_fires_public_grant_anon_write_policy() -> None:
    # The symmetric PUBLIC subsumption: a PUBLIC table INSERT grant covers anon,
    # and a permissive INSERT policy lists anon → anon can write → must fire.
    child = _child(
        rls_enabled=True,
        grants=(Grant(role="PUBLIC", privileges=("INSERT",)),),
        policies=(_policy(command="INSERT", roles=("anon",)),),
    )
    [v] = _check(_parent(), child)
    assert v.location == "public.child (child_fk)"


@pytest.mark.parametrize("priv", ["INSERT", "UPDATE", "ALL"])
def test_fires_on_each_write_grant(priv: str) -> None:
    # INSERT or UPDATE supplies the referencing value; ALL covers both.
    child = _child(grants=(Grant(role="anon", privileges=(priv,)),))
    assert len(_check(_parent(), child)) == 1


@pytest.mark.parametrize("cmd", ["INSERT", "UPDATE", "ALL"])
def test_fires_on_each_write_policy_command_under_rls(cmd: str) -> None:
    child = _child(
        rls_enabled=True,
        grants=(Grant(role="anon", privileges=("ALL",)),),
        policies=(_policy(command=cmd),),
    )
    assert len(_check(_parent(), child)) == 1


def test_fires_for_public_pseudo_role_grant() -> None:
    # A PUBLIC table grant (default low-trust set includes PUBLIC) on an
    # RLS-off child is an oracle for every connection.
    child = _child(grants=(Grant(role="PUBLIC", privileges=("INSERT",)),))
    [v] = _check(_parent(), child)
    assert "PUBLIC" in v.message


def test_still_fires_when_child_has_table_select_on_parent_overapprox() -> None:
    # Documented posture over-approximation: even if the writing role also has
    # broad access, SEC047 does NOT try to prove the role's RLS visibility on
    # the parent is all-rows — the FK oracle leaks regardless. Model that by a
    # parent that is RLS-enabled (its policy could grant the role table SELECT
    # and it would STILL leak existence of rows the policy hides). The rule
    # fires on the structural condition.
    parent = _parent()  # rls_enabled, with whatever policy
    child = _child(grants=(Grant(role="anon", privileges=("INSERT",)),))
    assert len(_check(parent, child)) == 1


# --- multi-column FK -----------------------------------------------------


def test_multi_column_fk_renders_both_column_lists() -> None:
    parent = _parent(name="parent2")
    fk = _fk(
        name="child2_fk",
        columns=("pa", "pb"),
        ref_table="parent2",
        ref_columns=("a", "b"),
    )
    child = _child(name="child2", foreign_keys=(fk,))
    [v] = _check(parent, child)
    assert "(pa, pb)" in v.message  # child columns in conkey order
    assert "public.parent2" in v.message
    assert v.location == "public.child2 (child2_fk)"


# --- silent / abstain ----------------------------------------------------


def test_silent_when_parent_not_rls() -> None:
    # FK to a non-RLS parent: no RLS to bypass, no existence to leak.
    assert _check(_parent(rls_enabled=False), _child()) == []


def test_silent_when_child_rls_on_but_no_write_policy() -> None:
    # Child has the anon INSERT grant but RLS is on with NO policy admitting
    # anon, so the write is blocked by RLS → no oracle handle.
    child = _child(rls_enabled=True, policies=())
    assert _check(_parent(), child) == []


def test_silent_when_child_rls_on_with_only_select_policy() -> None:
    # A SELECT policy does not gate a referencing write.
    child = _child(
        rls_enabled=True,
        policies=(_policy(name="sel", command="SELECT", roles=("anon",)),),
    )
    assert _check(_parent(), child) == []


def test_silent_when_child_policy_but_no_grant() -> None:
    # Child has a permissive anon INSERT policy but NO table grant → anon
    # cannot reach the write path.
    child = _child(
        rls_enabled=True,
        grants=(),
        policies=(_policy(command="INSERT"),),
    )
    assert _check(_parent(), child) == []


def test_silent_when_only_non_write_grant() -> None:
    # SELECT / DELETE grants never supply a referencing value.
    child = _child(grants=(Grant(role="anon", privileges=("SELECT", "DELETE")),))
    assert _check(_parent(), child) == []


def test_silent_when_grant_to_non_low_trust_role() -> None:
    # An INSERT grant to a normal application role is not the low-trust set.
    child = _child(grants=(Grant(role="app_writer", privileges=("INSERT",)),))
    assert _check(_parent(), child) == []


def test_silent_when_write_policy_lists_non_low_trust_role() -> None:
    # RLS on; anon holds the grant, but the permissive INSERT policy admits a
    # different role — the literal-role idiom does not credit anon.
    child = _child(
        rls_enabled=True,
        grants=(Grant(role="anon", privileges=("INSERT",)),),
        policies=(_policy(command="INSERT", roles=("app_writer",)),),
    )
    assert _check(_parent(), child) == []


def test_silent_when_write_policy_is_restrictive() -> None:
    # A RESTRICTIVE policy never grants access (it only narrows); the
    # literal-role credit requires a *permissive* write policy.
    child = _child(
        rls_enabled=True,
        grants=(Grant(role="anon", privileges=("INSERT",)),),
        policies=(_policy(command="INSERT", permissive=False, roles=("anon",)),),
    )
    assert _check(_parent(), child) == []


def test_abstains_when_parent_unresolved_out_of_scope() -> None:
    # The FK references a parent in a schema we didn't introspect (absent from
    # the snapshot). SEC047 cannot read its rls_enabled → abstains (fail-closed),
    # NOT a false positive.
    child = _child(
        foreign_keys=(_fk(ref_schema="private", ref_table="accounts"),)
    )
    assert _check(child) == []  # parent not in the schema at all


def test_silent_when_table_has_no_foreign_keys() -> None:
    child = _child(foreign_keys=())
    assert _check(_parent(), child) == []


# --- allowlist -----------------------------------------------------------


def test_allowlist_by_child_qualified_table() -> None:
    out = _check(
        _parent(), _child(), options={"allowlist": ["public.child"]}
    )
    assert out == []


def test_allowlist_by_child_bare_name() -> None:
    out = _check(_parent(), _child(), options={"allowlist": ["child"]})
    assert out == []


def test_allowlist_by_constraint_name() -> None:
    out = _check(
        _parent(), _child(), options={"allowlist": ["child_fk"]}
    )
    assert out == []


def test_allowlist_one_fk_leaves_another() -> None:
    # Two FKs on the same child, both to RLS parents; allowlist only one.
    parent_a = _parent(name="pa")
    parent_b = _parent(name="pb")
    child = _child(
        foreign_keys=(
            _fk(name="fk_a", ref_table="pa"),
            _fk(name="fk_b", ref_table="pb"),
        ),
    )
    out = _check(parent_a, parent_b, child, options={"allowlist": ["fk_a"]})
    assert [v.location for v in out] == ["public.child (fk_b)"]


# --- config --------------------------------------------------------------


def test_custom_low_trust_role_set() -> None:
    # Restricting the set to a custom role: a grant to that role fires, anon
    # no longer does.
    child = _child(grants=(Grant(role="visitor", privileges=("INSERT",)),))
    assert len(_check(_parent(), child, options={"low_trust_roles": ["visitor"]})) == 1
    # The default anon-granted child is now silent under this set.
    assert _check(_parent(), _child(), options={"low_trust_roles": ["visitor"]}) == []


def test_low_trust_public_normalized_case_insensitively() -> None:
    # "public" (any case) normalizes to the PUBLIC pseudo-role, mirroring SEC044.
    child = _child(grants=(Grant(role="PUBLIC", privileges=("INSERT",)),))
    assert len(_check(_parent(), child, options={"low_trust_roles": ["public"]})) == 1


def test_low_trust_roles_must_be_list_of_strings() -> None:
    with pytest.raises(TypeError):
        _check(_parent(), _child(), options={"low_trust_roles": "anon"})


def test_allowlist_rejects_whitespace_entry() -> None:
    with pytest.raises(TypeError):
        _check(_parent(), _child(), options={"allowlist": [" public.child "]})
