"""Unit tests for the access engine behind `pgrls matrix`.

Each case pins one privilege or RLS fact that `verify` already measured live
on PG16; the engine reuses those rules, so a regression here means the two
have drifted apart. Every load-bearing rule here was mutation-checked:
inverting it makes its test fail.
"""
from __future__ import annotations

from pgrls.access import build_access_map
from pgrls.ast_utils import parse_expr
from pgrls.model import (
    ColumnGrant,
    Grant,
    Policy,
    Role,
    RoleMembership,
    Schema,
    Table,
)


def _role(name: str, *, login: bool = True, su: bool = False, brls: bool = False) -> Role:
    return Role(name=name, can_login=login, superuser=su, bypassrls=brls)


def _policy(
    name: str,
    using: str | None,
    *,
    roles: tuple[str, ...] = ("PUBLIC",),
    permissive: bool = True,
    command: str = "SELECT",
) -> Policy:
    return Policy(
        name=name,
        command=command,
        permissive=permissive,
        roles=roles,
        using_sql=using,
        with_check_sql=None,
        using_ast=parse_expr(using) if using is not None else None,
        with_check_ast=None,
    )


def _table(
    name: str = "t",
    *,
    owner: str = "owner",
    rls: bool = True,
    force: bool = False,
    grants: tuple[Grant, ...] = (),
    column_grants: tuple[ColumnGrant, ...] = (),
    policies: tuple[Policy, ...] = (),
) -> Table:
    return Table(
        schema="public",
        name=name,
        rls_enabled=rls,
        force_rls=force,
        policies=policies,
        owner=owner,
        grants=grants,
        column_grants=column_grants,
        columns=("id", "email", "tenant_id"),
    )


def _schema(tables, roles, memberships=()) -> Schema:
    return Schema(tables=tuple(tables), roles=tuple(roles), role_memberships=tuple(memberships))


def _only(amap, principal, relation="public.t"):
    hits = [a for a in amap.accesses if a.principal == principal and a.relation == relation]
    assert len(hits) <= 1
    return hits[0] if hits else None


_SELECT = ("SELECT",)


# --- privilege ---------------------------------------------------------------


def test_no_grant_means_no_access() -> None:
    amap = build_access_map(_schema([_table()], [_role("app")]))
    assert _only(amap, "app") is None


def test_superuser_reads_everything_with_no_grant() -> None:
    amap = build_access_map(_schema([_table()], [_role("root", su=True)]))
    a = _only(amap, "root")
    assert a is not None and a.rows == "all" and a.columns is None
    assert [p.kind for p in a.paths] == ["superuser"]


def test_bypassrls_escapes_policies_but_not_the_privilege_check() -> None:
    """Measured: a non-superuser BYPASSRLS role with no SELECT grant got
    `permission denied for table`. BYPASSRLS is not a privilege."""
    amap = build_access_map(_schema([_table()], [_role("brls", brls=True)]))
    assert _only(amap, "brls") is None
    granted = _table(grants=(Grant(role="brls", privileges=_SELECT),))
    a = _only(build_access_map(_schema([granted], [_role("brls", brls=True)])), "brls")
    assert a is not None and a.rows == "all" and "BYPASSRLS" in (a.reason or "")


def test_public_grant_reaches_every_role() -> None:
    t = _table(grants=(Grant(role="PUBLIC", privileges=_SELECT),))
    amap = build_access_map(_schema([t], [_role("a"), _role("b")]))
    for r in ("a", "b"):
        a = _only(amap, r)
        assert a is not None and [p.kind for p in a.paths] == ["public_grant"]


def test_column_grant_reaches_only_those_columns() -> None:
    t = _table(column_grants=(ColumnGrant(role="app", column="email", privileges=_SELECT),))
    a = _only(build_access_map(_schema([t], [_role("app")])), "app")
    assert a is not None and a.columns == ("email",)
    assert a.paths[0].kind == "column_grant"


def test_table_grant_wins_over_column_grant_for_column_set() -> None:
    t = _table(
        grants=(Grant(role="app", privileges=_SELECT),),
        column_grants=(ColumnGrant(role="app", column="email", privileges=_SELECT),),
    )
    a = _only(build_access_map(_schema([t], [_role("app")])), "app")
    assert a is not None and a.columns is None  # every column


def test_grant_to_a_group_reaches_an_inherit_member() -> None:
    t = _table(grants=(Grant(role="readers", privileges=_SELECT),))
    amap = build_access_map(
        _schema([t], [_role("app"), _role("readers", login=False)],
                [RoleMembership(member="app", role="readers", inherit=True)])
    )
    a = _only(amap, "app")
    assert a is not None and a.paths[0].kind == "grant" and a.paths[0].via == "readers"


def test_noinherit_member_holds_none_of_the_groups_privileges() -> None:
    """Measured: a NOINHERIT member's view got `permission denied`."""
    t = _table(grants=(Grant(role="readers", privileges=_SELECT),))
    amap = build_access_map(
        _schema([t], [_role("app"), _role("readers", login=False)],
                [RoleMembership(member="app", role="readers", inherit=False)])
    )
    assert _only(amap, "app") is None


def test_pg_read_all_data_confers_select_with_no_grant() -> None:
    amap = build_access_map(
        _schema([_table()], [_role("analyst"), _role("pg_read_all_data", login=False)],
                [RoleMembership(member="analyst", role="pg_read_all_data", inherit=True)])
    )
    a = _only(amap, "analyst")
    assert a is not None and a.paths[0].kind == "pg_read_all_data"


# --- rows --------------------------------------------------------------------


def test_rls_off_means_every_row() -> None:
    t = _table(rls=False, grants=(Grant(role="app", privileges=_SELECT),))
    a = _only(build_access_map(_schema([t], [_role("app")])), "app")
    assert a is not None and a.rows == "all" and a.reason == "RLS is off"


def test_rls_on_with_no_applicable_policy_is_default_deny() -> None:
    t = _table(
        grants=(Grant(role="app", privileges=_SELECT),),
        policies=(_policy("staff_only", "true", roles=("staff",)),),
    )
    a = _only(build_access_map(_schema([t], [_role("app"), _role("staff")])), "app")
    assert a is not None and a.rows == "none"


def test_applicable_policy_filters_rows() -> None:
    t = _table(
        grants=(Grant(role="app", privileges=_SELECT),),
        policies=(_policy("tenant", "tenant_id = current_setting('app.t', true)"),),
    )
    a = _only(build_access_map(_schema([t], [_role("app")])), "app")
    assert a is not None and a.rows == "filtered" and a.policies == ("tenant",)


def test_using_true_with_no_restrictive_floor_is_every_row() -> None:
    t = _table(
        grants=(Grant(role="app", privileges=_SELECT),),
        policies=(_policy("open", "true"),),
    )
    a = _only(build_access_map(_schema([t], [_role("app")])), "app")
    assert a is not None and a.rows == "all" and "USING (true)" in (a.reason or "")


def test_a_restrictive_floor_keeps_using_true_filtered() -> None:
    t = _table(
        grants=(Grant(role="app", privileges=_SELECT),),
        policies=(
            _policy("open", "true"),
            _policy("floor", "tenant_id = current_setting('app.t', true)", permissive=False),
        ),
    )
    a = _only(build_access_map(_schema([t], [_role("app")])), "app")
    assert a is not None and a.rows == "filtered"


def test_owner_reads_every_row_without_force() -> None:
    t = _table(owner="app", policies=(_policy("tenant", "tenant_id = '1'"),))
    a = _only(build_access_map(_schema([t], [_role("app")])), "app")
    assert a is not None and a.rows == "all" and "FORCE" in (a.reason or "")


def test_force_strips_owner_exemption() -> None:
    t = _table(owner="app", force=True, policies=(_policy("tenant", "tenant_id = '1'"),))
    a = _only(build_access_map(_schema([t], [_role("app")])), "app")
    assert a is not None and a.rows == "filtered"


def test_inherit_member_of_owner_is_owner_equivalent() -> None:
    t = _table(owner="own", policies=(_policy("tenant", "tenant_id = '1'"),))
    amap = build_access_map(
        _schema([t], [_role("app"), _role("own", login=False)],
                [RoleMembership(member="app", role="own", inherit=True)])
    )
    a = _only(amap, "app")
    assert a is not None and a.paths[0].kind == "owner_member" and a.rows == "all"


def test_policy_applies_through_a_noinherit_edge_even_without_privileges() -> None:
    """Policy applicability is `is_member_of_role` — every membership edge —
    while privileges follow INHERIT only. So a `TO grp` policy applies to a
    NOINHERIT member even though that member inherits none of grp's grants."""
    t = _table(
        grants=(Grant(role="app", privileges=_SELECT),),
        policies=(_policy("grp_rows", "tenant_id = '1'", roles=("grp",)),),
    )
    amap = build_access_map(
        _schema([t], [_role("app"), _role("grp", login=False)],
                [RoleMembership(member="app", role="grp", inherit=False)])
    )
    a = _only(amap, "app")
    assert a is not None and a.rows == "filtered" and a.policies == ("grp_rows",)


# --- fail-closed -------------------------------------------------------------


def test_missing_graph_is_undecided_never_no_access() -> None:
    """With `role_memberships is None`, a grant to some role `app` might
    inherit cannot be ruled out — reporting "no access" would be a false
    clear."""
    t = _table(grants=(Grant(role="readers", privileges=_SELECT),))
    s = Schema(tables=(t,), roles=(_role("app"),), role_memberships=None)
    a = _only(build_access_map(s), "app")
    assert a is not None and a.rows == "undecided"
    assert build_access_map(s).graph_complete is False


def test_missing_catalogue_derives_principals_and_says_so() -> None:
    t = _table(grants=(Grant(role="app", privileges=_SELECT),))
    s = Schema(tables=(t,), roles=None, role_memberships=())
    amap = build_access_map(s)
    assert amap.roles_derived is True
    assert "app" in amap.principals and "owner" in amap.principals


def test_nologin_roles_are_excluded_by_default() -> None:
    t = _table(grants=(Grant(role="grp", privileges=_SELECT),))
    s = _schema([t], [_role("grp", login=False)])
    assert _only(build_access_map(s), "grp") is None
    assert _only(build_access_map(s, include_nologin=True), "grp") is not None


def test_naming_a_principal_includes_it_even_if_nologin() -> None:
    t = _table(grants=(Grant(role="grp", privileges=_SELECT),))
    s = _schema([t], [_role("grp", login=False)])
    assert _only(build_access_map(s, principals={"grp"}), "grp") is not None


# --- reach through views -----------------------------------------------------
#
# Every case mirrors a hop rule `verify`'s reachability walk measured on PG16.

from pgrls.model import View  # noqa: E402


def _view(
    name: str,
    refs: tuple[tuple[str, str], ...],
    *,
    owner: str,
    invoker: bool = False,
    grants: tuple[Grant, ...] = (),
    super_: bool = False,
    brls: bool = False,
    mat: bool = False,
) -> View:
    return View(
        schema="public", name=name, is_materialized=mat, security_invoker=invoker,
        security_barrier=False, definition="", references=refs,
        security_definer_calls=(), grants=grants, owner=owner,
        owner_bypasses_rls=super_ or brls, direct_references=refs,
        owner_is_superuser=super_,
    )


_T = (("public", "t"),)
_ANON_OPENS = (Grant(role="anon", privileges=_SELECT),)


def _vschema(tables, views, roles, memberships=()) -> Schema:
    return Schema(
        tables=tuple(tables), views=tuple(views), roles=tuple(roles),
        role_memberships=tuple(memberships),
    )


def test_definer_view_owned_by_a_superuser_hands_over_every_row() -> None:
    t = _table(policies=(_policy("tenant", "tenant_id = current_setting('app.t', true)"),))
    v = _view("v", _T, owner="root", super_=True, grants=_ANON_OPENS)
    a = _only(build_access_map(_vschema([t], [v], [_role("anon"), _role("root", su=True)])), "anon")
    assert a is not None and a.rows == "all"
    assert a.paths[0].kind == "view" and a.paths[0].hops == ("public.v", "public.t")
    assert "root" in (a.reason or "")


def test_definer_view_runs_under_the_owners_policies() -> None:
    """An ordinary owner is not exempt: the policies run — against the owner."""
    t = _table(
        grants=(Grant(role="svc", privileges=_SELECT),),
        policies=(_policy("svc_rows", "tenant_id = '1'", roles=("svc",)),),
    )
    v = _view("v", _T, owner="svc", grants=_ANON_OPENS)
    a = _only(build_access_map(_vschema([t], [v], [_role("anon"), _role("svc")])), "anon")
    assert a is not None and a.rows == "filtered" and a.policies == ("svc_rows",)


def test_invoker_view_opens_no_new_door() -> None:
    t = _table(policies=(_policy("tenant", "tenant_id = '1'"),))
    v = _view("v", _T, owner="root", super_=True, invoker=True, grants=_ANON_OPENS)
    assert _only(build_access_map(_vschema([t], [v], [_role("anon"), _role("root", su=True)])),
                 "anon") is None


def test_invoker_hop_resets_to_the_session_user_not_the_enclosing_definer() -> None:
    """Measured: definer(BYPASSRLS owner) → invoker → table returned the
    policy-filtered row, not every row — the invoker hop does not inherit the
    definer's owner.

    The definer's owner must be able to READ the table for this to test
    anything: BYPASSRLS is not a privilege, so without the grant the inherited
    path would be dead either way and the rule would go unexercised (an earlier
    version of this test passed with the rule inverted)."""
    t = _table(
        grants=(Grant(role="brls", privileges=_SELECT),),
        policies=(_policy("tenant", "tenant_id = '1'"),),
    )
    inner = _view("inner", _T, owner="brls", invoker=True)
    outer = _view("outer", (("public", "inner"),), owner="brls", brls=True, grants=_ANON_OPENS)
    amap = build_access_map(
        _vschema([t], [inner, outer], [_role("anon"), _role("brls", brls=True)])
    )
    assert _only(amap, "anon") is None  # the read is anon's own, and anon holds no grant


def test_a_hop_the_owner_cannot_read_is_a_dead_path() -> None:
    """Measured: `permission denied for view inner`, no leak."""
    t = _table()  # owner "owner"; nobody else granted
    v = _view("v", _T, owner="nobody", grants=_ANON_OPENS)
    assert _only(build_access_map(_vschema([t], [v], [_role("anon"), _role("nobody")])),
                 "anon") is None


def test_matview_is_undecided() -> None:
    t = _table()
    mv = _view("mv", _T, owner="root", super_=True, mat=True, grants=_ANON_OPENS)
    a = _only(build_access_map(_vschema([t], [mv], [_role("anon"), _role("root", su=True)])),
              "anon")
    assert a is not None and a.rows == "undecided" and "materialized" in (a.reason or "")


def test_direct_and_view_reach_merge_widest_first() -> None:
    t = _table(
        grants=(Grant(role="anon", privileges=_SELECT),),
        policies=(_policy("tenant", "tenant_id = current_setting('app.t', true)"),),
    )
    v = _view("v", _T, owner="root", super_=True, grants=_ANON_OPENS)
    a = _only(build_access_map(_vschema([t], [v], [_role("anon"), _role("root", su=True)])), "anon")
    assert a is not None
    assert a.rows == "all"  # the view's superuser door dominates the filtered direct read
    assert {p.kind for p in a.paths} == {"grant", "view"}


def test_view_door_reports_the_base_tables_sensitive_columns() -> None:
    """Column lineage through a view is not traced, so a view door reports the
    base table's sensitive columns as reachable — over-reporting sensitivity is
    the safe direction; under-reporting it is the failure this command exists
    to prevent."""
    t = _table()
    v = _view("v", _T, owner="root", super_=True, grants=_ANON_OPENS)
    a = _only(build_access_map(_vschema([t], [v], [_role("anon"), _role("root", su=True)])), "anon")
    assert a is not None and a.columns is None and "email" in a.sensitive


# --- reach through SECURITY DEFINER functions --------------------------------

from pgrls.model import SecdefFunction  # noqa: E402


def _fn(
    body: str,
    *,
    owner: str,
    execute: tuple[str, ...] = ("PUBLIC",),
    lang: str = "sql",
    name: str = "public.f",
) -> SecdefFunction:
    return SecdefFunction(
        qualified_name=name, body=body, language=lang, owner=owner,
        execute_roles=execute, owner_bypasses_rls=False,
    )


def _fschema(tables, fns, roles, memberships=()) -> Schema:
    return Schema(
        tables=tuple(tables), security_definer_functions=tuple(fns),
        roles=tuple(roles), role_memberships=tuple(memberships),
    )


def test_secdef_function_owned_by_a_superuser_hands_over_every_row() -> None:
    t = _table(policies=(_policy("tenant", "tenant_id = current_setting('app.t', true)"),))
    f = _fn("SELECT * FROM t", owner="root")
    a = _only(build_access_map(_fschema([t], [f], [_role("anon"), _role("root", su=True)])), "anon")
    assert a is not None and a.rows == "all"
    assert a.paths[0].kind == "function" and a.paths[0].via == "public.f"


import pytest  # noqa: E402


@pytest.mark.parametrize("ref", ["t", "public.t"])
def test_function_door_reaches_a_non_rls_table_too(ref: str) -> None:
    """Escalation only counts RLS tables; an access map must count every table
    — a definer function reading a non-RLS table is still a door for a caller
    holding no grant on it.

    Both reference forms: the body parser resolves a QUALIFIED ref through one
    table set and a BARE ref through a separate name map, and escalation builds
    both from RLS tables only. An earlier version of this test used only a bare
    ref, so restricting the qualified-ref set went unnoticed."""
    t = _table(rls=False)
    f = _fn(f"SELECT * FROM {ref}", owner="root")
    a = _only(build_access_map(_fschema([t], [f], [_role("anon"), _role("root", su=True)])), "anon")
    assert a is not None and a.rows == "all"


def test_no_execute_means_no_function_door() -> None:
    t = _table()
    f = _fn("SELECT * FROM t", owner="root", execute=("service_role",))
    assert _only(build_access_map(
        _fschema([t], [f], [_role("anon"), _role("root", su=True)])), "anon") is None


def test_execute_inherited_through_a_group() -> None:
    t = _table()
    f = _fn("SELECT * FROM t", owner="root", execute=("readers",))
    amap = build_access_map(_fschema(
        [t], [f], [_role("anon"), _role("readers", login=False), _role("root", su=True)],
        [RoleMembership(member="anon", role="readers", inherit=True)],
    ))
    assert _only(amap, "anon") is not None


def test_owner_that_cannot_read_the_table_is_no_door() -> None:
    """The body raises `permission denied` as its owner — no rows reach the caller."""
    t = _table()  # owned by "owner"; nobody else granted
    f = _fn("SELECT * FROM t", owner="nobody")
    assert _only(build_access_map(
        _fschema([t], [f], [_role("anon"), _role("nobody")])), "anon") is None


def test_bypassrls_owner_without_a_grant_is_no_door() -> None:
    """BYPASSRLS escapes the policies, not the privilege check — the same rule
    as for direct reach."""
    t = _table()
    f = _fn("SELECT * FROM t", owner="brls")
    assert _only(build_access_map(
        _fschema([t], [f], [_role("anon"), _role("brls", brls=True)])), "anon") is None


def test_opaque_body_is_an_unresolved_door_not_a_table_claim() -> None:
    t = _table()
    f = _fn("BEGIN RETURN QUERY SELECT * FROM t; END", owner="root", lang="plpgsql")
    amap = build_access_map(_fschema([t], [f], [_role("anon"), _role("root", su=True)]))
    assert _only(amap, "anon") is None  # not attributed to any table
    [u] = [u for u in amap.unresolved if u.principal == "anon"]
    assert u.function == "public.f" and "opaque" in u.reason


def test_function_owner_flag_alone_is_not_treated_as_superuser() -> None:
    """Without the catalogue, `owner_bypasses_rls` means superuser OR BYPASSRLS
    and cannot be split. Assuming superuser would invent a door the owner has
    no privilege to open; assuming BYPASSRLS does not."""
    t = _table()
    f = SecdefFunction(
        qualified_name="public.f", body="SELECT * FROM t", language="sql",
        owner="ambiguous", execute_roles=("PUBLIC",), owner_bypasses_rls=True,
    )
    s = Schema(tables=(t,), security_definer_functions=(f,),
               roles=(_role("anon"),), role_memberships=())
    assert _only(build_access_map(s), "anon") is None
