"""Unit tests for SEC018 — own column compared against current_user.

SEC018 fires when a policy's USING / WITH CHECK expression compares
a column of the policy's OWN table against `current_user` (or its
`current_role` / `user` aliases) or `session_user` — the
tenant-discriminator anti-pattern. It deliberately does NOT fire
when `current_user` is passed to a role/privilege function
(`pg_has_role(current_user, …)`), compared only to a literal
(`current_user = 'postgres'`), or compared to a non-own-table
column (a `pg_roles` catalog lookup) — all legitimate admin/role
checks.
"""
from __future__ import annotations

import pytest

from pgrls.ast_utils import parse_expr
from pgrls.model import Policy, Schema, Table
from pgrls.rules.sec018 import SEC018


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


def _wrap(
    policy: Policy, *, columns: tuple[str, ...] = ("id", "owner_role", "member_roles")
) -> Schema:
    return Schema(
        tables=(
            Table(
                schema="public",
                name="t",
                rls_enabled=True,
                force_rls=True,
                policies=(policy,),
                columns=columns,
            ),
        )
    )


# --- fires: own column compared against a role-identity function ---------


def test_sec018_fires_on_column_eq_current_user() -> None:
    schema = _wrap(_policy("owner_role = current_user"))
    [v] = SEC018().check(schema, {})
    assert v.rule_id == "SEC018"
    assert v.severity == "warning"
    assert v.location == "public.t.p"
    assert "current_user" in v.message
    assert "[lint.rules.SEC018]" in v.message


def test_sec018_fires_on_session_user() -> None:
    assert len(SEC018().check(_wrap(_policy("owner_role = session_user")), {})) == 1


def test_sec018_fires_on_current_role_alias() -> None:
    assert len(SEC018().check(_wrap(_policy("owner_role = current_role")), {})) == 1


def test_sec018_fires_on_user_keyword_alias() -> None:
    # The bare `user` keyword is `current_user` — Postgres parses it
    # as a SQLValueFunction too (a distinct op, same node type).
    assert len(SEC018().check(_wrap(_policy("owner_role = user")), {})) == 1


def test_sec018_fires_with_role_identity_on_the_left() -> None:
    # The comparison is symmetric — role identity on either operand.
    assert len(SEC018().check(_wrap(_policy("current_user = owner_role")), {})) == 1


def test_sec018_fires_on_any_against_array_column() -> None:
    # `current_user = ANY(<own array column>)` is still an own-column
    # comparison — the role identity is matched against row data.
    schema = _wrap(_policy("current_user = ANY(member_roles)"))
    assert len(SEC018().check(schema, {})) == 1


def test_sec018_silent_on_concat_with_role_identity() -> None:
    # R11 #4: `||` combines current_user INTO a composite value rather
    # than comparing a column against it. Neither `owner_role ||
    # current_user` (top operator is `||`, not a comparison) nor
    # `audit_key = owner_role || current_user` (current_user is buried in
    # the rhs `||`, not the direct operand) is a column-keyed-off-role
    # check.
    cols = ("id", "owner_role", "audit_key")
    for using in (
        "owner_role || current_user",
        "audit_key = owner_role || current_user",
        "audit_key = current_user || ':' || owner_role",
    ):
        assert SEC018().check(
            _wrap(_policy(using), columns=cols), {}
        ) == [], using


def test_sec018_fires_on_inequality_and_function_wrapped_column() -> None:
    # The role identity must be the DIRECT operand, but the OWN-COLUMN
    # side may be wrapped — `lower(owner_role) = current_user` is still
    # the anti-pattern. Inequality comparisons stay in scope per the
    # rule's documented "= or another comparison".
    for using in (
        "owner_role <> current_user",
        "owner_role > session_user",
        "lower(owner_role) = current_user",
    ):
        assert len(SEC018().check(_wrap(_policy(using)), {})) == 1, using


def test_sec018_fires_when_only_in_with_check() -> None:
    p = _policy(with_check="owner_role = current_user", command="INSERT")
    assert len(SEC018().check(_wrap(p), {})) == 1


def test_sec018_fires_on_table_qualified_own_column() -> None:
    # `t.owner_role = current_user` — a table-qualified own-column
    # reference. The 2-part form resolves against the policy's table
    # (`t`) just like the bare form, so SEC018 still fires.
    schema = _wrap(_policy("t.owner_role = current_user"))
    [v] = SEC018().check(schema, {})
    assert v.location == "public.t.p"


def test_sec018_fires_on_schema_qualified_own_column() -> None:
    # `public.t.owner_role = current_user` — a fully schema-qualified
    # own-column reference. The 3-part form resolves against the
    # policy's `schema.table` and SEC018 fires the same as the bare
    # and table-qualified forms.
    schema = _wrap(_policy("public.t.owner_role = current_user"))
    [v] = SEC018().check(schema, {})
    assert v.location == "public.t.p"


def test_sec018_silent_on_schema_qualified_cross_table_column() -> None:
    # `public.other.owner_role = current_user` — a 3-part ref whose
    # table part is NOT the policy's table. The schema matches but the
    # table doesn't, so `_is_own_column_ref` rejects it and SEC018
    # stays silent (the column belongs to a different relation).
    schema = _wrap(_policy("public.other.owner_role = current_user"))
    assert SEC018().check(schema, {}) == []


def test_sec018_silent_on_four_part_qualified_column() -> None:
    # `mydb.public.t.owner_role = current_user` — a four-part
    # database-qualified ref. SEC018 resolves only 1/2/3-part own-column
    # shapes; a 4-part ref falls through to the resolver's final
    # `return False`, so the comparison isn't treated as an own-column
    # vs. role-identity pairing and SEC018 stays silent.
    schema = _wrap(_policy("mydb.public.t.owner_role = current_user"))
    assert SEC018().check(schema, {}) == []


def test_sec018_fires_on_correlated_own_column_in_subquery() -> None:
    # An own-table column compared to current_user, reached through
    # correlation from inside a sub-select, still fires — the walk
    # recurses and `t.owner_role` resolves to the policy's table.
    schema = _wrap(
        _policy(
            "EXISTS (SELECT 1 FROM acl a "
            "WHERE a.doc_id = t.id AND t.owner_role = current_user)"
        )
    )
    assert len(SEC018().check(schema, {})) == 1


# --- silent: legitimate uses of current_user -----------------------------


def test_sec018_silent_on_pg_has_role_admin_escape() -> None:
    # `pg_has_role(current_user, 'admin', 'MEMBER')` passes
    # current_user to a role-membership check — the standard admin
    # escape, not a tenant key. SEC018 must NOT fire.
    schema = _wrap(
        _policy("pg_has_role(current_user, 'pg_read_all_data', 'MEMBER')")
    )
    assert SEC018().check(schema, {}) == []


def test_sec018_silent_on_current_user_compared_to_literal() -> None:
    # `current_user = 'postgres'` checks for one specific role (a
    # superuser/admin escape). No column operand — SEC018 silent.
    schema = _wrap(_policy("current_user = 'postgres'"))
    assert SEC018().check(schema, {}) == []


def test_sec018_silent_on_catalog_role_lookup() -> None:
    # A superuser check written as a pg_roles catalog lookup —
    # `pg_roles.rolname` is a catalog column, not the policy table's
    # own column, so the own-column scoping leaves it alone. This is
    # the same admin-escape family as the literal/pg_has_role cases.
    schema = _wrap(
        _policy(
            "EXISTS (SELECT 1 FROM pg_roles "
            "WHERE rolname = current_user AND rolsuper)"
        )
    )
    assert SEC018().check(schema, {}) == []


def test_sec018_silent_on_cross_table_subquery_comparison() -> None:
    # `current_user` compared to a column of ANOTHER table inside a
    # sub-select (a membership lookup) is a known false negative:
    # only the policy's own-table columns are in scope. Pin the
    # documented behavior so a future scoping change is deliberate.
    schema = _wrap(
        _policy("id IN (SELECT doc_id FROM acl WHERE acl_member = current_user)")
    )
    assert SEC018().check(schema, {}) == []


def test_sec018_silent_on_own_column_eq_subquery_using_current_user() -> None:
    # `owner_role = (SELECT … WHERE m = current_user)` is NOT an
    # own-column-vs-current_user comparison: current_user is buried
    # in the sub-select, compared there to another table's column,
    # and the sub-select's *result* is what `owner_role` is matched
    # against. The per-operand checks use exclude_sublinks, so the
    # outer A_Expr does not pair `owner_role` with that nested
    # current_user. SEC018 must stay silent.
    schema = _wrap(
        _policy(
            "owner_role = (SELECT r FROM tenant_defaults "
            "WHERE created_by = current_user)"
        )
    )
    assert SEC018().check(schema, {}) == []


def test_sec018_silent_on_tenant_guc_with_pg_has_role_escape() -> None:
    # The real-world pattern: tenant isolation via a session GUC,
    # plus a pg_has_role admin escape. No own column is compared
    # against current_user, so SEC018 stays silent.
    schema = _wrap(
        _policy(
            "tenant_id = current_setting('app.tenant', true) "
            "OR pg_has_role(current_user, 'pg_read_all_data', 'MEMBER')"
        )
    )
    assert SEC018().check(schema, {}) == []


def test_sec018_silent_on_current_setting_policy() -> None:
    # The recommended pattern — a per-request session GUC — must
    # NOT fire. current_setting is not a role-identity function.
    schema = _wrap(
        _policy("owner_role = current_setting('app.tenant_id')")
    )
    assert SEC018().check(schema, {}) == []


def test_sec018_silent_on_plain_column_predicate() -> None:
    assert SEC018().check(_wrap(_policy("id = 1")), {}) == []


def test_sec018_silent_when_policy_has_no_clauses() -> None:
    # A policy whose USING and WITH CHECK both parsed to None — an
    # empty clause, or a parse failure that left the AST unset —
    # has nothing for SEC018 to walk.
    schema = _wrap(_policy(using=None, with_check=None))
    assert SEC018().check(schema, {}) == []


def test_sec018_silent_when_table_columns_unknown() -> None:
    # Without a column list — a `Table` constructed without one —
    # SEC018 cannot resolve own-table columns and skips the table,
    # the same degradation SEC005 has.
    schema = _wrap(_policy("owner_role = current_user"), columns=())
    assert SEC018().check(schema, {}) == []


def test_sec018_bare_name_collision_is_a_known_false_positive() -> None:
    # Own-table membership is resolved by column NAME. When a
    # sub-select's unqualified column collides with an own-table
    # column name, SEC018 (mis-)flags it. Here the policy table has
    # its own `rolname` column, so the pg_roles catalog lookup's
    # bare `rolname` is treated as own-table — a documented false
    # positive (the bare-name imprecision SEC005 also carries).
    # Pin it so a future scope-resolution change is deliberate.
    schema = _wrap(
        _policy("EXISTS (SELECT 1 FROM pg_roles WHERE rolname = current_user)"),
        columns=("id", "rolname"),
    )
    assert len(SEC018().check(schema, {})) == 1


# --- allowlist / multiplicity / metadata ---------------------------------


def test_sec018_allowlist_exempts_qualified_policy_id() -> None:
    # Role-per-tenant deployments legitimately compare a column to
    # current_user; the allowlist silences SEC018 after confirming
    # the deployment model.
    schema = _wrap(_policy("owner_role = current_user"))
    assert SEC018().check(schema, {"allowlist": ["public.t.p"]}) == []


def test_sec018_fires_once_per_policy_with_multiple_comparisons() -> None:
    schema = _wrap(
        _policy("owner_role = current_user OR owner_role = session_user")
    )
    assert len(SEC018().check(schema, {})) == 1


def test_sec018_fires_on_each_offending_policy_independently() -> None:
    schema = Schema(
        tables=(
            Table(
                schema="public",
                name="t",
                rls_enabled=True,
                force_rls=True,
                columns=("id", "owner_role"),
                policies=(
                    _policy("owner_role = current_user", name="bad_a"),
                    _policy("id = 1", name="ok"),
                    _policy("owner_role = session_user", name="bad_b"),
                ),
            ),
        )
    )
    locations = sorted(v.location for v in SEC018().check(schema, {}))
    assert locations == ["public.t.bad_a", "public.t.bad_b"]


def test_sec018_bad_allowlist_type_raises_clearly() -> None:
    schema = _wrap(_policy("owner_role = current_user"))
    with pytest.raises(TypeError, match="allowlist"):
        SEC018().check(schema, {"allowlist": "public.t.p"})  # type: ignore[dict-item]


def test_sec018_message_recommends_session_guc() -> None:
    # The message must point operators at the fix (a session GUC /
    # JWT claim) and acknowledge the role-per-tenant exception.
    schema = _wrap(_policy("owner_role = current_user"))
    [v] = SEC018().check(schema, {})
    assert "current_setting" in v.message
    assert "role-per-tenant" in v.message


def test_sec018_metadata_present() -> None:
    rule = SEC018()
    assert rule.id == "SEC018"
    assert rule.severity == "warning"
    assert rule.title
