"""Unit tests for SEC036.

SEC036 (error) fires when a policy's USING / WITH CHECK expression
has an `EXISTS (SELECT ... FROM auth.users WHERE ...)` clause whose
WHERE body doesn't bind the calling user. Stays silent when the
sub-select WHERE references any of the configured binding functions
(`auth.uid()`, `current_user`, `current_setting(...)`, etc.), and
silent on EXISTS clauses against tables that aren't in the
configured target set.
"""
from __future__ import annotations

import pytest

from pgrls.ast_utils import parse_expr
from pgrls.model import Policy, Schema, Table
from pgrls.rules.sec036 import SEC036


def _policy(
    using: str | None = None,
    *,
    name: str = "p",
    command: str = "SELECT",
    with_check: str | None = None,
    roles: tuple[str, ...] = ("authenticated",),
) -> Policy:
    return Policy(
        name=name,
        command=command,  # type: ignore[arg-type]
        permissive=True,
        roles=roles,
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
                columns=("id", "owner_id", "body"),
            ),
        )
    )


# ──────────────────────────────────────────────────────────────────────
# Fires — EXISTS against auth.users with no caller binding
# ──────────────────────────────────────────────────────────────────────


def test_fires_on_exists_admin_check_without_user_binding() -> None:
    expr = (
        "EXISTS (SELECT 1 FROM auth.users "
        "WHERE raw_app_meta_data ->> 'role' = 'admin')"
    )
    schema = _wrap(_policy(f"({expr})", name="admins_only"))
    violations = SEC036().check(schema, {})
    assert len(violations) == 1
    assert violations[0].rule_id == "SEC036"
    assert violations[0].severity == "error"
    assert violations[0].location == "public.t.admins_only"
    assert "auth.users" in violations[0].message
    assert "auth.uid" in violations[0].message


def test_fires_in_with_check_clause() -> None:
    expr = (
        "EXISTS (SELECT 1 FROM auth.users "
        "WHERE raw_app_meta_data ->> 'role' = 'editor')"
    )
    schema = _wrap(
        _policy(
            command="INSERT",
            with_check=f"({expr})",
            name="any_editor_can_insert",
        )
    )
    violations = SEC036().check(schema, {})
    assert len(violations) == 1
    assert violations[0].location == "public.t.any_editor_can_insert"


def test_fires_on_exists_without_where_clause() -> None:
    # `EXISTS (SELECT 1 FROM auth.users)` — no WHERE at all — is the
    # absolute worst-case version: it's true if the table has any
    # row, which it always does. Make sure we catch it.
    expr = "EXISTS (SELECT 1 FROM auth.users)"
    schema = _wrap(_policy(f"({expr})", name="any_user_exists"))
    violations = SEC036().check(schema, {})
    assert len(violations) == 1


def test_fires_once_per_policy_even_with_multiple_offending_subselects() -> (
    None
):
    # An OR of two unbound EXISTS clauses still emits one violation
    # per policy — the fix is the same single-line edit applied
    # twice, and the message identifies the first offender.
    expr = (
        "EXISTS (SELECT 1 FROM auth.users "
        "WHERE raw_app_meta_data ->> 'role' = 'admin') "
        "OR EXISTS (SELECT 1 FROM auth.users "
        "WHERE raw_app_meta_data ->> 'role' = 'super')"
    )
    schema = _wrap(_policy(f"({expr})", name="any_admin_or_super"))
    violations = SEC036().check(schema, {})
    assert len(violations) == 1


def test_fires_when_target_reached_through_join_without_binding() -> None:
    # Regression (#18): the target table is reached through an explicit
    # JOIN, so the sub-select's `fromClause` holds a `JoinExpr`, not a
    # top-level `RangeVar`. The JOIN's ON quals only correlate the two
    # *inner* tables (`u.id = m.user_id`) — nothing binds the OUTER
    # row to the calling user — so this is the same binding-free bypass
    # ("does any admin membership exist") and must fire. Before the fix
    # the JoinExpr was invisible and SEC036 silently missed it.
    expr = (
        "EXISTS (SELECT 1 FROM memberships m "
        "JOIN auth.users u ON u.id = m.user_id "
        "WHERE u.raw_app_meta_data ->> 'role' = 'admin')"
    )
    schema = _wrap(_policy(f"({expr})", name="join_admin"))
    violations = SEC036().check(schema, {})
    assert len(violations) == 1
    assert violations[0].location == "public.t.join_admin"
    assert "auth.users" in violations[0].message


def test_fires_when_target_is_right_arm_of_nested_join() -> None:
    # The target table sits in the right arm of a nested JOIN tree.
    # The recursion into `JoinExpr.larg`/`.rarg` must reach it.
    expr = (
        "EXISTS (SELECT 1 FROM a "
        "JOIN b ON a.id = b.a_id "
        "JOIN auth.users u ON u.id = b.user_id "
        "WHERE u.raw_app_meta_data ->> 'role' = 'admin')"
    )
    schema = _wrap(_policy(f"({expr})", name="nested_join"))
    assert len(SEC036().check(schema, {})) == 1


# ──────────────────────────────────────────────────────────────────────
# Silent — caller binding present, or non-target table, or wrong shape
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "binding",
    [
        "id = auth.uid()",
        "auth.uid() = id",
        "id = (SELECT auth.uid())",  # PERF001-wrapped form
        "current_user = (id::text)",
        "current_setting('request.jwt.claim.sub', true)::uuid = id",
        # R19 #1: IN / `= ANY` sub-query binding. Postgres parses both as
        # ANY_SUBLINK; a single-target `SELECT auth.uid()` genuinely binds
        # the caller, exactly like the scalar EXPR_SUBLINK form above.
        "id IN (SELECT auth.uid())",
        "id = ANY(SELECT auth.uid())",
    ],
)
def test_silent_when_subselect_binds_caller(binding: str) -> None:
    expr = (
        f"EXISTS (SELECT 1 FROM auth.users "
        f"WHERE {binding} AND raw_app_meta_data ->> 'role' = 'admin')"
    )
    schema = _wrap(_policy(f"({expr})", name="caller_bound"))
    assert SEC036().check(schema, {}) == [], binding


def test_silent_when_join_on_clause_binds_caller() -> None:
    # Regression (#18) precision: a JOIN to the target whose ON clause
    # binds the caller (`u.id = auth.uid()`) IS correctly scoped — the
    # binding check must inspect JOIN ON quals, not only the top-level
    # WHERE, or this correctly-written policy would false-fire.
    expr = (
        "EXISTS (SELECT 1 FROM memberships m "
        "JOIN auth.users u ON u.id = auth.uid() "
        "WHERE u.raw_app_meta_data ->> 'role' = 'admin')"
    )
    schema = _wrap(_policy(f"({expr})", name="join_caller_bound"))
    assert SEC036().check(schema, {}) == []


def test_fires_on_admin_any_with_unrelated_nested_auth_call() -> None:
    # Regression (#1): the admin-any EXISTS is unbound — its WHERE only
    # checks `role = 'admin'`. The auth.uid() lives in an UNRELATED
    # nested EXISTS (a correlated audit sub-select), a separate
    # existence test, not a binding of the outer EXISTS. The binding
    # search must NOT descend into it, or this real
    # every-authenticated-user bypass ships as clean.
    expr = (
        "EXISTS (SELECT 1 FROM auth.users u "
        "WHERE u.raw_app_meta_data ->> 'role' = 'admin' "
        "AND EXISTS (SELECT 1 FROM audit_log a WHERE a.actor = auth.uid()))"
    )
    schema = _wrap(_policy(f"({expr})", name="admin_any_distractor"))
    [v] = SEC036().check(schema, {})
    assert v.rule_id == "SEC036"


def test_fires_when_any_subquery_is_not_a_single_auth_target() -> None:
    # R19 #1 tightness: the IN/ANY binding exception is gated to a
    # single-target `SELECT <auth call>`. A membership-style ANY sub-query
    # whose auth call lives in its WHERE (the target is an unrelated
    # column) is NOT a recognized binding — descending into arbitrary
    # ANY/ALL bodies would let an unrelated nested auth call mask a real
    # admin-any leak (the deliberately-preserved false-negative-avoidance,
    # mirroring the nested-EXISTS distractor above). So this still fires.
    expr = (
        "EXISTS (SELECT 1 FROM auth.users u "
        "WHERE u.raw_app_meta_data ->> 'role' = 'admin' "
        "AND u.id = ANY(SELECT m.user_id FROM memberships m "
        "WHERE m.owner = auth.uid()))"
    )
    schema = _wrap(_policy(f"({expr})", name="membership_any_distractor"))
    assert len(SEC036().check(schema, {})) == 1


def test_silent_on_scalar_wrap_binding_not_confused_with_nested_exists() -> None:
    # Precision companion to the distractor: a scalar `(SELECT
    # auth.uid())` value sub-select DOES bind (the PERF001 wrap), so the
    # binding search must still descend into EXPR_SUBLINK subselects.
    expr = (
        "EXISTS (SELECT 1 FROM auth.users u "
        "WHERE u.id = (SELECT auth.uid()) "
        "AND u.raw_app_meta_data ->> 'role' = 'admin')"
    )
    schema = _wrap(_policy(f"({expr})", name="scalar_wrap_bound"))
    assert SEC036().check(schema, {}) == []


def test_fires_when_target_reached_through_from_subselect() -> None:
    # Regression (#14): the target table sits inside a derived table
    # (`FROM (SELECT * FROM auth.users) sub`). The FROM walk must
    # recurse into the sub-select's own FROM, or the unbound admin-any
    # EXISTS is invisible.
    expr = (
        "EXISTS (SELECT 1 FROM (SELECT * FROM auth.users) sub "
        "WHERE sub.raw_app_meta_data ->> 'role' = 'admin')"
    )
    schema = _wrap(_policy(f"({expr})", name="target_via_subselect"))
    [v] = SEC036().check(schema, {})
    assert v.rule_id == "SEC036"


def test_silent_when_from_subselect_target_is_caller_bound() -> None:
    # Precision for #14: the same derived-table shape, but the EXISTS
    # binds the caller — must stay silent.
    expr = (
        "EXISTS (SELECT 1 FROM (SELECT * FROM auth.users) sub "
        "WHERE sub.id = auth.uid())"
    )
    schema = _wrap(_policy(f"({expr})", name="subselect_bound"))
    assert SEC036().check(schema, {}) == []


def test_silent_when_binding_lives_inside_a_derived_table() -> None:
    # Regression (round-2 #4): target detection recurses into a derived
    # table (round-1 #14), so the binding check must too. A policy that
    # binds the caller INSIDE the derived table's own WHERE is correctly
    # scoped and must stay silent — otherwise the target is found one
    # level down but the binding there is never inspected (false positive).
    expr = (
        "EXISTS (SELECT 1 FROM "
        "(SELECT id FROM auth.users WHERE id = auth.uid()) sub "
        "WHERE sub.id IS NOT NULL)"
    )
    schema = _wrap(_policy(f"({expr})", name="bound_in_derived"))
    assert SEC036().check(schema, {}) == []


def test_silent_on_in_subselect_against_auth_users() -> None:
    # The IN/ANY variant has a different failure mode (rows owned by
    # any admin, not all rows when any admin exists). SEC036 is
    # scoped to EXISTS deliberately. The IN variant is a future
    # rule's territory.
    expr = (
        "owner_id IN (SELECT id FROM auth.users "
        "WHERE raw_app_meta_data ->> 'role' = 'admin')"
    )
    schema = _wrap(_policy(f"({expr})", name="any_admin_owns"))
    assert SEC036().check(schema, {}) == []


def test_silent_on_exists_against_non_target_table() -> None:
    # `public.profiles` isn't in the default target set, so an
    # unbound EXISTS against it doesn't fire — until the operator
    # adds it explicitly via [lint.rules.SEC036].target_tables.
    expr = (
        "EXISTS (SELECT 1 FROM public.profiles "
        "WHERE role = 'admin')"
    )
    schema = _wrap(_policy(f"({expr})", name="profiles_admin"))
    assert SEC036().check(schema, {}) == []


def test_silent_on_unqualified_users_reference() -> None:
    # `FROM users` (no schema qualifier) is search-path-dependent —
    # could be auth.users, could be public.users, depends on the
    # caller's session. We don't fire without a clear schema match.
    expr = "EXISTS (SELECT 1 FROM users WHERE role = 'admin')"
    schema = _wrap(_policy(f"({expr})", name="users_bare"))
    assert SEC036().check(schema, {}) == []


def test_silent_when_no_policy_predicate() -> None:
    schema = _wrap(_policy(using=None, name="open"))
    assert SEC036().check(schema, {}) == []


def test_silent_on_owner_scoped_policy_without_exists() -> None:
    # The canonical correct shape doesn't trip SEC036 at all — no
    # SubLink to walk.
    schema = _wrap(
        _policy("(owner_id = auth.uid())", name="owner_scoped")
    )
    assert SEC036().check(schema, {}) == []


# ──────────────────────────────────────────────────────────────────────
# Configuration paths
# ──────────────────────────────────────────────────────────────────────


def test_target_tables_override_adds_custom_user_table() -> None:
    expr = (
        "EXISTS (SELECT 1 FROM public.profiles "
        "WHERE role = 'admin')"
    )
    schema = _wrap(_policy(f"({expr})", name="profiles_admin"))
    options = {"target_tables": ["auth.users", "public.profiles"]}
    violations = SEC036().check(schema, options)
    assert len(violations) == 1
    assert "public.profiles" in violations[0].message


def test_target_tables_override_replaces_default() -> None:
    # Setting only `public.profiles` means `auth.users` no longer
    # fires — list-replace, not list-merge, matching the project
    # convention (SEC004, SEC033, etc.).
    expr = (
        "EXISTS (SELECT 1 FROM auth.users "
        "WHERE raw_app_meta_data ->> 'role' = 'admin')"
    )
    schema = _wrap(_policy(f"({expr})", name="auth_admin"))
    options = {"target_tables": ["public.profiles"]}
    assert SEC036().check(schema, options) == []


def test_binding_functions_override_replaces_default() -> None:
    # If your project uses `app.user_id()` as the binding function
    # name, the default set won't match and the policy would
    # mis-fire — overriding to include it silences the rule.
    expr = (
        "EXISTS (SELECT 1 FROM auth.users "
        "WHERE id = app.user_id() "
        "AND raw_app_meta_data ->> 'role' = 'admin')"
    )
    schema = _wrap(_policy(f"({expr})", name="custom_binding"))
    options = {"binding_functions": ["app.user_id"]}
    assert SEC036().check(schema, options) == []


def test_allowlist_exempts_specific_policy() -> None:
    expr = "EXISTS (SELECT 1 FROM auth.users WHERE deleted_at IS NULL)"
    schema = _wrap(_policy(f"({expr})", name="intentional_any_user"))
    options = {"allowlist": ["public.t.intentional_any_user"]}
    assert SEC036().check(schema, options) == []


def test_rejects_malformed_target_tables_option() -> None:
    with pytest.raises(TypeError) as exc:
        SEC036().check(
            _wrap(_policy("(true)")), {"target_tables": "auth.users"}
        )
    assert "list" in str(exc.value)


def test_rejects_target_table_without_schema_qualifier() -> None:
    with pytest.raises(TypeError) as exc:
        SEC036().check(
            _wrap(_policy("(true)")), {"target_tables": ["users"]}
        )
    assert "schema.table" in str(exc.value)


def test_rejects_malformed_binding_functions_option() -> None:
    with pytest.raises(TypeError) as exc:
        SEC036().check(
            _wrap(_policy("(true)")),
            {"binding_functions": ["auth.uid", 7]},
        )
    assert "function names" in str(exc.value)


def test_sec036_fires_on_setop_union_subselect_reaching_target() -> None:
    # Regression (round-7): a set-op (UNION/INTERSECT/EXCEPT) sub-select
    # puts its FROM items in larg/rarg, not fromClause. An unbound
    # admin-any EXISTS reaching auth.users through a UNION arm must still
    # be flagged (the every-authenticated-user bypass SEC036 exists for).
    expr = (
        "EXISTS (SELECT 1 FROM auth.users "
        "WHERE raw_app_meta_data ->> 'role' = 'admin' "
        "UNION SELECT 1 FROM other_t)"
    )
    schema = _wrap(_policy(f"({expr})", name="setop_unbound"))
    violations = SEC036().check(schema, {})
    assert len(violations) == 1
    assert violations[0].location == "public.t.setop_unbound"


def test_sec036_silent_on_setop_union_bound_to_caller() -> None:
    # Lockstep: a correctly-bound set-op EXISTS (the binding lives in an
    # arm's WHERE) must NOT false-fire now that target detection is
    # set-op-aware.
    expr = (
        "EXISTS (SELECT 1 FROM auth.users WHERE id = auth.uid() "
        "UNION SELECT 1 FROM other_t)"
    )
    schema = _wrap(_policy(f"({expr})", name="setop_bound"))
    assert SEC036().check(schema, {}) == []


def test_sec036_fires_on_setop_nested_in_derived_table() -> None:
    # Regression (round-10 #5): the target scan recursed a derived
    # table's `fromClause` directly, so a derived table that is itself a
    # set operation — `FROM (SELECT id FROM auth.users UNION SELECT …) s`,
    # whose FROM items live in larg/rarg — was invisible and the unbound
    # admin-any EXISTS slipped through. It must now be flagged.
    expr = (
        "EXISTS (SELECT 1 FROM ("
        "SELECT id FROM auth.users UNION SELECT id FROM other_t"
        ") s WHERE s.id IS NOT NULL)"
    )
    schema = _wrap(_policy(f"({expr})", name="derived_setop_unbound"))
    violations = SEC036().check(schema, {})
    assert len(violations) == 1
    assert violations[0].location == "public.t.derived_setop_unbound"


def test_sec036_silent_on_setop_nested_in_derived_table_bound() -> None:
    # Lockstep: a binding inside the derived set-op's arm (WHERE) must
    # keep it silent — the binding scan already descends derived-table
    # set-ops, so target detection becoming set-op-aware here must not
    # introduce a false positive.
    expr = (
        "EXISTS (SELECT 1 FROM ("
        "SELECT id FROM auth.users WHERE id = auth.uid() "
        "UNION SELECT id FROM other_t WHERE id = auth.uid()"
        ") s)"
    )
    schema = _wrap(_policy(f"({expr})", name="derived_setop_bound"))
    assert SEC036().check(schema, {}) == []


def test_sec036_silent_on_having_clause_binding() -> None:
    # Regression (round-7): a HAVING-clause binding constrains the EXISTS
    # to the caller exactly like a WHERE binding. Omitting havingClause
    # from the candidate quals false-fired at error severity.
    for expr in (
        "EXISTS (SELECT 1 FROM auth.users GROUP BY id HAVING id = auth.uid())",
        "EXISTS (SELECT 1 FROM auth.users HAVING bool_or(id = auth.uid()))",
    ):
        schema = _wrap(_policy(f"({expr})", name="having_bound"))
        assert SEC036().check(schema, {}) == [], expr
