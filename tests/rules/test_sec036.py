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
    ],
)
def test_silent_when_subselect_binds_caller(binding: str) -> None:
    expr = (
        f"EXISTS (SELECT 1 FROM auth.users "
        f"WHERE {binding} AND raw_app_meta_data ->> 'role' = 'admin')"
    )
    schema = _wrap(_policy(f"({expr})", name="caller_bound"))
    assert SEC036().check(schema, {}) == [], binding


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
