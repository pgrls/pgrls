"""Unit tests for SEC033 — policy scopes by user-modifiable JWT claim.

SEC033 (error) fires when a policy's USING / WITH CHECK expression
references the `user_metadata` JSON key (in any path/arrow operator
shape) or the `raw_user_meta_data` column directly. Both vectors land
on the same Supabase auth-model footgun: the value is end-user
writable via the auth API, so a policy gating on it is
self-bypassable. Stays silent on the safe counterpart (`app_metadata`
/ `raw_app_meta_data`) and on policies that just happen to mention
the string in a non-load-bearing comment (no string-const match
possible there).
"""
from __future__ import annotations

import pytest

from pgrls.ast_utils import parse_expr
from pgrls.model import Policy, Schema, Table
from pgrls.rules.sec033 import SEC033


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
# Fires — direct `user_metadata` references via JSON operators
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "expr",
    [
        # Arrow / arrow-text
        "auth.jwt() -> 'user_metadata' ->> 'role' = 'admin'",
        "auth.jwt() ->> 'user_metadata' = 'admin'",
        # Path / path-text (text[] argument; key embedded in array)
        "auth.jwt() #> '{user_metadata,role}' = '\"admin\"'",
        "auth.jwt() #>> '{user_metadata,role}' = 'admin'",
        # `raw_user_meta_data` JSON-key form (some templates expose
        # this synonym via a custom JWT-builder helper).
        "auth.jwt() -> 'raw_user_meta_data' ->> 'role' = 'admin'",
    ],
)
def test_fires_on_jwt_user_metadata_subscript(expr: str) -> None:
    schema = _wrap(
        _policy(
            f"({expr})",
            name="user_metadata_role_check",
        )
    )
    # The bare 'raw_user_meta_data' string literal isn't in the
    # default string_keys set — only 'user_metadata' is, plus the
    # column form. Test that case explicitly.
    options: dict[str, object] = (
        {"string_keys": ["user_metadata", "raw_user_meta_data"]}
        if "raw_user_meta_data" in expr
        else {}
    )
    violations = SEC033().check(schema, options)
    assert len(violations) == 1, expr
    assert violations[0].rule_id == "SEC033"
    assert violations[0].severity == "error"
    assert violations[0].location == "public.t.user_metadata_role_check"


def test_fires_in_with_check_clause() -> None:
    schema = _wrap(
        _policy(
            command="INSERT",
            with_check="(auth.jwt() ->> 'user_metadata') IS NOT NULL",
            name="user_metadata_required",
        )
    )
    violations = SEC033().check(schema, {})
    assert len(violations) == 1
    assert violations[0].location == "public.t.user_metadata_required"


def test_fires_on_raw_user_meta_data_column_ref() -> None:
    schema = _wrap(
        _policy(
            using=(
                "(SELECT raw_user_meta_data ->> 'role' FROM auth.users "
                "WHERE id = auth.uid()) = 'admin'"
            ),
            name="lookup_via_auth_users",
        )
    )
    violations = SEC033().check(schema, {})
    assert len(violations) == 1
    assert "raw_user_meta_data" in violations[0].message


def test_fires_on_both_vectors_produces_single_violation() -> None:
    # When both the column ref AND the string-key match in the same
    # policy, the rule emits one finding whose message names both
    # vectors — not two findings.
    schema = _wrap(
        _policy(
            using=(
                "(SELECT raw_user_meta_data -> 'user_metadata' ->> "
                "'role' FROM auth.users WHERE id = auth.uid()) = "
                "'admin'"
            ),
            name="double_vector",
        )
    )
    violations = SEC033().check(schema, {})
    assert len(violations) == 1
    msg = violations[0].message
    assert "user_metadata" in msg
    assert "raw_user_meta_data" in msg


# ──────────────────────────────────────────────────────────────────────
# Silent — `app_metadata` and unrelated patterns
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "expr",
    [
        # The safe counterpart — admin-only, never user-writable
        "auth.jwt() -> 'app_metadata' ->> 'role' = 'admin'",
        "auth.jwt() ->> 'app_metadata' = 'admin'",
        "auth.jwt() #>> '{app_metadata,role}' = 'admin'",
        # Standard owner-scoping shape
        "owner_id = auth.uid()",
        # Top-level claim — `role`, `sub`, etc. are admin-set (or
        # come from the auth provider directly), not user-writable
        "auth.jwt() ->> 'role' = 'admin'",
        "auth.jwt() ->> 'sub' = owner_id::text",
        # GUC-based scoping
        "current_setting('app.uid', true) = owner_id::text",
        # Regression (#2): the string 'user_metadata' as a DATA VALUE,
        # not a JSON key operand of an arrow/path operator.
        "event_type = 'user_metadata'",
        # A JSON *value* that merely equals the key name — the key
        # operand here is 'role', not 'user_metadata'.
        "auth.jwt() ->> 'role' = 'user_metadata'",
        # A bare reference to the metadata column, NOT used as a JSON
        # extraction source — not the self-bypass hazard.
        "raw_user_meta_data IS NOT NULL",
    ],
)
def test_silent_on_safe_shapes(expr: str) -> None:
    schema = _wrap(_policy(f"({expr})", name="safe"))
    violations = SEC033().check(schema, {})
    assert violations == [], expr


def test_silent_when_no_policy_predicate() -> None:
    # PERMISSIVE FOR SELECT … (no USING/WITH CHECK) shouldn't fire —
    # there's no predicate to walk.
    schema = _wrap(_policy(using=None, name="open"))
    violations = SEC033().check(schema, {})
    assert violations == []


# ──────────────────────────────────────────────────────────────────────
# Silent — `user_metadata` nested under the service-role `app_metadata`
# root (regression #6: detection is root-aware, not root-blind)
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "expr",
    [
        # Arrow chain rooted at app_metadata: the end user cannot write
        # inside the service-role-only app_metadata object, so a
        # user_metadata key read under it is trustworthy.
        "auth.jwt() -> 'app_metadata' -> 'user_metadata' ->> 'role' = 'admin'",
        # Path form: app_metadata precedes user_metadata in the path.
        "auth.jwt() #>> '{app_metadata,user_metadata,role}' = 'admin'",
        # Deeper nesting, still rooted at app_metadata.
        "auth.jwt() #> '{app_metadata,nested,user_metadata}' IS NOT NULL",
        # Rooted at the service-role `raw_app_meta_data` column.
        (
            "(SELECT raw_app_meta_data -> 'user_metadata' ->> 'role' "
            "FROM auth.users WHERE id = auth.uid()) = 'admin'"
        ),
    ],
)
def test_silent_on_user_metadata_nested_under_app_metadata(expr: str) -> None:
    schema = _wrap(_policy(f"({expr})", name="nested_safe"))
    violations = SEC033().check(schema, {})
    assert violations == [], expr


# ──────────────────────────────────────────────────────────────────────
# Silent — `user_metadata` key read out of a NON-JWT source (R16 #3):
# a plain application JSONB column is not the user-writable JWT claim
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "expr",
    [
        # `settings` is an ordinary table column, not the verified JWT.
        "settings -> 'user_metadata' ->> 'role' = 'admin'",
        "(settings ->> 'user_metadata') = 'x'",
        # Path form rooted in a plain column.
        "prefs #>> '{user_metadata,role}' = 'admin'",
        # A nested column expression — still not a JWT source.
        "(data -> 'profile') ->> 'user_metadata' = 'x'",
    ],
)
def test_silent_on_user_metadata_from_non_jwt_source(expr: str) -> None:
    # R16 #3: the string-key vector fires only when the JSON-extraction
    # chain roots in the verified JWT (auth.jwt() / the PostgREST
    # request.jwt GUC / the raw_user_meta_data column). A `user_metadata`
    # key read out of a plain application JSONB column is NOT the
    # self-bypass hazard — the value is not the user-controllable JWT
    # claim — so the error-severity rule must stay silent.
    schema = _wrap(_policy(f"({expr})", name="plain_column"))
    violations = SEC033().check(schema, {})
    assert violations == [], expr


# ──────────────────────────────────────────────────────────────────────
# Fires — `user_metadata` read out of a recognized JWT source other than
# the default auth.jwt(): the PostgREST GUC and a configured helper
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "expr",
    [
        # PostgREST: the request.jwt.claims GUC carries the verified JWT.
        (
            "(current_setting('request.jwt.claims', true)::jsonb "
            "-> 'user_metadata' ->> 'role') = 'admin'"
        ),
        # …path form on the same GUC source.
        (
            "((current_setting('request.jwt.claims', true)::jsonb) "
            "#>> '{user_metadata,role}') = 'admin'"
        ),
    ],
)
def test_fires_on_user_metadata_from_postgrest_jwt_guc(expr: str) -> None:
    schema = _wrap(_policy(f"({expr})", name="postgrest_jwt"))
    violations = SEC033().check(schema, {})
    assert len(violations) == 1, expr


def test_jwt_functions_option_gates_a_custom_helper() -> None:
    # A project-local JWT helper is not a recognized source by default
    # (so it does NOT fire — the conservative FP-safe behavior), but
    # configuring `jwt_functions` opens it up.
    schema = _wrap(
        _policy(
            "(my_schema.jwt() ->> 'user_metadata') = 'admin'", name="custom"
        )
    )
    assert SEC033().check(schema, {}) == []
    violations = SEC033().check(
        schema, {"jwt_functions": ["auth.jwt", "my_schema.jwt"]}
    )
    assert len(violations) == 1


def test_rejects_malformed_jwt_functions_option() -> None:
    schema = _wrap(_policy("(auth.jwt() ->> 'user_metadata') = 'x'"))
    with pytest.raises(TypeError, match="jwt_functions"):
        SEC033().check(schema, {"jwt_functions": "auth.jwt"})


# ──────────────────────────────────────────────────────────────────────
# Fires — `user_metadata` is the TOP-LEVEL claim even when app_metadata
# appears deeper in the same chain (root order is what matters)
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "expr",
    [
        # user_metadata is the root claim; app_metadata is just a subkey
        # the end user can still set underneath it.
        "auth.jwt() -> 'user_metadata' -> 'app_metadata' ->> 'role' = 'admin'",
        # Path form: user_metadata precedes app_metadata.
        "auth.jwt() #>> '{user_metadata,app_metadata,role}' = 'admin'",
    ],
)
def test_fires_when_user_metadata_is_root_even_if_app_metadata_below(
    expr: str,
) -> None:
    schema = _wrap(_policy(f"({expr})", name="root_user_metadata"))
    violations = SEC033().check(schema, {})
    assert len(violations) == 1, expr
    assert violations[0].location == "public.t.root_user_metadata"


# ──────────────────────────────────────────────────────────────────────
# Configuration paths
# ──────────────────────────────────────────────────────────────────────


def test_allowlist_exempts_specific_policy() -> None:
    schema = _wrap(
        _policy(
            "(auth.jwt() ->> 'user_metadata' IS NOT NULL)",
            name="intentional_read",
        )
    )
    options = {"allowlist": ["public.t.intentional_read"]}
    violations = SEC033().check(schema, options)
    assert violations == []


def test_string_keys_override_replaces_default() -> None:
    # `string_keys=["custom_field"]` REPLACES the default
    # `["user_metadata"]` — so a policy referencing `user_metadata`
    # is no longer flagged, while one referencing `custom_field` is.
    schema = _wrap(
        _policy(
            "(auth.jwt() ->> 'user_metadata' = 'admin')",
            name="default_key",
        )
    )
    options = {"string_keys": ["custom_field"]}
    assert SEC033().check(schema, options) == []

    schema2 = _wrap(
        _policy(
            "(auth.jwt() ->> 'custom_field' = 'admin')",
            name="custom_key",
        )
    )
    violations = SEC033().check(schema2, options)
    assert len(violations) == 1


def test_column_names_override_replaces_default() -> None:
    schema = _wrap(
        _policy(
            using=(
                "(SELECT user_extra ->> 'role' FROM auth.users "
                "WHERE id = auth.uid()) = 'admin'"
            ),
            name="custom_col",
        )
    )
    options = {
        "string_keys": [],  # disable string-key matching here
        "column_names": ["user_extra"],
    }
    violations = SEC033().check(schema, options)
    assert len(violations) == 1


def test_string_keys_match_is_case_sensitive() -> None:
    # JSON keys are case-sensitive in Postgres jsonb — `User_Metadata`
    # is a different key than `user_metadata`. The rule must not
    # case-fold or it would flag innocent custom keys whose name
    # happens to differ only in case.
    schema = _wrap(
        _policy(
            "(auth.jwt() ->> 'User_Metadata' = 'admin')",
            name="different_case",
        )
    )
    violations = SEC033().check(schema, {})
    assert violations == []


def test_rejects_malformed_string_keys_option() -> None:
    with pytest.raises(TypeError) as exc:
        SEC033().check(_wrap(_policy("(true)")), {"string_keys": "not a list"})
    assert "list of JSON-key strings" in str(exc.value)


def test_rejects_malformed_column_names_option() -> None:
    with pytest.raises(TypeError) as exc:
        SEC033().check(
            _wrap(_policy("(true)")), {"column_names": ["ok", 5]}
        )
    assert "list of bare column names" in str(exc.value)


# ──────────────────────────────────────────────────────────────────────
# Multi-policy + multi-table fan-out
# ──────────────────────────────────────────────────────────────────────


def test_emits_one_violation_per_offending_policy() -> None:
    p_bad1 = _policy(
        "(auth.jwt() ->> 'user_metadata' = 'admin')",
        name="bad1",
    )
    p_bad2 = _policy(
        "(auth.jwt() #>> '{user_metadata,role}' = 'admin')",
        name="bad2",
    )
    p_good = _policy(
        "(auth.jwt() ->> 'app_metadata' = 'admin')",
        name="good",
    )
    schema = Schema(
        tables=(
            Table(
                schema="public",
                name="docs",
                rls_enabled=True,
                force_rls=True,
                policies=(p_bad1, p_bad2, p_good),
                columns=("id",),
            ),
        )
    )
    violations = SEC033().check(schema, {})
    assert len(violations) == 2
    assert {v.location for v in violations} == {
        "public.docs.bad1",
        "public.docs.bad2",
    }


@pytest.mark.parametrize(
    "expr",
    [
        # Regression (round-7): the #>>/#> PATH-operator spelling must honor
        # a server-controlled root in the LEFT operand, like the arrow form.
        # Reading from the service-role raw_app_meta_data column:
        "raw_app_meta_data #>> '{user_metadata,role}' = 'admin'",
        "raw_app_meta_data #> '{user_metadata,role}' IS NOT NULL",
        # Left operand already selects the app_metadata root:
        "(auth.jwt() -> 'app_metadata') #>> '{user_metadata,role}' = 'admin'",
        # Safe root precedes the user key within the same path literal:
        "auth.jwt() #>> '{app_metadata,user_metadata,role}' = 'admin'",
    ],
)
def test_silent_on_path_operator_rooted_in_server_controlled(expr: str) -> None:
    schema = _wrap(_policy(f"({expr})", name="path_safe"))
    assert SEC033().check(schema, {}) == [], expr


@pytest.mark.parametrize(
    "expr",
    [
        # The genuine hazard: user_metadata read as a top-level claim via a
        # path operator (nothing server-controlled root-ward of it).
        "auth.jwt() #>> '{user_metadata,role}' = 'admin'",
        # user_metadata is the ROOT even though app_metadata appears deeper
        # — fires (via the arrow node for the user_metadata key).
        "(auth.jwt() -> 'user_metadata' -> 'app_metadata') #>> '{role}' = 'admin'",
    ],
)
def test_fires_on_path_operator_user_metadata_root(expr: str) -> None:
    schema = _wrap(_policy(f"({expr})", name="path_hazard"))
    violations = SEC033().check(schema, {})
    assert len(violations) == 1, expr
    assert violations[0].location == "public.t.path_hazard"
