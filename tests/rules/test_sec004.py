"""Unit tests for SEC004 — inverted auth check (Lovable CVE pattern)."""
from __future__ import annotations

from pgrls.ast_utils import parse_expr
from pgrls.model import Policy, Schema, Table
from pgrls.rules.sec004 import SEC004


def _policy_with_using(using: str) -> Policy:
    return Policy(
        name="p",
        command="SELECT",
        permissive=True,
        roles=("authenticated",),
        using_sql=using,
        with_check_sql=None,
        using_ast=parse_expr(using),
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
            ),
        )
    )


def test_sec004_fires_on_auth_uid_is_null_disjunct() -> None:
    schema = _wrap(
        _policy_with_using("auth.uid() IS NULL OR user_id = '1'")
    )
    violations = SEC004().check(schema, {})
    assert len(violations) == 1
    assert violations[0].rule_id == "SEC004"
    assert violations[0].location == "public.t.p"


def test_sec004_fires_on_current_setting_is_null_disjunct() -> None:
    schema = _wrap(
        _policy_with_using(
            "current_setting('jwt.uid', true) IS NULL OR user_id = '1'"
        )
    )
    assert len(SEC004().check(schema, {})) == 1


def test_sec004_silent_on_never_null_role_svfops_by_default() -> None:
    # R11 #1: current_user / session_user / current_role / user ALWAYS
    # return the session role name — Postgres has no unauthenticated
    # backend (PostgREST's "anon" is a real role), so `<svfop> IS NULL`
    # is the constant FALSE and the disjunct is dead, not an
    # anonymous-read hole. Flagging it is a false positive, so these are
    # no longer in the default auth-function set.
    for using in (
        "current_user IS NULL OR user_id = '1'",
        "session_user IS NULL OR user_id = '1'",
        "current_role IS NULL OR user_id = '1'",
        "user IS NULL OR user_id = '1'",
    ):
        assert SEC004().check(_wrap(_policy_with_using(using)), {}) == [], using


def test_sec004_fires_on_never_null_svfop_when_explicitly_configured() -> None:
    # The mechanism still honors an explicit opt-in: a project that
    # configures current_user into the auth set gets it flagged. (The
    # default just no longer assumes it.)
    schema = _wrap(
        _policy_with_using("current_user IS NULL OR user_id = '1'")
    )
    assert len(
        SEC004().check(schema, {"auth_functions": ["current_user"]})
    ) == 1


def test_sec004_does_not_fire_on_is_not_null() -> None:
    schema = _wrap(
        _policy_with_using("auth.uid() IS NOT NULL AND user_id = '1'")
    )
    assert SEC004().check(schema, {}) == []


def test_sec004_does_not_fire_on_plain_equality() -> None:
    schema = _wrap(_policy_with_using("auth.uid() = user_id"))
    assert SEC004().check(schema, {}) == []


def test_sec004_does_not_fire_on_coalesce_wrapper() -> None:
    # Documented blind spot — coalesce variants aren't shaped as IS NULL.
    schema = _wrap(
        _policy_with_using(
            "coalesce(auth.uid(), '') = '' OR user_id = '1'"
        )
    )
    assert SEC004().check(schema, {}) == []


def test_sec004_does_not_fire_when_only_inside_subquery() -> None:
    # Subquery-internal IS NULL is not a top-level disjunct.
    schema = _wrap(
        _policy_with_using(
            "user_id IN (SELECT id FROM users WHERE auth.uid() IS NULL)"
        )
    )
    assert SEC004().check(schema, {}) == []


def test_sec004_skips_policy_without_using_ast() -> None:
    schema = _wrap(
        Policy(
            name="p",
            command="SELECT",
            permissive=True,
            roles=("authenticated",),
            using_sql=None,
            with_check_sql=None,
            using_ast=None,
        )
    )
    assert SEC004().check(schema, {}) == []


def test_sec004_auth_functions_config_overrides_default() -> None:
    schema = _wrap(
        _policy_with_using("auth.uid() IS NULL OR user_id = '1'")
    )
    # Override removes auth.uid from the auth set; rule should not fire.
    assert SEC004().check(
        schema, {"auth_functions": ["my.custom_auth"]}
    ) == []


def test_sec004_bad_auth_functions_type_raises_clearly() -> None:
    import pytest
    schema = _wrap(_policy_with_using("auth.uid() IS NULL OR a = 1"))
    with pytest.raises(TypeError, match="auth_functions"):
        SEC004().check(
            schema, {"auth_functions": "auth.uid"}  # type: ignore[dict-item]
        )


def test_sec004_bad_auth_functions_item_type_raises_clearly() -> None:
    import pytest
    schema = _wrap(_policy_with_using("auth.uid() IS NULL OR a = 1"))
    with pytest.raises(TypeError, match="auth_functions"):
        SEC004().check(
            schema,
            {"auth_functions": ["auth.uid", 42]},  # type: ignore[list-item]
        )


def test_sec004_emits_only_one_violation_per_policy() -> None:
    # Two qualifying disjuncts in the same policy must still produce one
    # violation — the rule reports per-policy, not per-disjunct.
    schema = _wrap(
        _policy_with_using(
            "auth.uid() IS NULL OR current_user IS NULL OR user_id = '1'"
        )
    )
    violations = SEC004().check(schema, {})
    assert len(violations) == 1


def test_sec004_fires_on_with_check_disjunct_not_just_using() -> None:
    # Document current behavior: SEC004 inspects USING only, not WITH CHECK.
    # This test pins that decision so a future change is intentional.
    policy = Policy(
        name="p",
        command="UPDATE",
        permissive=True,
        roles=("authenticated",),
        using_sql="user_id = '1'",
        with_check_sql="auth.uid() IS NULL OR user_id = '1'",
        using_ast=parse_expr("user_id = '1'"),
        with_check_ast=parse_expr(
            "auth.uid() IS NULL OR user_id = '1'"
        ),
    )
    schema = _wrap(policy)
    assert SEC004().check(schema, {}) == []


def test_sec004_default_set_covers_auth_role() -> None:
    schema = _wrap(
        _policy_with_using("auth.role() IS NULL OR user_id = '1'")
    )
    assert len(SEC004().check(schema, {})) == 1


def test_sec004_fires_on_nested_right_or_disjunct() -> None:
    # The natural authoring order — real checks first, anonymous escape
    # parenthesized last — must still be flagged. pglast preserves the
    # explicit parens as a nested OR BoolExpr; flatten_or_disjuncts
    # recurses through it so the trailing `auth.uid() IS NULL` is seen.
    # Truth-value-identical to the flat form, which was already caught.
    schema = _wrap(
        _policy_with_using(
            "is_admin = true OR (owner_id = auth.uid() OR auth.uid() IS NULL)"
        )
    )
    violations = SEC004().check(schema, {})
    assert len(violations) == 1
    assert violations[0].location == "public.t.p"


def test_sec004_fires_on_deeply_nested_or_disjunct() -> None:
    # Recursion must reach an IS NULL nested several OR-levels deep.
    schema = _wrap(
        _policy_with_using(
            "a = 1 OR (b = 2 OR (c = 3 OR auth.uid() IS NULL))"
        )
    )
    assert len(SEC004().check(schema, {})) == 1


def test_sec004_does_not_fire_on_is_null_gated_by_nested_and() -> None:
    # An IS NULL under an AND is NOT a standalone anonymous-access hole:
    # the AND still requires `b = 2`, so an anonymous connection (auth
    # NULL) does not automatically satisfy the policy. flatten_or_disjuncts
    # must NOT flatten through AND, so the AND is one opaque disjunct and
    # match_is_null returns None for it.
    schema = _wrap(
        _policy_with_using(
            "a = 1 OR (b = 2 AND auth.uid() IS NULL)"
        )
    )
    assert SEC004().check(schema, {}) == []
