"""Unit tests for SEC004 — inverted auth check (Lovable CVE pattern)."""
from __future__ import annotations

from pgrls.ast_utils import parse_expr
from pgrls.model import Policy, Schema, Table
from pgrls.rules.sec004 import SEC004


def _policy_with_using(
    using: str, roles: tuple[str, ...] = ("authenticated",)
) -> Policy:
    return Policy(
        name="p",
        command="SELECT",
        permissive=True,
        roles=roles,
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


def test_sec004_silent_on_one_arg_current_setting_is_null() -> None:
    # R12 #1: the one-arg `current_setting('app.x')` RAISES on an unset
    # GUC and is otherwise a non-NULL string — it is NEVER NULL, so the
    # `IS NULL` disjunct is dead and the policy fails closed. Flagging it
    # ERROR-severity is a false positive (the two-arg missing_ok form is
    # the genuinely-NULLable one). Covers the builtin in both spellings.
    for fn in ("current_setting", "pg_catalog.current_setting"):
        schema = _wrap(
            _policy_with_using(f"{fn}('app.x') IS NULL OR user_id = '1'")
        )
        assert SEC004().check(schema, {}) == [], fn


def test_sec004_silent_on_two_arg_false_current_setting_is_null() -> None:
    # R13 #2: the two-arg `current_setting(name, false)` form ALSO raises
    # on an unset GUC (missing_ok=false), so it is NEVER NULL just like
    # the one-arg form — the `IS NULL` disjunct is dead and the policy
    # fails closed. The R12 fix keyed on arity (1 arg) and so left this
    # 2-arg-false case still false-firing at ERROR severity. Only the
    # `, true` form (test above) is genuinely NULLable. Covers bare
    # `false`, `FALSE`, and the `false::boolean` cast, in both builtin
    # spellings.
    for fn in ("current_setting", "pg_catalog.current_setting"):
        for lit in ("false", "FALSE", "false::boolean"):
            using = f"{fn}('app.x', {lit}) IS NULL OR user_id = '1'"
            assert SEC004().check(_wrap(_policy_with_using(using)), {}) == [], using


def test_sec004_fires_on_user_defined_one_arg_current_setting() -> None:
    # A user-defined `myschema.current_setting(text)` is NOT the builtin
    # and could legitimately return NULL, so the never-NULL skip must not
    # suppress it (it matches via the bare name in the auth set).
    schema = _wrap(
        _policy_with_using(
            "myschema.current_setting('app.x') IS NULL OR user_id = '1'"
        )
    )
    assert len(
        SEC004().check(schema, {"auth_functions": ["current_setting"]})
    ) == 1


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


def test_sec004_error_when_policy_reaches_anon() -> None:
    # A policy applying to PUBLIC (the no-`TO` default) or `anon` is
    # reachable by a token-less request, so the IS NULL disjunct is a live
    # anonymous-read hole: ERROR, with the anon/PUBLIC message.
    for roles in (("PUBLIC",), ("anon",), ("anon", "authenticated")):
        schema = _wrap(
            _policy_with_using(
                "auth.uid() IS NULL OR user_id = '1'", roles=roles
            )
        )
        v = SEC004().check(schema, {})
        assert len(v) == 1, roles
        assert v[0].severity == "error", roles
        assert "anon / PUBLIC" in v[0].message, roles


def test_sec004_warning_when_restricted_to_authenticated() -> None:
    # A `TO authenticated` policy can't be reached by a token-less request
    # (that runs as `anon`), so it is NOT a drive-by anonymous leak. The
    # disjunct is still a latent defect (null-`sub` token; loosening the
    # restriction), so SEC004 reports it — but as WARNING, and the message
    # must not claim anonymous exposure. Pins the fix for the false anon
    # claim on role-restricted policies.
    schema = _wrap(
        _policy_with_using(
            "auth.uid() IS NULL OR user_id = '1'", roles=("authenticated",)
        )
    )
    v = SEC004().check(schema, {})
    assert len(v) == 1
    assert v[0].severity == "warning"
    assert "cannot reach it" in v[0].message
    assert "exposing every row" not in v[0].message


def test_sec004_warns_on_custom_anon_role_by_default() -> None:
    # A non-Supabase anonymous role (e.g. PostgREST's `web_anon`) is not in
    # the default anon set, so by default it is treated like any non-anon
    # role: WARNING, not error. Documents the default; the config below
    # promotes it back to error.
    schema = _wrap(
        _policy_with_using(
            "auth.uid() IS NULL OR user_id = '1'", roles=("web_anon",)
        )
    )
    v = SEC004().check(schema, {})
    assert len(v) == 1
    assert v[0].severity == "warning"


def test_sec004_error_on_custom_anon_role_when_configured() -> None:
    # Configuring the project's anonymous role name restores the ERROR: the
    # policy really is reachable by unauthenticated callers.
    schema = _wrap(
        _policy_with_using(
            "auth.uid() IS NULL OR user_id = '1'", roles=("web_anon",)
        )
    )
    v = SEC004().check(schema, {"anon_roles": ["web_anon", "PUBLIC"]})
    assert len(v) == 1
    assert v[0].severity == "error"


def test_sec004_anon_roles_config_normalizes_public_keyword() -> None:
    # A config entry of lowercase "public" matches the stored "PUBLIC" form.
    schema = _wrap(
        _policy_with_using(
            "auth.uid() IS NULL OR user_id = '1'", roles=("PUBLIC",)
        )
    )
    v = SEC004().check(schema, {"anon_roles": ["public"]})
    assert len(v) == 1
    assert v[0].severity == "error"


def test_sec004_warns_with_no_role_label_on_empty_roles() -> None:
    # Defensive: a policy with no resolved roles can't be reached by anon,
    # so WARNING with a graceful "no role" label rather than a crash.
    schema = _wrap(
        _policy_with_using(
            "auth.uid() IS NULL OR user_id = '1'", roles=()
        )
    )
    v = SEC004().check(schema, {})
    assert len(v) == 1
    assert v[0].severity == "warning"
    assert "no role" in v[0].message


def test_sec004_bad_anon_roles_type_raises_clearly() -> None:
    import pytest
    schema = _wrap(_policy_with_using("auth.uid() IS NULL OR a = 1"))
    with pytest.raises(TypeError, match="anon_roles"):
        SEC004().check(
            schema, {"anon_roles": "anon"}  # type: ignore[dict-item]
        )


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
