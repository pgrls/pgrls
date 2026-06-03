"""Unit tests for SEC037.

SEC037 (warning) fires when a policy's USING / WITH CHECK clause
has a `=` comparison between `auth.role()` and a string literal not
in the configured known-role set. The default set is the Supabase
triad `{anon, authenticated, service_role}`. The hazard is silent
deny — the comparison never matches, every row hidden — masking
broken policies that look correct on read-through.
"""
from __future__ import annotations

import pytest

from pgrls.ast_utils import parse_expr
from pgrls.model import Policy, Schema, Table
from pgrls.rules.sec037 import SEC037


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
# Fires — auth.role() compared to a value outside the known set
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "expr,bad_value",
    [
        ("auth.role() = 'admin'", "admin"),
        ("auth.role() = 'authorized'", "authorized"),
        ("auth.role() = 'authenticted'", "authenticted"),  # typo
        # Reversed: literal on LHS, FuncCall on RHS
        ("'admin' = auth.role()", "admin"),
        # Inside an OR-disjunct still fires
        ("owner_id = auth.uid() OR auth.role() = 'editor'", "editor"),
    ],
)
def test_fires_on_unknown_role(expr: str, bad_value: str) -> None:
    schema = _wrap(_policy(f"({expr})", name="role_check"))
    violations = SEC037().check(schema, {})
    assert len(violations) == 1, expr
    v = violations[0]
    assert v.rule_id == "SEC037"
    assert v.severity == "warning"
    assert v.location == "public.t.role_check"
    assert bad_value in v.message


def test_fires_in_with_check_clause() -> None:
    schema = _wrap(
        _policy(
            command="INSERT",
            with_check="(auth.role() = 'admin')",
            name="admin_inserts",
        )
    )
    violations = SEC037().check(schema, {})
    assert len(violations) == 1
    assert violations[0].location == "public.t.admin_inserts"


def test_dedupes_identical_literal_across_using_and_with_check() -> None:
    # Same `'admin'` literal in both clauses — one finding (same fix).
    schema = _wrap(
        _policy(
            command="UPDATE",
            using="(auth.role() = 'admin')",
            with_check="(auth.role() = 'admin')",
            name="dual_admin",
        )
    )
    violations = SEC037().check(schema, {})
    assert len(violations) == 1


def test_fires_per_distinct_unknown_literal() -> None:
    # Two distinct unknown literals → two findings (each suggests a
    # different intended fix — was it 'admin'? was it 'super'?).
    expr = "auth.role() = 'admin' OR auth.role() = 'super'"
    schema = _wrap(_policy(f"({expr})", name="admin_or_super"))
    violations = SEC037().check(schema, {})
    assert len(violations) == 2
    assert {
        unknown
        for unknown in ("admin", "super")
        if any(unknown in v.message for v in violations)
    } == {"admin", "super"}


def test_fires_on_in_list_with_all_unknown_roles() -> None:
    # Regression (#27): `auth.role() IN ('admin', 'editor')` is the
    # same silent-deny shape as `auth.role() = 'admin' OR auth.role()
    # = 'editor'` — it never matches when every listed value is outside
    # the known set. Each distinct unknown element is its own finding,
    # mirroring the per-disjunct `=` path.
    schema = _wrap(_policy("(auth.role() IN ('admin', 'editor'))", name="in_roles"))
    violations = SEC037().check(schema, {})
    assert len(violations) == 2
    assert {
        unknown
        for unknown in ("admin", "editor")
        if any(unknown in v.message for v in violations)
    } == {"admin", "editor"}


def test_fires_on_pg_get_expr_normalized_any_array_form() -> None:
    # R15 #1: this is the form SEC037 ACTUALLY sees at runtime. Postgres
    # stores polqual normalized and pg_get_expr re-renders
    # `auth.role() IN ('admin','editor')` as
    # `auth.role() = ANY (ARRAY['admin'::text, 'editor'::text])` (an
    # A_Expr of kind AEXPR_OP_ANY). The raw-IN test above never exercises
    # this — it parses the hand-written AEXPR_IN — so the rule's headline
    # case was a false negative on EVERY introspected/snapshotted schema
    # until the AEXPR_OP_ANY branch landed. Build the fixture from the
    # normalized string so the production path is genuinely covered.
    schema = _wrap(
        _policy(
            "(auth.role() = ANY (ARRAY['admin'::text, 'editor'::text]))",
            name="any_roles",
        )
    )
    violations = SEC037().check(schema, {})
    assert len(violations) == 2
    assert {
        unknown
        for unknown in ("admin", "editor")
        if any(unknown in v.message for v in violations)
    } == {"admin", "editor"}
    # `= ALL (ARRAY['admin'])` — the single-value / contradictory form —
    # is likewise a silent deny when the value is unknown.
    all_schema = _wrap(
        _policy("(auth.role() = ALL (ARRAY['admin'::text]))", name="all_role")
    )
    assert len(SEC037().check(all_schema, {})) == 1


def test_does_not_fire_on_not_in_normalized_neq_all_form() -> None:
    # The pg_get_expr normalization of `auth.role() NOT IN ('admin')` is
    # `auth.role() <> ALL (ARRAY['admin'::text])`, which is ALWAYS TRUE
    # for a real role — every row visible, the OPPOSITE of the silent-deny
    # hazard. The AEXPR_OP_ANY/ALL branch is gated to operator name `=`
    # (mirroring the IN branch's `=`-only gate), so `<> ALL` must NOT fire.
    schema = _wrap(
        _policy(
            "(auth.role() <> ALL (ARRAY['admin'::text]))", name="neq_all"
        )
    )
    assert SEC037().check(schema, {}) == []


def test_does_not_fire_on_not_in_list() -> None:
    # `auth.role() NOT IN ('admin')` is ALWAYS TRUE for any real role
    # (auth.role() returns a genuine role, never the unknown 'admin'),
    # so every row is VISIBLE — the OPPOSITE of SEC037's silent-deny
    # hazard ("comparison never matches, every row hidden"). Emitting
    # the silent-deny finding here is an inverted-semantics false
    # positive. `NOT IN` parses as AEXPR_IN with operator name `<>`;
    # only plain `IN` (operator `=`) is the silent-deny shape, so
    # SEC037 must stay silent on `NOT IN`.
    schema = _wrap(_policy("(auth.role() NOT IN ('admin'))", name="not_in_admin"))
    assert SEC037().check(schema, {}) == []


def test_fires_on_schema_qualified_equality_operator() -> None:
    # pglast can render/parse `=` as the schema-qualified
    # `OPERATOR(pg_catalog.=)`. The equality check matches on the
    # operator name's FINAL component, so the silent-deny shape is
    # caught in the qualified form too (regression for the len(name)==1
    # gate that previously rejected it).
    schema = _wrap(
        _policy(
            "(auth.role() OPERATOR(pg_catalog.=) 'admin')",
            name="qualified_eq",
        )
    )
    violations = SEC037().check(schema, {})
    assert len(violations) == 1
    assert "admin" in violations[0].message


def test_in_list_fires_only_on_the_unknown_element() -> None:
    # Mixed list: a known role plus an unknown one. Only the unknown
    # `'admin'` is a finding — the known `'authenticated'` is fine.
    # Pins that membership is checked per element, not "is the whole
    # list unknown".
    schema = _wrap(
        _policy("(auth.role() IN ('authenticated', 'admin'))", name="mixed_in")
    )
    violations = SEC037().check(schema, {})
    assert len(violations) == 1
    assert "admin" in violations[0].message


def test_in_list_dedupes_against_equality_same_literal() -> None:
    # `auth.role() = 'admin' OR auth.role() IN ('admin')` — the same
    # unknown literal across an `=` and an `IN` is one mistake, one
    # finding (per-literal dedup in `check`).
    schema = _wrap(
        _policy(
            "(auth.role() = 'admin' OR auth.role() IN ('admin'))",
            name="dup_admin",
        )
    )
    assert len(SEC037().check(schema, {})) == 1


# ──────────────────────────────────────────────────────────────────────
# Silent — known role, non-auth.role check, unrelated comparison
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "expr",
    [
        # Known roles — silent.
        "auth.role() = 'anon'",
        "auth.role() = 'authenticated'",
        "auth.role() = 'service_role'",
        # auth.role() compared to a column ref (not a literal) — not
        # the silent-deny class.
        "auth.role() = role_column",
        # auth.role() in inequality / IS NULL — different shape.
        "auth.role() <> 'admin'",
        "auth.role() IS NULL",
        # Wholly unrelated policies.
        "owner_id = auth.uid()",
        "current_user = 'postgres'",
    ],
)
def test_silent_on_safe_shapes(expr: str) -> None:
    schema = _wrap(_policy(f"({expr})", name="safe"))
    assert SEC037().check(schema, {}) == [], expr


def test_silent_when_no_policy_predicate() -> None:
    schema = _wrap(_policy(using=None, name="open"))
    assert SEC037().check(schema, {}) == []


# ──────────────────────────────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────────────────────────────


def test_known_roles_override_extends_silent_set() -> None:
    # Add `'guest'` to the known-roles set — comparison silent.
    schema = _wrap(_policy("(auth.role() = 'guest')", name="guest_check"))
    options = {"known_roles": ["anon", "authenticated", "service_role", "guest"]}
    assert SEC037().check(schema, options) == []


def test_known_roles_override_replaces_default() -> None:
    # Replace defaults entirely with just `'admin'`. Now
    # `auth.role() = 'admin'` is silent and `'anon'` fires.
    schema_admin = _wrap(_policy("(auth.role() = 'admin')", name="admin_ok"))
    schema_anon = _wrap(_policy("(auth.role() = 'anon')", name="anon_now_bad"))
    options = {"known_roles": ["admin"]}
    assert SEC037().check(schema_admin, options) == []
    violations = SEC037().check(schema_anon, options)
    assert len(violations) == 1
    assert "anon" in violations[0].message


def test_role_functions_override() -> None:
    # Extend to flag `current_user = 'admin'` too. (SEC018 is the
    # 'current_user as a tenant key' rule; SEC037 with this override
    # adds the silent-deny-typo class to current_user too.)
    schema = _wrap(_policy("(current_user = 'admin')", name="current_user_check"))
    options = {"role_functions": ["auth.role", "current_user"]}
    violations = SEC037().check(schema, options)
    assert len(violations) == 1


def test_allowlist_exempts_specific_policy() -> None:
    schema = _wrap(_policy("(auth.role() = 'admin')", name="legacy_admin"))
    options = {"allowlist": ["public.t.legacy_admin"]}
    assert SEC037().check(schema, options) == []


def test_rejects_malformed_known_roles_option() -> None:
    with pytest.raises(TypeError) as exc:
        SEC037().check(_wrap(_policy("(true)")), {"known_roles": "anon"})
    assert "role-name" in str(exc.value)


def test_rejects_malformed_role_functions_option() -> None:
    with pytest.raises(TypeError) as exc:
        SEC037().check(
            _wrap(_policy("(true)")),
            {"role_functions": ["auth.role", 9]},
        )
    assert "function names" in str(exc.value)


def test_sec037_fires_on_typecast_wrapped_role_call() -> None:
    # Regression (round-7): the role-call side is unwrapped of a TypeCast
    # just like the literal side, so `auth.role()::text = 'admin'` (and the
    # parenthesized form) is recognized as the silent-deny footgun, not
    # silently missed.
    for using in (
        "auth.role()::text = 'admin'",
        "(auth.role())::text = 'admin'",
    ):
        violations = SEC037().check(_wrap(_policy(using, name="cast")), {})
        assert len(violations) == 1, using
        assert violations[0].location == "public.t.cast"
