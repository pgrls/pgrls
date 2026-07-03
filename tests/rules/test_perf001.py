"""Unit tests for PERF001 — unwrapped auth function in USING / WITH CHECK."""
from __future__ import annotations

import pytest

from pgrls.ast_utils import parse_expr
from pgrls.model import Policy, Schema, Table
from pgrls.rules.perf001 import PERF001


def _policy(
    using: str | None,
    *,
    name: str = "p",
    command: str = "SELECT",
    with_check: str | None = None,
) -> Policy:
    return Policy(
        name=name,
        command=command,  # type: ignore[arg-type]
        permissive=True,
        roles=("authenticated",),
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
                columns=("id", "user_id"),
            ),
        )
    )


def test_perf001_fires_on_unwrapped_auth_uid() -> None:
    schema = _wrap(_policy("auth.uid() = user_id"))
    violations = PERF001().check(schema, {})
    assert len(violations) == 1
    assert violations[0].rule_id == "PERF001"
    assert violations[0].location == "public.t.p"


def test_perf001_does_not_fire_on_wrapped_auth_uid() -> None:
    schema = _wrap(_policy("(SELECT auth.uid()) = user_id"))
    assert PERF001().check(schema, {}) == []


def test_perf001_does_not_fire_on_in_subquery_wrap() -> None:
    # Any SubLink ancestor counts as wrapped — IN/EXISTS work too.
    schema = _wrap(_policy("user_id IN (SELECT auth.uid())"))
    assert PERF001().check(schema, {}) == []


def test_perf001_fires_on_unwrapped_auth_on_in_lhs() -> None:
    # `auth.uid() IN (SELECT id FROM trusted)` — auth.uid() is on the
    # IN-expression's LHS (SubLink.testexpr), not inside the subselect.
    # The call is unwrapped and Postgres re-evaluates it per row, so
    # PERF001 must fire. Pins find_func_calls(exclude_sublinks=True)
    # walking testexpr.
    schema = _wrap(_policy("auth.uid() IN (SELECT id FROM trusted_admins)"))
    assert len(PERF001().check(schema, {})) == 1


def test_perf001_fires_on_unwrapped_auth_in_correlated_exists() -> None:
    # The common RLS membership-join pattern: a bare auth.uid() inside a
    # CORRELATED EXISTS — the subquery references the outer table via
    # `m.t_id = t.id` — re-evaluates once per outer row scanned. Wrapping
    # it `(SELECT auth.uid())` makes it a per-statement InitPlan, the same
    # win as a top-level call, so PERF001 must fire. (CodeRabbit and
    # cubic-dev-ai flagged exactly this on the goodwill PRs `pgrls fix`
    # generated; it is the gap descend_correlated_sublinks closes.)
    schema = _wrap(
        _policy(
            "EXISTS (SELECT 1 FROM members m "
            "WHERE m.user_id = auth.uid() AND m.t_id = t.id)"
        )
    )
    assert len(PERF001().check(schema, {})) == 1


def test_perf001_does_not_fire_on_uncorrelated_exists() -> None:
    # An UNCORRELATED EXISTS (no reference to the outer table) is an
    # InitPlan Postgres runs ONCE, so the auth.uid() inside already
    # evaluates once — wrapping buys nothing. Soundness: stay quiet.
    schema = _wrap(
        _policy(
            "EXISTS (SELECT 1 FROM admins a WHERE a.user_id = auth.uid())"
        )
    )
    assert PERF001().check(schema, {}) == []


def test_perf001_does_not_fire_on_correlated_exists_already_wrapped() -> None:
    # A correlated EXISTS whose nested auth call is ALREADY wrapped
    # `(SELECT auth.uid())` is in the recommended form — no finding. The
    # outer reference `s2.id = t.id` makes the subselect correlated (so
    # the walk descends), but the only auth call inside is wrapped.
    # Mirrors the corpus `sec004-is-null-in-subquery-safe` shape, which
    # guards this against regression at the corpus level too.
    schema = _wrap(
        _policy(
            "owner_id = (SELECT auth.uid()) OR EXISTS "
            "(SELECT 1 FROM public.shares s2 "
            "WHERE s2.id = t.id AND (SELECT auth.uid()) IS NULL)"
        )
    )
    assert PERF001().check(schema, {}) == []


def test_perf001_fires_on_correlated_nested_in_with_check() -> None:
    # The correlated-subselect rule applies to WITH CHECK too — the write
    # path re-evaluates the nested call per written row.
    schema = _wrap(
        _policy(
            None,
            command="INSERT",
            with_check=(
                "EXISTS (SELECT 1 FROM members m "
                "WHERE m.user_id = auth.uid() AND m.t_id = t.id)"
            ),
        )
    )
    assert len(PERF001().check(schema, {})) == 1


def test_perf001_fires_on_postgres_normalized_correlated_exists() -> None:
    # The exact shape `pg_get_expr` stores for a correlated membership
    # EXISTS — schema-qualified FROM, AS-less alias, doubled parens. Pins
    # that correlation detection survives Postgres normalization (the
    # introspection path), verified end-to-end against a live PG16:
    # `pgrls lint` reports PERF001 and `pgrls fix` wraps the nested call.
    schema = _wrap(
        _policy(
            "(EXISTS ( SELECT 1 FROM public.team_members tm "
            "WHERE ((tm.team_id = t.id) AND (tm.user_id = auth.uid()))))"
        )
    )
    assert len(PERF001().check(schema, {})) == 1


def test_perf001_fires_on_current_setting_nested_in_correlated_exists() -> None:
    # `current_setting` (the headline non-auth.uid call the docs cite) in
    # a correlated EXISTS re-evaluates per outer row exactly like
    # auth.uid(), so it fires too.
    schema = _wrap(
        _policy(
            "EXISTS (SELECT 1 FROM members m "
            "WHERE m.t_id = t.id "
            "AND m.token = current_setting('app.user'))"
        )
    )
    assert len(PERF001().check(schema, {})) == 1


def test_perf001_fires_on_auth_jwt_nested_in_correlated_exists() -> None:
    # auth.jwt() (a default auth function) nested in a correlated EXISTS
    # fires the same as auth.uid() — including when the JSON is projected
    # via `->>`.
    schema = _wrap(
        _policy(
            "EXISTS (SELECT 1 FROM members m "
            "WHERE m.t_id = t.id "
            "AND m.role = (auth.jwt() ->> 'role'))"
        )
    )
    assert len(PERF001().check(schema, {})) == 1


def test_perf001_fires_on_auth_in_correlated_any_subquery() -> None:
    # A correlated subselect reached via `= ANY (SELECT …)` (not just
    # EXISTS) is descended into too — the testexpr is walked and the
    # correlated subselect is descended when it references the outer row.
    schema = _wrap(
        _policy(
            "t.id = ANY (SELECT m.doc_id FROM members m "
            "WHERE m.t_id = t.id AND m.user_id = auth.uid())"
        )
    )
    assert len(PERF001().check(schema, {})) == 1


def test_perf001_fires_on_unwrapped_current_setting() -> None:
    schema = _wrap(
        _policy("current_setting('app.user') = user_id")
    )
    assert len(PERF001().check(schema, {})) == 1


def test_perf001_does_not_fire_on_current_user() -> None:
    # current_user is in SEC004's set but NOT PERF001's default — Postgres
    # evaluates the SQLValueFunction cheaply, so wrapping buys nothing.
    schema = _wrap(_policy("current_user = 'admin'"))
    assert PERF001().check(schema, {}) == []


def test_perf001_does_not_fire_on_session_user() -> None:
    schema = _wrap(_policy("session_user = 'admin'"))
    assert PERF001().check(schema, {}) == []


def test_perf001_emits_only_one_violation_per_policy() -> None:
    # Multiple unwrapped calls in one policy → still one violation.
    schema = _wrap(
        _policy(
            "auth.uid() = user_id OR auth.uid() IS NULL"
        )
    )
    assert len(PERF001().check(schema, {})) == 1


def test_perf001_fires_on_with_check_only() -> None:
    # An INSERT policy whose only auth call is in WITH CHECK: a bare
    # auth.uid() there is re-evaluated per written row (verified live —
    # a 1000-row INSERT calls it 1000 times, the (SELECT …) wrap once),
    # so PERF001 must fire, exactly like USING.
    schema = _wrap(
        _policy(
            None,
            command="INSERT",
            with_check="auth.uid() = user_id",
        )
    )
    violations = PERF001().check(schema, {})
    assert len(violations) == 1
    assert violations[0].location == "public.t.p"
    assert "WITH CHECK" in violations[0].message


def test_perf001_fires_once_when_both_clauses_unwrapped() -> None:
    # FOR ALL with a bare auth call in BOTH USING and WITH CHECK →
    # still ONE violation, message naming both clauses.
    schema = _wrap(
        _policy(
            "auth.uid() = user_id",
            command="ALL",
            with_check="auth.uid() = user_id",
        )
    )
    violations = PERF001().check(schema, {})
    assert len(violations) == 1
    assert "USING and WITH CHECK" in violations[0].message


def test_perf001_does_not_fire_on_wrapped_with_check() -> None:
    # Already-wrapped WITH CHECK (and no USING) → silent.
    schema = _wrap(
        _policy(
            None,
            command="INSERT",
            with_check="(SELECT auth.uid()) = user_id",
        )
    )
    assert PERF001().check(schema, {}) == []


def test_perf001_does_not_fire_when_using_is_none() -> None:
    schema = _wrap(_policy(None, command="INSERT", with_check="true"))
    assert PERF001().check(schema, {}) == []


def test_perf001_default_set_covers_auth_role() -> None:
    schema = _wrap(_policy("auth.role() = 'admin'"))
    assert len(PERF001().check(schema, {})) == 1


def test_perf001_default_set_covers_auth_jwt() -> None:
    schema = _wrap(_policy("auth.jwt() ->> 'sub' = '1'"))
    assert len(PERF001().check(schema, {})) == 1


def test_perf001_allowlist_exempts_qualified_policy_id() -> None:
    schema = _wrap(_policy("auth.uid() = user_id"))
    assert PERF001().check(
        schema, {"allowlist": ["public.t.p"]}
    ) == []


def test_perf001_auth_functions_override_replaces_default() -> None:
    # Override = replace, not extend. auth.uid is gone unless re-listed.
    schema = _wrap(_policy("auth.uid() = user_id"))
    options = {"auth_functions": ["my.custom"]}
    assert PERF001().check(schema, options) == []


def test_perf001_auth_functions_override_finds_custom_func() -> None:
    schema = _wrap(_policy("my.custom() = user_id"))
    options = {"auth_functions": ["my.custom"]}
    assert len(PERF001().check(schema, options)) == 1


def test_perf001_empty_auth_functions_never_fires() -> None:
    schema = _wrap(_policy("auth.uid() = user_id"))
    assert PERF001().check(schema, {"auth_functions": []}) == []


def test_perf001_bad_allowlist_type_raises_clearly() -> None:
    schema = _wrap(_policy("auth.uid() = user_id"))
    with pytest.raises(TypeError, match="allowlist"):
        PERF001().check(schema, {"allowlist": "public.t.p"})  # type: ignore[dict-item]


def test_perf001_bad_auth_functions_type_raises_clearly() -> None:
    schema = _wrap(_policy("auth.uid() = user_id"))
    with pytest.raises(TypeError, match="auth_functions"):
        PERF001().check(schema, {"auth_functions": "auth.uid"})  # type: ignore[dict-item]


def test_perf001_bad_auth_functions_item_type_raises_clearly() -> None:
    schema = _wrap(_policy("auth.uid() = user_id"))
    with pytest.raises(TypeError, match="auth_functions"):
        PERF001().check(
            schema, {"auth_functions": ["auth.uid", 42]}  # type: ignore[list-item]
        )


def test_perf001_fires_on_each_offending_policy_independently() -> None:
    schema = Schema(
        tables=(
            Table(
                schema="public",
                name="t",
                rls_enabled=True,
                force_rls=True,
                columns=("id", "user_id"),
                policies=(
                    _policy("auth.uid() = user_id", name="bad_a"),
                    _policy(
                        "(SELECT auth.uid()) = user_id", name="good"
                    ),
                    _policy(
                        "current_setting('app.u') = user_id",
                        name="bad_b",
                    ),
                ),
            ),
        )
    )
    locations = sorted(v.location for v in PERF001().check(schema, {}))
    assert locations == ["public.t.bad_a", "public.t.bad_b"]
