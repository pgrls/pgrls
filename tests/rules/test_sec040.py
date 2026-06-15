"""Unit tests for SEC040 — write-side WITH CHECK drops USING's row scope.

SEC040 (warning) fires when a permissive UPDATE/ALL policy has a USING
that scopes by a discriminator equality `col = <auth value>` and an
explicit, non-constant WITH CHECK that does NOT re-assert that same
`col` — so a caller can UPDATE a row to change `col`, migrating it out
of their tenant/owner scope. It is the asymmetry SEC006 (absent WITH
CHECK), SEC028/SEC020 (constant-true WITH CHECK) miss. Detection reuses
SEC030's `_scoping_columns` over USING and WITH CHECK separately; the
finding is `using_scope - check_scope`.
"""
from __future__ import annotations

import pytest

from pgrls.ast_utils import parse_expr
from pgrls.model import Policy, Schema, Table
from pgrls.rules.sec040 import SEC040

_AUTH = "current_setting('app.tenant_id', true)::int"


def _policy(
    *,
    name: str = "tenant_rw",
    command: str = "UPDATE",
    permissive: bool = True,
    roles: tuple[str, ...] = ("authenticated",),
    using: str | None = None,
    with_check: str | None = None,
) -> Policy:
    return Policy(
        name=name,
        command=command,
        permissive=permissive,
        roles=roles,
        using_sql=using,
        with_check_sql=with_check,
        using_ast=parse_expr(using) if using else None,
        with_check_ast=parse_expr(with_check) if with_check else None,
    )


def _table(
    *policies: Policy,
    schema: str = "public",
    name: str = "documents",
    rls_enabled: bool = True,
) -> Table:
    return Table(
        schema=schema,
        name=name,
        rls_enabled=rls_enabled,
        force_rls=True,
        policies=policies,
        columns=("id", "tenant_id", "user_id", "status"),
        column_details=(),
    )


def _check(*policies: Policy, options: dict | None = None) -> list:
    schema = Schema(tables=(_table(*policies),))
    return SEC040().check(schema, options=options or {})


# --- firing --------------------------------------------------------------


def test_fires_when_with_check_drops_the_tenant_scope() -> None:
    [v] = _check(
        _policy(using=f"tenant_id = {_AUTH}", with_check="status IN ('draft', 'published')")
    )
    assert v.rule_id == "SEC040"
    assert v.severity == "warning"
    assert v.location == "public.documents.tenant_rw"
    assert "'tenant_id'" in v.message
    assert "WITH CHECK" in v.message
    assert "migration" in v.message.lower()


def test_fires_on_for_all_policy() -> None:
    # FOR ALL carries both USING (read scope) and WITH CHECK (write image),
    # so the same drop applies to its UPDATE/INSERT write path.
    [v] = _check(
        _policy(command="ALL", using=f"tenant_id = {_AUTH}", with_check="status = 'x'")
    )
    assert v.location == "public.documents.tenant_rw"
    assert "ALL" in v.message


def test_fires_when_using_scope_is_wrapped_in_fromless_subselect() -> None:
    # `tenant_id = (SELECT current_setting(...))` is the PERF001-recommended
    # form; SEC030's extraction (reused here) sees through the fromless
    # sub-select, so the scope is still recognised.
    [v] = _check(
        _policy(
            using=f"tenant_id = (SELECT {_AUTH})",
            with_check="status = 'x'",
        )
    )
    assert v.location == "public.documents.tenant_rw"


def test_fires_naming_all_scoped_columns_when_check_binds_none() -> None:
    # USING scopes by tenant_id AND user_id; WITH CHECK binds neither (only
    # status) — both are droppable, so both are named.
    [v] = _check(
        _policy(
            using=f"tenant_id = {_AUTH} AND user_id = {_AUTH}",
            with_check="status = 'x'",
        )
    )
    assert "'tenant_id'" in v.message
    assert "'user_id'" in v.message


def test_fires_when_using_is_null_safe_but_check_drops_scope() -> None:
    # USING scopes NULL-safely (`IS NOT DISTINCT FROM`) — still a recognized
    # read-scope — while WITH CHECK validates only status. The scope is
    # dropped on the write side, so SEC040 fires.
    [v] = _check(
        _policy(
            using=f"tenant_id IS NOT DISTINCT FROM {_AUTH}",
            with_check="status = 'x'",
        )
    )
    assert "'tenant_id'" in v.message


def test_fires_when_check_references_column_without_constraining_it() -> None:
    # `tenant_id <> 'x'` is not a scoping equality (`= <auth>`), so the
    # scope is not re-asserted: a caller can still set tenant_id to most
    # other tenants. Fire.
    [v] = _check(
        _policy(using=f"tenant_id = {_AUTH}", with_check="tenant_id <> 0")
    )
    assert "'tenant_id'" in v.message


# --- not firing ----------------------------------------------------------


def test_silent_when_with_check_reasserts_the_scope() -> None:
    assert (
        _check(
            _policy(
                using=f"tenant_id = {_AUTH}",
                with_check=f"tenant_id = {_AUTH} AND status = 'x'",
            )
        )
        == []
    )


def test_silent_when_check_reasserts_via_is_not_distinct_from() -> None:
    # A NULL-safe re-assertion (`tenant_id IS NOT DISTINCT FROM <session>`)
    # is strictly stronger than `=` — it pins the write to the caller's
    # tenant. SEC040 must recognize it as a binding and stay silent (else it
    # would false-fire on a *hardened* policy).
    assert (
        _check(
            _policy(
                using=f"tenant_id = {_AUTH}",
                with_check=f"tenant_id IS NOT DISTINCT FROM {_AUTH}",
            )
        )
        == []
    )


def test_silent_when_check_binds_a_different_identity_column() -> None:
    # The "read your team, write your own" pattern: USING scopes by team_id
    # but WITH CHECK binds user_id to the caller. The write side still
    # carries an identity binding, so the asymmetry is intentional and
    # SEC040 stays silent (it fires only when the write side binds NO
    # identity column at all).
    assert (
        _check(
            _policy(
                using=f"tenant_id = {_AUTH}",
                with_check=f"user_id = {_AUTH}",
            )
        )
        == []
    )


def test_silent_when_with_check_equals_using() -> None:
    assert _check(_policy(using=f"tenant_id = {_AUTH}", with_check=f"tenant_id = {_AUTH}")) == []


def test_silent_on_constant_true_with_check_ceded_to_sec028_sec020() -> None:
    # A constant-true WITH CHECK is SEC028's (no/true USING) or SEC020's
    # (restrictive USING) finding — SEC040 must not double-report.
    assert _check(_policy(using=f"tenant_id = {_AUTH}", with_check="true")) == []


def test_silent_on_constant_false_with_check_blocks_all_writes() -> None:
    # WITH CHECK (false) rejects every write — no migration is possible,
    # so SEC040 must stay silent (not treat the empty scope as a drop).
    assert _check(_policy(using=f"tenant_id = {_AUTH}", with_check="false")) == []


def test_silent_when_with_check_omitted_using_is_reused() -> None:
    # No explicit WITH CHECK → Postgres reuses USING as the implicit check,
    # preserving the scope. SEC006's domain, not SEC040's.
    assert _check(_policy(using=f"tenant_id = {_AUTH}", with_check=None)) == []


def test_silent_when_using_is_not_a_scope() -> None:
    # USING (true) carries no discriminator scope to drop (SEC008's case).
    assert _check(_policy(using="true", with_check="status = 'x'")) == []


def test_silent_on_insert_policy() -> None:
    # INSERT has no USING, so there is no read-scope to drop. An open
    # INSERT WITH CHECK is SEC028's concern.
    assert _check(_policy(command="INSERT", using=None, with_check="status = 'x'")) == []


def test_silent_on_update_with_check_but_no_using() -> None:
    # An UPDATE/ALL policy with an explicit WITH CHECK but no USING has no
    # read-scope to compare against, so there is nothing to "drop" — silent.
    assert _check(_policy(command="UPDATE", using=None, with_check="status = 'x'")) == []


def test_silent_on_select_policy() -> None:
    assert _check(_policy(command="SELECT", using=f"tenant_id = {_AUTH}", with_check=None)) == []


def test_silent_on_delete_policy() -> None:
    assert _check(_policy(command="DELETE", using=f"tenant_id = {_AUTH}", with_check=None)) == []


def test_silent_on_restrictive_policy() -> None:
    # Restrictive policies AND-combine; a dropped scope there is SEC006's
    # restrictive framing, not an escape on its own.
    assert (
        _check(
            _policy(
                permissive=False,
                using=f"tenant_id = {_AUTH}",
                with_check="status = 'x'",
            )
        )
        == []
    )


def test_silent_when_scoped_by_non_identity_column() -> None:
    # `created_at = current_setting(...)` is a point-in-time read, not a
    # tenant/owner key — not an identity column, so no scope is recognised.
    p = Policy(
        name="snapshot",
        command="UPDATE",
        permissive=True,
        roles=("authenticated",),
        using_sql="created_at = current_setting('app.snapshot', true)::timestamptz",
        with_check_sql="status = 'x'",
        using_ast=parse_expr("created_at = current_setting('app.snapshot', true)::timestamptz"),
        with_check_ast=parse_expr("status = 'x'"),
    )
    t = Table(
        schema="public",
        name="documents",
        rls_enabled=True,
        force_rls=True,
        policies=(p,),
        columns=("id", "created_at", "status"),
        column_details=(),
    )
    assert SEC040().check(Schema(tables=(t,)), options={}) == []


# --- configuration -------------------------------------------------------


def test_allowlist_exempts_policy_by_qualified_id() -> None:
    pol = _policy(using=f"tenant_id = {_AUTH}", with_check="status = 'x'")
    options = {"allowlist": ["public.documents.tenant_rw"]}
    assert _check(pol, options=options) == []


def test_identity_columns_override_recognises_custom_key() -> None:
    # 'workspace' isn't a default identity name; with it configured, a
    # dropped workspace scope fires.
    pol = _policy(using=f"workspace = {_AUTH}", with_check="status = 'x'")
    t = Table(
        schema="public",
        name="documents",
        rls_enabled=True,
        force_rls=True,
        policies=(pol,),
        columns=("id", "workspace", "status"),
        column_details=(),
    )
    schema = Schema(tables=(t,))
    assert SEC040().check(schema, options={}) == []  # default set: workspace not recognised
    [v] = SEC040().check(schema, options={"identity_columns": ["workspace"]})
    assert "'workspace'" in v.message


def test_auth_functions_override_replaces_default_set() -> None:
    # With only auth.uid configured, current_setting is no longer an auth
    # value, so `tenant_id = current_setting(...)` is not a recognised
    # scope and nothing fires.
    pol = _policy(using=f"tenant_id = {_AUTH}", with_check="status = 'x'")
    assert _check(pol, options={"auth_functions": ["auth.uid"]}) == []


def test_rejects_malformed_auth_functions_option() -> None:
    pol = _policy(using=f"tenant_id = {_AUTH}", with_check="status = 'x'")
    with pytest.raises(TypeError, match="auth_functions"):
        _check(pol, options={"auth_functions": "current_setting"})


def test_rejects_malformed_identity_columns_option() -> None:
    pol = _policy(using=f"tenant_id = {_AUTH}", with_check="status = 'x'")
    with pytest.raises(TypeError, match="identity_columns"):
        _check(pol, options={"identity_columns": [123]})


def test_metadata() -> None:
    rule = SEC040()
    assert rule.id == "SEC040"
    assert rule.severity == "warning"
    assert rule.title
