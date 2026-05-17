"""Unit tests for SEC019 — one-argument current_setting() in a policy.

SEC019 (info) fires when a policy's USING / WITH CHECK expression
calls `current_setting` with a single argument — the overload that
raises on an unset GUC. The two-argument `current_setting('x', true)`
form (returns NULL on an unset GUC) does not fire.
"""
from __future__ import annotations

import pytest

from pgrls.ast_utils import parse_expr
from pgrls.model import Policy, Schema, Table
from pgrls.rules.sec019 import SEC019


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


def _wrap(policy: Policy) -> Schema:
    return Schema(
        tables=(
            Table(
                schema="public",
                name="t",
                rls_enabled=True,
                force_rls=True,
                policies=(policy,),
                columns=("id", "tenant_id"),
            ),
        )
    )


# --- fires: one-argument current_setting ---------------------------------


def test_sec019_fires_on_one_arg_current_setting() -> None:
    schema = _wrap(_policy("tenant_id = current_setting('app.tenant')"))
    [v] = SEC019().check(schema, {})
    assert v.rule_id == "SEC019"
    assert v.severity == "info"
    assert v.location == "public.t.p"
    assert "current_setting" in v.message
    assert "missing_ok" in v.message
    assert "[lint.rules.SEC019]" in v.message


def test_sec019_fires_when_one_arg_only_in_with_check() -> None:
    p = _policy(
        with_check="tenant_id = current_setting('app.tenant')",
        command="INSERT",
    )
    assert len(SEC019().check(_wrap(p), {})) == 1


def test_sec019_fires_when_one_arg_call_is_subquery_wrapped() -> None:
    # `(SELECT current_setting('app.tenant'))` — the one-arg call
    # still raises on an unset GUC; find_func_calls walks into the
    # sub-select, so SEC019 catches it.
    schema = _wrap(
        _policy("tenant_id = (SELECT current_setting('app.tenant'))")
    )
    assert len(SEC019().check(schema, {})) == 1


def test_sec019_fires_when_a_one_arg_call_sits_beside_a_two_arg_call() -> None:
    # One offending call is enough — even if another current_setting
    # in the same policy uses the safe two-arg form.
    schema = _wrap(
        _policy(
            "tenant_id = current_setting('app.tenant') "
            "OR id::text = current_setting('app.id', true)"
        )
    )
    assert len(SEC019().check(schema, {})) == 1


# --- silent --------------------------------------------------------------


def test_sec019_silent_on_two_arg_current_setting() -> None:
    # The two-argument form returns NULL on an unset GUC instead of
    # raising — this is the form SEC019 nudges toward.
    schema = _wrap(
        _policy("tenant_id = current_setting('app.tenant', true)")
    )
    assert SEC019().check(schema, {}) == []


def test_sec019_silent_on_policy_without_current_setting() -> None:
    assert SEC019().check(_wrap(_policy("tenant_id = id")), {}) == []


def test_sec019_silent_when_policy_has_no_clauses() -> None:
    # USING and WITH CHECK both parsed to None (empty clauses or a
    # parse failure) — nothing for SEC019 to walk.
    schema = _wrap(_policy(using=None, with_check=None))
    assert SEC019().check(schema, {}) == []


# --- allowlist / multiplicity / metadata ---------------------------------


def test_sec019_fires_once_per_policy_with_multiple_one_arg_calls() -> None:
    schema = _wrap(
        _policy(
            "tenant_id = current_setting('app.tenant') "
            "OR id::text = current_setting('app.id')"
        )
    )
    assert len(SEC019().check(schema, {})) == 1


def test_sec019_fires_on_each_offending_policy_independently() -> None:
    schema = Schema(
        tables=(
            Table(
                schema="public",
                name="t",
                rls_enabled=True,
                force_rls=True,
                columns=("id", "tenant_id"),
                policies=(
                    _policy(
                        "tenant_id = current_setting('app.tenant')",
                        name="bad_a",
                    ),
                    _policy(
                        "tenant_id = current_setting('app.tenant', true)",
                        name="ok",
                    ),
                    _policy(
                        "tenant_id = current_setting('app.t')",
                        name="bad_b",
                    ),
                ),
            ),
        )
    )
    locations = sorted(v.location for v in SEC019().check(schema, {}))
    assert locations == ["public.t.bad_a", "public.t.bad_b"]


def test_sec019_allowlist_exempts_qualified_policy_id() -> None:
    # Allowlist a policy when the raise-on-unset behaviour is the
    # intended, documented choice.
    schema = _wrap(_policy("tenant_id = current_setting('app.tenant')"))
    assert SEC019().check(schema, {"allowlist": ["public.t.p"]}) == []


def test_sec019_bad_allowlist_type_raises_clearly() -> None:
    schema = _wrap(_policy("tenant_id = current_setting('app.tenant')"))
    with pytest.raises(TypeError, match="allowlist"):
        SEC019().check(schema, {"allowlist": "public.t.p"})  # type: ignore[dict-item]


def test_sec019_message_recommends_two_arg_form() -> None:
    schema = _wrap(_policy("tenant_id = current_setting('app.tenant')"))
    [v] = SEC019().check(schema, {})
    assert "true" in v.message  # names the two-arg form
    assert "info-level" in v.message


def test_sec019_metadata_present() -> None:
    rule = SEC019()
    assert rule.id == "SEC019"
    assert rule.severity == "info"
    assert rule.title
