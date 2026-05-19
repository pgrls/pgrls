"""Unit tests for SEC023 — policy applies to a role that bypasses RLS.

SEC023 fires when a policy's `TO` clause names a non-superuser role
carrying the BYPASSRLS attribute. Such a role skips every RLS
policy, so the `TO` reference is inert: the policy's predicate is
never evaluated for it. The rule is a cross-reference between
`Policy.roles` and `Schema.bypassrls_roles` — no AST walk.
"""
from __future__ import annotations

import pytest

from pgrls.model import BypassRlsRole, Policy, Schema, Table
from pgrls.rules.sec023 import SEC023


def _role(
    name: str,
    *,
    superuser: bool = False,
    can_login: bool = True,
) -> BypassRlsRole:
    return BypassRlsRole(
        name=name, superuser=superuser, can_login=can_login
    )


def _policy(
    *,
    name: str = "p",
    roles: tuple[str, ...] = ("PUBLIC",),
    command: str = "SELECT",
    permissive: bool = True,
) -> Policy:
    return Policy(
        name=name,
        command=command,
        permissive=permissive,
        roles=roles,
        using_sql="tenant_id = current_setting('app.t', true)",
        with_check_sql=None,
    )


def _table(*policies: Policy, name: str = "docs") -> Table:
    return Table(
        schema="public",
        name=name,
        rls_enabled=True,
        force_rls=True,
        policies=policies,
        columns=("id", "tenant_id"),
    )


# --- firing --------------------------------------------------------------


def test_sec023_fires_when_policy_targets_bypassrls_role() -> None:
    schema = Schema(
        tables=(_table(_policy(name="scope", roles=("etl_worker",))),),
        bypassrls_roles=(_role("etl_worker"),),
    )
    [v] = SEC023().check(schema, options={})
    assert v.rule_id == "SEC023"
    assert v.severity == "warning"
    assert v.location == "public.docs.scope"
    assert "etl_worker" in v.message
    assert "BYPASSRLS" in v.message


def test_sec023_silent_when_no_bypassrls_roles() -> None:
    # A policy that names a role is fine when that role does not
    # bypass RLS — the schema reports an empty BYPASSRLS set.
    schema = Schema(
        tables=(_table(_policy(roles=("app_user",))),),
    )
    assert SEC023().check(schema, options={}) == []


def test_sec023_silent_when_policy_targets_only_normal_roles() -> None:
    # `app_user` is not in the BYPASSRLS set, so the policy
    # genuinely constrains it — nothing to flag.
    schema = Schema(
        tables=(_table(_policy(roles=("app_user",))),),
        bypassrls_roles=(_role("etl_worker"),),
    )
    assert SEC023().check(schema, options={}) == []


def test_sec023_silent_on_to_public_policy() -> None:
    # `TO PUBLIC` is reported as the pseudo-role 'PUBLIC', never a
    # real rolname — it does not intersect the BYPASSRLS set. A
    # BYPASSRLS role is covered by a PUBLIC policy and bypasses it,
    # but that is SEC016's finding, not this policy's.
    schema = Schema(
        tables=(_table(_policy(roles=("PUBLIC",))),),
        bypassrls_roles=(_role("etl_worker"),),
    )
    assert SEC023().check(schema, options={}) == []


def test_sec023_skips_superuser_bypassrls_role() -> None:
    # A superuser bypasses RLS via rolsuper regardless of the
    # BYPASSRLS attribute; SEC023 skips it exactly as SEC016 does,
    # rather than restating "this role is a superuser".
    schema = Schema(
        tables=(_table(_policy(roles=("admin",))),),
        bypassrls_roles=(_role("admin", superuser=True),),
    )
    assert SEC023().check(schema, options={}) == []


def test_sec023_fires_when_bypassrls_role_is_one_of_several() -> None:
    # The policy also targets a normal role; it still works for
    # that role, but the BYPASSRLS role portion is inert — fire,
    # and name only the offending role.
    schema = Schema(
        tables=(
            _table(_policy(roles=("app_user", "etl_worker"))),
        ),
        bypassrls_roles=(_role("etl_worker"),),
    )
    [v] = SEC023().check(schema, options={})
    assert "etl_worker" in v.message
    assert "app_user" not in v.message


def test_sec023_one_violation_lists_every_bypassing_role() -> None:
    # A policy naming two BYPASSRLS roles is one finding (keyed on
    # the policy), and the message names both, sorted.
    schema = Schema(
        tables=(
            _table(_policy(roles=("zeta_etl", "alpha_etl"))),
        ),
        bypassrls_roles=(_role("zeta_etl"), _role("alpha_etl")),
    )
    violations = SEC023().check(schema, options={})
    assert len(violations) == 1
    msg = violations[0].message
    assert msg.index("alpha_etl") < msg.index("zeta_etl")
    assert "carry the BYPASSRLS" in msg


def test_sec023_fires_per_policy_across_tables() -> None:
    schema = Schema(
        tables=(
            _table(_policy(name="a", roles=("etl",)), name="t1"),
            _table(_policy(name="b", roles=("etl",)), name="t2"),
        ),
        bypassrls_roles=(_role("etl"),),
    )
    locations = {v.location for v in SEC023().check(schema, options={})}
    assert locations == {"public.t1.a", "public.t2.b"}


def test_sec023_fires_regardless_of_permissive_or_command() -> None:
    # SEC023 does not inspect the predicate or the policy kind — a
    # restrictive write policy targeting a bypassing role is just
    # as inert as a permissive read one.
    schema = Schema(
        tables=(
            _table(
                _policy(
                    name="w",
                    roles=("etl",),
                    permissive=False,
                    command="ALL",
                )
            ),
        ),
        bypassrls_roles=(_role("etl"),),
    )
    [v] = SEC023().check(schema, options={})
    assert v.location == "public.docs.w"


# --- message detail ------------------------------------------------------


def test_sec023_message_names_remediation_and_siblings() -> None:
    schema = Schema(
        tables=(_table(_policy(name="scope", roles=("etl_worker",))),),
        bypassrls_roles=(_role("etl_worker"),),
    )
    [v] = SEC023().check(schema, options={})
    # The two remediations and the related role-level rule.
    assert "NOBYPASSRLS" in v.message
    assert "SEC016" in v.message
    # The allowlist hint carries the exact qualified policy ID.
    assert "'public.docs.scope'" in v.message
    assert "[lint.rules.SEC023]" in v.message


# --- allowlist -----------------------------------------------------------


def test_sec023_allowlist_skips_named_policy() -> None:
    schema = Schema(
        tables=(
            _table(_policy(name="exempt", roles=("etl",)), name="t1"),
            _table(_policy(name="active", roles=("etl",)), name="t2"),
        ),
        bypassrls_roles=(_role("etl"),),
    )
    violations = SEC023().check(
        schema, options={"allowlist": ["public.t1.exempt"]}
    )
    assert [v.location for v in violations] == ["public.t2.active"]


def test_sec023_allowlist_rejects_non_list() -> None:
    schema = Schema(
        tables=(_table(_policy(roles=("etl",))),),
        bypassrls_roles=(_role("etl"),),
    )
    with pytest.raises(TypeError, match="allowlist"):
        SEC023().check(schema, options={"allowlist": "public.docs.p"})


def test_sec023_allowlist_rejects_whitespace_padded_entry() -> None:
    # The allowlist matches a qualified policy ID byte-for-byte; a
    # padded entry would silently never match, so it is rejected.
    schema = Schema(
        tables=(_table(_policy(roles=("etl",))),),
        bypassrls_roles=(_role("etl"),),
    )
    with pytest.raises(TypeError, match="allowlist"):
        SEC023().check(
            schema, options={"allowlist": [" public.docs.p "]}
        )
