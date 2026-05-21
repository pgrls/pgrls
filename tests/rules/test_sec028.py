"""Unit tests for SEC028 — write-side policy WITH CHECK is constant true.

SEC028 (warning) fires when a PERMISSIVE write policy (INSERT /
UPDATE / ALL) has a `WITH CHECK (true)` clause and no restrictive
USING to contrast with — the open-write footgun that SEC006
(missing WITH CHECK), SEC008 (USING true), and SEC020 (WITH CHECK
true *while USING restricts*) all miss.
"""
from __future__ import annotations

import pytest

from pgrls.ast_utils import parse_expr
from pgrls.model import Policy, Schema, Table
from pgrls.rules.sec028 import SEC028


def _policy(
    *,
    name: str = "p",
    command: str = "INSERT",
    permissive: bool = True,
    using: str | None = None,
    with_check: str | None = "true",
) -> Policy:
    return Policy(
        name=name,
        command=command,  # type: ignore[arg-type]
        permissive=permissive,
        roles=("PUBLIC",),
        using_sql=using,
        with_check_sql=with_check,
        using_ast=parse_expr(using) if using else None,
        with_check_ast=parse_expr(with_check) if with_check else None,
    )


def _table(*policies: Policy, name: str = "documents") -> Table:
    return Table(
        schema="public",
        name=name,
        rls_enabled=True,
        force_rls=True,
        policies=policies,
        columns=("id", "tenant_id"),
    )


# --- firing --------------------------------------------------------------


def test_sec028_fires_on_for_insert_with_check_true() -> None:
    schema = Schema(tables=(_table(_policy(command="INSERT")),))
    [v] = SEC028().check(schema, options={})
    assert v.rule_id == "SEC028"
    assert v.severity == "warning"
    assert v.location == "public.documents.p"
    assert "WITH CHECK (true)" in v.message
    assert "allowlist" in v.message


def test_sec028_fires_on_for_all_with_using_and_check_both_true() -> None:
    # USING true is not a *restrictive* USING, so SEC020 doesn't own
    # this — SEC028 does (the policy is open on the write side).
    schema = Schema(
        tables=(_table(_policy(command="ALL", using="true", with_check="true")),)
    )
    [v] = SEC028().check(schema, options={})
    assert v.location == "public.documents.p"


def test_sec028_fires_on_for_update_with_check_true_no_using() -> None:
    schema = Schema(
        tables=(_table(_policy(command="UPDATE", using=None, with_check="true")),)
    )
    [v] = SEC028().check(schema, options={})
    assert v.location == "public.documents.p"


# --- silent: ceded to other rules ---------------------------------------


def test_sec028_silent_when_using_is_a_real_predicate() -> None:
    # USING restricts + WITH CHECK true is SEC020's asymmetry, not
    # SEC028's open-write case.
    schema = Schema(
        tables=(
            _table(
                _policy(
                    command="ALL",
                    using="tenant_id = 1",
                    with_check="true",
                )
            ),
        )
    )
    assert SEC028().check(schema, options={}) == []


def test_sec028_silent_when_with_check_is_a_real_predicate() -> None:
    schema = Schema(
        tables=(_table(_policy(command="INSERT", with_check="tenant_id = 1")),)
    )
    assert SEC028().check(schema, options={}) == []


def test_sec028_silent_when_with_check_absent() -> None:
    # Missing WITH CHECK is SEC006's surface, not SEC028's.
    schema = Schema(
        tables=(_table(_policy(command="INSERT", with_check=None)),)
    )
    assert SEC028().check(schema, options={}) == []


def test_sec028_silent_on_select_only_policy() -> None:
    # SELECT is not a write command; a SELECT policy has no
    # write side to leave open.
    schema = Schema(
        tables=(
            _table(
                _policy(command="SELECT", using="true", with_check=None)
            ),
        )
    )
    assert SEC028().check(schema, options={}) == []


def test_sec028_silent_on_restrictive_policy() -> None:
    # A restrictive WITH CHECK (true) is a dead clause (restrictive
    # policies AND-combine; it opens nothing on its own), not an
    # open-write hole.
    schema = Schema(
        tables=(
            _table(
                _policy(command="INSERT", permissive=False, with_check="true")
            ),
        )
    )
    assert SEC028().check(schema, options={}) == []


# --- allowlist -----------------------------------------------------------


def test_sec028_respects_allowlist() -> None:
    schema = Schema(tables=(_table(_policy(command="INSERT")),))
    assert (
        SEC028().check(schema, options={"allowlist": ["public.documents.p"]})
        == []
    )


def test_sec028_raises_on_malformed_allowlist() -> None:
    schema = Schema(tables=(_table(_policy(command="INSERT")),))
    with pytest.raises(TypeError, match="allowlist"):
        SEC028().check(schema, options={"allowlist": "public.documents.p"})


def test_sec028_emits_one_per_offending_policy() -> None:
    schema = Schema(
        tables=(
            _table(
                _policy(name="ins", command="INSERT", with_check="true"),
                _policy(
                    name="upd_ok",
                    command="UPDATE",
                    using="tenant_id = 1",
                    with_check="tenant_id = 1",
                ),
                _policy(name="all_open", command="ALL", with_check="true"),
            ),
        )
    )
    locs = sorted(v.location for v in SEC028().check(schema, options={}))
    assert locs == ["public.documents.all_open", "public.documents.ins"]
