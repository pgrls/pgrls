"""Unit tests for SEC006 — INSERT/UPDATE/ALL policy missing WITH CHECK."""
from __future__ import annotations

from pgrls.model import Policy, Schema, Table
from pgrls.rules.sec006 import SEC006


def _policy(
    name: str,
    *,
    command: str,
    with_check: str | None,
) -> Policy:
    return Policy(
        name=name,
        command=command,  # type: ignore[arg-type]
        permissive=True,
        roles=("authenticated",),
        using_sql="tenant_id = current_setting('app.t')",
        with_check_sql=with_check,
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


def test_sec006_fires_on_insert_without_with_check() -> None:
    violations = SEC006().check(
        _wrap(_policy("p", command="INSERT", with_check=None)), {}
    )
    assert len(violations) == 1
    assert violations[0].location == "public.t.p"


def test_sec006_fires_on_update_without_with_check() -> None:
    violations = SEC006().check(
        _wrap(_policy("p", command="UPDATE", with_check=None)), {}
    )
    assert len(violations) == 1


def test_sec006_fires_on_all_without_with_check() -> None:
    violations = SEC006().check(
        _wrap(_policy("p", command="ALL", with_check=None)), {}
    )
    assert len(violations) == 1


def test_sec006_does_not_fire_on_select_without_with_check() -> None:
    violations = SEC006().check(
        _wrap(_policy("p", command="SELECT", with_check=None)), {}
    )
    assert violations == []


def test_sec006_does_not_fire_when_with_check_present() -> None:
    violations = SEC006().check(
        _wrap(
            _policy(
                "p",
                command="INSERT",
                with_check="tenant_id = current_setting('app.t')",
            )
        ),
        {},
    )
    assert violations == []


def test_sec006_allowlist_exempts_qualified_policy_id() -> None:
    violations = SEC006().check(
        _wrap(_policy("p", command="INSERT", with_check=None)),
        {"allowlist": ["public.t.p"]},
    )
    assert violations == []


def test_sec006_bad_allowlist_type_raises_clearly() -> None:
    import pytest
    with pytest.raises(TypeError, match="allowlist"):
        SEC006().check(
            _wrap(_policy("p", command="INSERT", with_check=None)),
            {"allowlist": "p"},  # type: ignore[dict-item]
        )


def test_sec006_bad_allowlist_item_type_raises_clearly() -> None:
    import pytest
    with pytest.raises(TypeError, match="allowlist"):
        SEC006().check(
            _wrap(_policy("p", command="INSERT", with_check=None)),
            {"allowlist": ["public.t.p", None]},  # type: ignore[list-item]
        )


def test_sec006_does_not_fire_on_delete_without_with_check() -> None:
    # DELETE has no WITH CHECK semantics in Postgres; SEC006 must skip it.
    violations = SEC006().check(
        _wrap(_policy("p", command="DELETE", with_check=None)), {}
    )
    assert violations == []


def test_sec006_treats_empty_with_check_as_absent() -> None:
    # `pg_get_expr` never returns "" for a real WITH CHECK clause,
    # so an empty string can only come from a hand-built or
    # snapshot-loaded Policy. Treat it as functionally absent so
    # the rule doesn't silently slip past on the empty-string
    # boundary.
    violations = SEC006().check(
        _wrap(_policy("p", command="INSERT", with_check="")), {}
    )
    assert len(violations) == 1
    assert violations[0].location == "public.t.p"


def test_sec006_fires_on_each_offending_policy_independently() -> None:
    schema = Schema(
        tables=(
            Table(
                schema="public",
                name="t",
                rls_enabled=True,
                force_rls=True,
                policies=(
                    _policy("a", command="INSERT", with_check=None),
                    _policy("b", command="UPDATE", with_check="x = 1"),
                    _policy("c", command="ALL", with_check=None),
                    _policy("d", command="SELECT", with_check=None),
                ),
            ),
        )
    )
    violations = SEC006().check(schema, {})
    locations = sorted(v.location for v in violations)
    assert locations == ["public.t.a", "public.t.c"]


