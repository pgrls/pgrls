"""Unit tests for SEC003 — Permissive policy grants PUBLIC."""
from __future__ import annotations

from pgrls.model import Policy, Schema, Table
from pgrls.rules.sec003 import SEC003


def _table_with_policy(policy: Policy) -> Table:
    return Table(
        schema="public",
        name="t",
        rls_enabled=True,
        force_rls=True,
        policies=(policy,),
    )


def _policy(name: str, *, permissive: bool, roles: tuple[str, ...]) -> Policy:
    return Policy(
        name=name,
        command="SELECT",
        permissive=permissive,
        roles=roles,
        using_sql="true",
        with_check_sql=None,
    )


def test_sec003_fires_on_permissive_public_policy() -> None:
    schema = Schema(
        tables=(
            _table_with_policy(
                _policy("p", permissive=True, roles=("PUBLIC",))
            ),
        )
    )
    violations = SEC003().check(schema, options={})
    assert len(violations) == 1
    v = violations[0]
    assert v.rule_id == "SEC003"
    assert v.severity == "error"
    assert v.location == "public.t.p"


def test_sec003_does_not_fire_on_restrictive_public_policy() -> None:
    schema = Schema(
        tables=(
            _table_with_policy(
                _policy("p", permissive=False, roles=("PUBLIC",))
            ),
        )
    )
    assert SEC003().check(schema, options={}) == []


def test_sec003_does_not_fire_on_permissive_specific_role() -> None:
    schema = Schema(
        tables=(
            _table_with_policy(
                _policy("p", permissive=True, roles=("authenticated",))
            ),
        )
    )
    assert SEC003().check(schema, options={}) == []


def test_sec003_allowlist_exempts_qualified_policy_id() -> None:
    schema = Schema(
        tables=(
            _table_with_policy(
                _policy("p", permissive=True, roles=("PUBLIC",))
            ),
        )
    )
    assert SEC003().check(
        schema, options={"allowlist": ["public.t.p"]}
    ) == []


def test_sec003_bad_allowlist_type_raises_clearly() -> None:
    schema = Schema(
        tables=(
            _table_with_policy(
                _policy("p", permissive=True, roles=("PUBLIC",))
            ),
        )
    )
    import pytest
    with pytest.raises(TypeError, match="allowlist"):
        SEC003().check(schema, options={"allowlist": "p"})  # type: ignore[arg-type]


def test_sec003_bad_allowlist_item_type_raises_clearly() -> None:
    schema = Schema(
        tables=(
            _table_with_policy(
                _policy("p", permissive=True, roles=("PUBLIC",))
            ),
        )
    )
    import pytest
    with pytest.raises(TypeError, match="allowlist"):
        SEC003().check(
            schema,
            options={"allowlist": ["public.t.p", 42]},  # type: ignore[list-item]
        )


def test_sec003_empty_allowlist_behaves_like_default() -> None:
    schema = Schema(
        tables=(
            _table_with_policy(
                _policy("p", permissive=True, roles=("PUBLIC",))
            ),
        )
    )
    assert len(SEC003().check(schema, options={"allowlist": []})) == 1


def test_sec003_does_not_fire_on_permissive_policy_with_no_roles() -> None:
    # roles=() means the policy lists no roles at all. PUBLIC must be
    # explicitly named for SEC003 to fire — implicit-PUBLIC behavior in
    # Postgres is not assumed by this rule.
    schema = Schema(
        tables=(
            _table_with_policy(
                _policy("p", permissive=True, roles=())
            ),
        )
    )
    assert SEC003().check(schema, options={}) == []


def test_sec003_fires_on_each_offending_policy_independently() -> None:
    schema = Schema(
        tables=(
            Table(
                schema="public",
                name="t",
                rls_enabled=True,
                force_rls=True,
                policies=(
                    _policy("a", permissive=True, roles=("PUBLIC",)),
                    _policy("b", permissive=True, roles=("PUBLIC",)),
                    _policy("c", permissive=True, roles=("authenticated",)),
                ),
            ),
        )
    )
    violations = SEC003().check(schema, options={})
    locations = sorted(v.location for v in violations)
    assert locations == ["public.t.a", "public.t.b"]
