"""Unit tests for SEC010 — policy USING clause is constant false."""
from __future__ import annotations

import pytest

from pgrls.ast_utils import parse_expr
from pgrls.model import Policy, Schema, Table
from pgrls.rules.sec010 import SEC010


def _policy(
    using: str | None = "false",
    *,
    name: str = "p",
    command: str = "SELECT",
    permissive: bool = True,
    with_check: str | None = None,
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


def _wrap(policy: Policy) -> Schema:
    return Schema(
        tables=(
            Table(
                schema="public",
                name="t",
                rls_enabled=True,
                force_rls=True,
                policies=(policy,),
                columns=("id",),
            ),
        )
    )


def test_sec010_fires_on_using_false() -> None:
    schema = _wrap(_policy("false"))
    violations = SEC010().check(schema, {})
    assert len(violations) == 1
    v = violations[0]
    assert v.rule_id == "SEC010"
    assert v.severity == "warning"
    assert v.location == "public.t.p"
    assert "false" in v.message.lower()


def test_sec010_silent_on_using_true() -> None:
    # `USING (true)` is SEC008's territory; SEC010 must not double-up.
    schema = _wrap(_policy("true"))
    assert SEC010().check(schema, {}) == []


def test_sec010_silent_on_real_predicate() -> None:
    schema = _wrap(_policy("id > 0"))
    assert SEC010().check(schema, {}) == []


def test_sec010_silent_on_using_not_true() -> None:
    # `NOT true` is logically `false` but the AST is BoolExpr+A_Const,
    # not a literal Boolean false. SEC010's detector keys on the
    # literal A_Const, mirroring SEC008's treatment of `NOT false`.
    # Pin the asymmetry — semantic-equivalence detection is a
    # significant infrastructure investment for marginal real-world
    # value (most disguised cases are SEC005 anyway).
    schema = _wrap(_policy("NOT true"))
    assert SEC010().check(schema, {}) == []


def test_sec010_silent_when_using_is_none() -> None:
    # INSERT-only policies have no USING clause.
    p = _policy(None, command="INSERT")
    schema = _wrap(p)
    assert SEC010().check(schema, {}) == []


def test_sec010_fires_on_restrictive_false_too() -> None:
    # RESTRICTIVE `USING (false)` is even more clearly a deny-all
    # anti-pattern (AND with false ⇒ false everywhere). The rule
    # fires regardless of permissive/restrictive — the literal-
    # false pattern is the smell.
    schema = _wrap(_policy("false", permissive=False))
    assert len(SEC010().check(schema, {})) == 1


def test_sec010_allowlist_exempts_qualified_policy_id() -> None:
    schema = _wrap(_policy("false"))
    options = {"allowlist": ["public.t.p"]}
    assert SEC010().check(schema, options) == []


def test_sec010_bad_allowlist_type_raises_clearly() -> None:
    schema = _wrap(_policy("false"))
    with pytest.raises(TypeError, match="allowlist"):
        SEC010().check(schema, {"allowlist": "public.t.p"})  # type: ignore[dict-item]


def test_sec010_bad_allowlist_item_type_raises_clearly() -> None:
    schema = _wrap(_policy("false"))
    with pytest.raises(TypeError, match="allowlist"):
        SEC010().check(schema, {"allowlist": ["public.t.p", 42]})  # type: ignore[list-item]


def test_sec010_fires_on_each_offending_policy_independently() -> None:
    schema = Schema(
        tables=(
            Table(
                schema="public",
                name="t",
                rls_enabled=True,
                force_rls=True,
                columns=("id",),
                policies=(
                    _policy("false", name="bad_a"),
                    _policy("id > 0", name="ok"),
                    _policy("false", name="bad_b", permissive=False),
                ),
            ),
        )
    )
    locations = sorted(v.location for v in SEC010().check(schema, {}))
    assert locations == ["public.t.bad_a", "public.t.bad_b"]


def test_sec010_metadata_present() -> None:
    rule = SEC010()
    assert rule.id == "SEC010"
    assert rule.severity == "warning"
    assert rule.title


def test_sec010_fires_on_with_check_false_for_insert_policy() -> None:
    # `WITH CHECK (false)` is the write-side mirror of
    # `USING (false)`. The author wrote a deny-all-writes policy
    # — the right primitive is REVOKE INSERT at the GRANT layer,
    # not a policy that makes the table look RLS-protected.
    p = _policy(using=None, command="INSERT", with_check="false")
    schema = _wrap(p)
    violations = SEC010().check(schema, {})
    assert len(violations) == 1
    assert "WITH CHECK" in violations[0].message
    assert "rejects every write" in violations[0].message


def test_sec010_fires_on_with_check_false_when_using_is_real() -> None:
    # The most damaging case: USING references a real own-column
    # so SEC005 stays silent. WITH CHECK is `false`, so all writes
    # die. Without walking with_check_ast, no rule catches this.
    p = _policy(
        using="id > 0",
        command="UPDATE",
        with_check="false",
        permissive=False,  # Restrictive UPDATE; common shape.
    )
    schema = _wrap(p)
    violations = SEC010().check(schema, {})
    assert len(violations) == 1
    assert "WITH CHECK" in violations[0].message


def test_sec010_message_distinguishes_using_vs_with_check() -> None:
    # USING (false) → "denies every row"; WITH CHECK (false) →
    # "rejects every write". Two different framings because the
    # remediation hint differs (REVOKE ALL vs REVOKE INSERT,UPDATE).
    using_only = _wrap(_policy("false"))
    check_only = _wrap(
        _policy(using=None, command="INSERT", with_check="false")
    )
    using_msg = SEC010().check(using_only, {})[0].message
    check_msg = SEC010().check(check_only, {})[0].message
    assert "denies every row" in using_msg
    assert "REVOKE ALL" in using_msg
    assert "rejects every write" in check_msg
    assert "REVOKE INSERT" in check_msg


def test_sec010_silent_on_with_check_true() -> None:
    # `WITH CHECK (true)` is permissive's no-op — out of SEC010
    # scope. Mirror of the SEC008/SEC010 split on USING.
    p = _policy(using=None, command="INSERT", with_check="true")
    schema = _wrap(p)
    assert SEC010().check(schema, {}) == []
