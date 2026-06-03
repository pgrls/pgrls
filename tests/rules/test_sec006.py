"""Unit tests for SEC006 — INSERT/UPDATE/ALL policy missing WITH CHECK."""
from __future__ import annotations

from pgrls.ast_utils import parse_expr
from pgrls.model import Policy, Schema, Table
from pgrls.rules.sec006 import SEC006

# The common multi-tenant USING predicate. A real (non-constant) USING is
# what Postgres reuses as the implicit WITH CHECK on UPDATE/ALL, so a
# permissive policy carrying it is NOT an open write.
_REAL_USING = "tenant_id = current_setting('app.t')"


def _policy(
    name: str,
    *,
    command: str,
    with_check: str | None,
    permissive: bool = True,
    using: str | None = _REAL_USING,
) -> Policy:
    return Policy(
        name=name,
        command=command,  # type: ignore[arg-type]
        permissive=permissive,
        roles=("authenticated",),
        using_sql=using,
        using_ast=parse_expr(using) if using else None,
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


def test_sec006_suppresses_permissive_update_with_reusable_using() -> None:
    # Permissive FOR UPDATE with a real USING and no WITH CHECK is NOT an
    # open write: Postgres reuses the USING expression as the implicit
    # WITH CHECK, so the written row must still satisfy `tenant_id = …`.
    # This is the most common multi-tenant shape; firing here was a false
    # positive that failed clean-lint CI.
    violations = SEC006().check(
        _wrap(_policy("p", command="UPDATE", with_check=None)), {}
    )
    assert violations == []


def test_sec006_suppresses_permissive_all_with_reusable_using() -> None:
    # Same reuse semantics apply to FOR ALL (its write side is INSERT and
    # UPDATE, both of which honour the reused WITH CHECK).
    violations = SEC006().check(
        _wrap(_policy("p", command="ALL", with_check=None)), {}
    )
    assert violations == []


def test_sec006_fires_on_update_without_using_or_with_check() -> None:
    # No USING for Postgres to reuse → the write side is genuinely
    # unconstrained, so the finding is real.
    violations = SEC006().check(
        _wrap(_policy("p", command="UPDATE", with_check=None, using=None)),
        {},
    )
    assert len(violations) == 1
    assert violations[0].location == "public.t.p"


def test_sec006_fires_on_all_with_constant_true_using() -> None:
    # A constant-true USING reused as WITH CHECK admits every written row,
    # so the write side is still open — the finding is real.
    violations = SEC006().check(
        _wrap(_policy("p", command="ALL", with_check=None, using="true")),
        {},
    )
    assert len(violations) == 1
    assert violations[0].location == "public.t.p"


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
                    # Real USING reused as WITH CHECK → closed → no finding.
                    _policy("c", command="ALL", with_check=None),
                    _policy("d", command="SELECT", with_check=None),
                    # No USING to reuse → genuinely open → finding.
                    _policy("e", command="ALL", with_check=None, using=None),
                ),
            ),
        )
    )
    violations = SEC006().check(schema, {})
    locations = sorted(v.location for v in violations)
    assert locations == ["public.t.a", "public.t.e"]


def test_sec006_restrictive_write_policy_emits_dead_policy_message() -> None:
    # A restrictive INSERT with no WITH CHECK is genuinely dead — INSERT
    # carries no USING for Postgres to reuse, so the missing clause
    # defaults to `true` and the policy constrains nothing. SEC006 fires
    # with the dead-policy diagnosis (a hygiene bug, not a security hole).
    p = _policy(
        "restrictive_floor",
        command="INSERT",
        with_check=None,
        permissive=False,
    )
    schema = _wrap(p)
    violations = SEC006().check(schema, {})
    assert len(violations) == 1
    msg = violations[0].message
    assert "Restrictive policy" in msg
    assert "dead policy" in msg
    assert "defaults the missing clause to `true`" in msg


def test_sec006_suppresses_restrictive_update_all_with_reusable_using() -> None:
    # Regression (round-5): a restrictive FOR UPDATE/ALL with a real USING
    # and no WITH CHECK is NOT a dead policy — Postgres reuses the USING as
    # the implicit WITH CHECK for restrictive policies too, so the write
    # side is constrained. Flagging it was an error-severity false positive
    # whose "remove the policy" remediation would delete a real constraint.
    for command in ("UPDATE", "ALL"):
        violations = SEC006().check(
            _wrap(
                _policy("p", command=command, with_check=None,
                        permissive=False)
            ),
            {},
        )
        assert violations == [], command


def test_sec006_restrictive_open_shapes_still_dead_policy() -> None:
    # A restrictive write policy with nothing to reuse still fires the
    # dead-policy diagnosis: INSERT (no USING), or UPDATE/ALL whose USING
    # is absent or constant-true.
    for command, using in (
        ("UPDATE", None),
        ("ALL", "true"),
    ):
        violations = SEC006().check(
            _wrap(
                _policy("p", command=command, with_check=None,
                        permissive=False, using=using)
            ),
            {},
        )
        assert len(violations) == 1, (command, using)
        assert "dead policy" in violations[0].message


def test_sec006_permissive_message_unchanged() -> None:
    # The permissive case is the security hole the rule was
    # originally written for. Pin its message wording so a future
    # message refactor doesn't accidentally regress.
    p = _policy(
        "p",
        command="INSERT",
        with_check=None,
        permissive=True,
    )
    schema = _wrap(p)
    msg = SEC006().check(schema, {})[0].message
    assert "Restrictive policy" not in msg
    assert "writes that violate the policy's intent are accepted" in msg


