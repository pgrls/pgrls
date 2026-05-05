"""Unit tests for SEC012 — table has only RESTRICTIVE policies (silent deny-all)."""
from __future__ import annotations

import pytest

from pgrls.model import Policy, Schema, Table
from pgrls.rules.sec012 import SEC012


def _table(
    name: str,
    *,
    rls: bool = True,
    schema: str = "public",
    policies: tuple[Policy, ...] = (),
) -> Table:
    return Table(
        schema=schema,
        name=name,
        rls_enabled=rls,
        force_rls=rls,  # mirror RLS so SEC002 isn't a confound
        policies=policies,
    )


def _policy(name: str = "p", *, permissive: bool = True) -> Policy:
    return Policy(
        name=name,
        command="SELECT",
        permissive=permissive,
        roles=("authenticated",),
        using_sql="true",
        with_check_sql=None,
    )


def test_sec012_fires_when_only_restrictive_policies() -> None:
    schema = Schema(
        tables=(
            _table(
                "invoices",
                policies=(_policy("tenant_lock", permissive=False),),
            ),
        )
    )
    violations = SEC012().check(schema, {})
    assert len(violations) == 1
    v = violations[0]
    assert v.rule_id == "SEC012"
    assert v.severity == "warning"
    assert v.location == "public.invoices"
    assert "RESTRICTIVE" in v.message
    assert "PERMISSIVE" in v.message


def test_sec012_silent_when_at_least_one_permissive_policy() -> None:
    # The canonical correct shape: PERMISSIVE grants access, RESTRICTIVE
    # narrows it. SEC012 must NOT fire here.
    schema = Schema(
        tables=(
            _table(
                "invoices",
                policies=(
                    _policy("tenant_read", permissive=True),
                    _policy("tenant_lock", permissive=False),
                ),
            ),
        )
    )
    assert SEC012().check(schema, {}) == []


def test_sec012_silent_when_rls_disabled() -> None:
    # SEC001 covers the rls=False case. Even though "only RESTRICTIVE
    # policies" is structurally present, with RLS off the policies
    # aren't applied at all — SEC012 must not double up.
    schema = Schema(
        tables=(
            _table(
                "orders",
                rls=False,
                policies=(_policy("tenant_lock", permissive=False),),
            ),
        )
    )
    assert SEC012().check(schema, {}) == []


def test_sec012_silent_when_no_policies() -> None:
    # SEC009 covers the empty-policies case. Don't double-fire.
    schema = Schema(tables=(_table("audit_log"),))
    assert SEC012().check(schema, {}) == []


def test_sec012_fires_per_table_independently() -> None:
    # Two tables, each with only-RESTRICTIVE — both fire, in
    # `Schema.tables` order (the rule preserves caller order).
    schema = Schema(
        tables=(
            _table(
                "invoices",
                policies=(_policy("a", permissive=False),),
            ),
            _table(
                "shipments",
                policies=(_policy("b", permissive=False),),
            ),
        )
    )
    violations = SEC012().check(schema, {})
    assert [v.location for v in violations] == [
        "public.invoices",
        "public.shipments",
    ]


def test_sec012_message_pluralizes_policy_count() -> None:
    one = Schema(
        tables=(
            _table(
                "single",
                policies=(_policy("a", permissive=False),),
            ),
        )
    )
    two = Schema(
        tables=(
            _table(
                "multi",
                policies=(
                    _policy("a", permissive=False),
                    _policy("b", permissive=False),
                ),
            ),
        )
    )
    [one_v] = SEC012().check(one, {})
    [two_v] = SEC012().check(two, {})
    assert "1 RESTRICTIVE policy" in one_v.message
    assert "2 RESTRICTIVE policies" in two_v.message


@pytest.mark.parametrize(
    "allowlist_entry",
    [
        "shadow_table",  # unqualified
        "public.shadow_table",  # qualified
    ],
)
def test_sec012_allowlist_silences_table(allowlist_entry: str) -> None:
    schema = Schema(
        tables=(
            _table(
                "shadow_table",
                policies=(_policy("a", permissive=False),),
            ),
        )
    )
    options = {"allowlist": [allowlist_entry]}
    assert SEC012().check(schema, options) == []


def test_sec012_allowlist_does_not_silence_other_tables() -> None:
    # Allowlisting `audit_log` must NOT silence `invoices`.
    schema = Schema(
        tables=(
            _table(
                "audit_log",
                policies=(_policy("a", permissive=False),),
            ),
            _table(
                "invoices",
                policies=(_policy("b", permissive=False),),
            ),
        )
    )
    options = {"allowlist": ["audit_log"]}
    violations = SEC012().check(schema, options)
    assert [v.location for v in violations] == ["public.invoices"]


def test_sec012_bad_allowlist_type_raises_clearly() -> None:
    schema = Schema(tables=())
    with pytest.raises(TypeError, match=r"\[lint\.rules\.SEC012\]"):
        SEC012().check(schema, {"allowlist": "not_a_list"})


def test_sec012_bad_allowlist_entry_shape_raises_clearly() -> None:
    # Three-part entries (policy IDs) aren't valid for SEC012's
    # table-ref allowlist; the helper rejects them with the rule_id
    # in the error.
    schema = Schema(tables=())
    with pytest.raises(TypeError, match="SEC012"):
        SEC012().check(
            schema, {"allowlist": ["public.invoices.bad_policy_id"]}
        )


def test_sec012_does_not_double_fire_with_sec009() -> None:
    # SEC009: RLS on, zero policies → fires.
    # SEC012: RLS on, ≥1 policy, all RESTRICTIVE → fires.
    # The two cases are disjoint by construction (zero vs ≥1
    # policies). A table can't trigger both — SEC012 must skip
    # the empty-policies case explicitly. Pin that.
    from pgrls.rules.sec009 import SEC009

    schema = Schema(tables=(_table("audit_log"),))  # zero policies
    sec009 = SEC009().check(schema, {})
    sec012 = SEC012().check(schema, {})
    assert len(sec009) == 1
    assert len(sec012) == 0


def test_sec012_does_not_double_fire_with_sec010() -> None:
    # SEC010 catches `USING (false)` deny-all. A table with one
    # PERMISSIVE policy that uses `false` is SEC010's case, not
    # SEC012's — SEC012 only fires when there's no PERMISSIVE
    # policy at all.
    schema = Schema(
        tables=(
            _table(
                "deny_via_false",
                policies=(
                    Policy(
                        name="never",
                        command="SELECT",
                        permissive=True,
                        roles=("authenticated",),
                        using_sql="false",
                        with_check_sql=None,
                    ),
                ),
            ),
        )
    )
    assert SEC012().check(schema, {}) == []
