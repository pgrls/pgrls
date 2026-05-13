"""Unit tests for SEC013 — trigger on RLS-protected table can bypass policies."""
from __future__ import annotations

import pytest

from pgrls.model import Policy, Schema, Table, Trigger
from pgrls.rules.sec013 import SEC013


def _trigger(
    name: str = "tg",
    *,
    schema: str = "public",
    function_schema: str = "public",
    function_name: str = "trg_fn",
    event: str = "INSERT",
    timing: str = "BEFORE",
    enabled: bool = True,
) -> Trigger:
    return Trigger(
        schema=schema,
        name=name,
        function_schema=function_schema,
        function_name=function_name,
        event=event,
        timing=timing,
        enabled=enabled,
    )


def _table(
    name: str,
    *,
    rls: bool = True,
    schema: str = "public",
    triggers: tuple[Trigger, ...] = (),
    policies: tuple[Policy, ...] = (),
) -> Table:
    # SEC013 only inspects rls_enabled. Mirror force_rls so SEC002
    # isn't a confound for any cross-rule test that imports this
    # helper through copy/paste.
    return Table(
        schema=schema,
        name=name,
        rls_enabled=rls,
        force_rls=rls,
        policies=policies,
        triggers=triggers,
    )


def test_sec013_fires_on_enabled_trigger_for_rls_enabled_table() -> None:
    schema = Schema(
        tables=(
            _table(
                "invoices",
                triggers=(
                    _trigger(
                        "audit_insert",
                        function_schema="audit",
                        function_name="log_change",
                    ),
                ),
            ),
        )
    )
    [v] = SEC013().check(schema, {})
    assert v.rule_id == "SEC013"
    assert v.severity == "warning"
    assert v.location == "public.invoices.audit_insert"
    # Message mentions the trigger function so the operator knows
    # what code to audit.
    assert "audit.log_change" in v.message
    assert "BEFORE" in v.message
    assert "INSERT" in v.message
    assert "owner" in v.message.lower()  # bypass explanation


def test_sec013_silent_when_rls_disabled() -> None:
    # SEC001's territory. Triggers on RLS-off tables aren't bypassing
    # anything because the policies don't apply.
    schema = Schema(
        tables=(
            _table(
                "events",
                rls=False,
                triggers=(_trigger("audit_insert"),),
            ),
        )
    )
    assert SEC013().check(schema, {}) == []


def test_sec013_silent_when_no_triggers() -> None:
    schema = Schema(tables=(_table("invoices"),))
    assert SEC013().check(schema, {}) == []


def test_sec013_skips_disabled_triggers() -> None:
    # `pg_trigger.tgenabled = 'D'` triggers can't fire under any
    # session_replication_role; they're still in the snapshot so a
    # re-enable surfaces as a diff, but they're not an active
    # bypass right now.
    schema = Schema(
        tables=(
            _table(
                "invoices",
                triggers=(
                    _trigger("audit_insert", enabled=False),
                    _trigger("audit_update", enabled=True),
                ),
            ),
        )
    )
    [v] = SEC013().check(schema, {})
    assert v.location == "public.invoices.audit_update"


def test_sec013_fires_per_trigger_per_table_independently() -> None:
    # Two tables, each with two enabled triggers — four violations
    # total, in Schema.tables order then per-table trigger order.
    schema = Schema(
        tables=(
            _table(
                "invoices",
                triggers=(
                    _trigger("a"),
                    _trigger("b"),
                ),
            ),
            _table(
                "orders",
                triggers=(
                    _trigger("c"),
                    _trigger("d"),
                ),
            ),
        )
    )
    locs = [v.location for v in SEC013().check(schema, {})]
    assert locs == [
        "public.invoices.a",
        "public.invoices.b",
        "public.orders.c",
        "public.orders.d",
    ]


def test_sec013_message_includes_timing_and_event() -> None:
    # Different timing/event combinations surface verbatim in the
    # message so the operator can reproduce the trigger context
    # without needing a separate \\dy in psql.
    schema = Schema(
        tables=(
            _table(
                "invoices",
                triggers=(
                    _trigger(
                        "sync_state",
                        timing="AFTER",
                        event="INSERT OR UPDATE",
                    ),
                ),
            ),
        )
    )
    [v] = SEC013().check(schema, {})
    assert "AFTER" in v.message
    assert "INSERT OR UPDATE" in v.message


def test_sec013_message_handles_instead_of_trigger() -> None:
    schema = Schema(
        tables=(
            _table(
                "invoices_writable",
                triggers=(
                    _trigger(
                        "route_to_base",
                        timing="INSTEAD OF",
                        event="UPDATE",
                    ),
                ),
            ),
        )
    )
    [v] = SEC013().check(schema, {})
    assert "INSTEAD OF" in v.message


def test_sec013_allowlist_silences_qualified_trigger_id() -> None:
    schema = Schema(
        tables=(
            _table(
                "invoices",
                triggers=(
                    _trigger("audit_insert"),
                    _trigger("denorm_amount"),
                ),
            ),
        )
    )
    options = {"allowlist": ["public.invoices.audit_insert"]}
    locs = [v.location for v in SEC013().check(schema, options)]
    # Only the un-allowlisted trigger remains.
    assert locs == ["public.invoices.denorm_amount"]


def test_sec013_allowlist_does_not_silence_same_named_trigger_on_other_table() -> None:
    # A trigger named `audit_insert` can exist on multiple tables
    # (Postgres scopes trigger names per table). Allowlisting one
    # must NOT silence the other — that's the whole reason SEC013
    # uses qualified `schema.table.trigger_name` allowlist keys
    # instead of bare names.
    schema = Schema(
        tables=(
            _table(
                "invoices",
                triggers=(_trigger("audit_insert"),),
            ),
            _table(
                "orders",
                triggers=(_trigger("audit_insert"),),
            ),
        )
    )
    options = {"allowlist": ["public.invoices.audit_insert"]}
    locs = [v.location for v in SEC013().check(schema, options)]
    assert locs == ["public.orders.audit_insert"]


def test_sec013_bad_allowlist_type_raises_clearly() -> None:
    schema = Schema(tables=())
    with pytest.raises(TypeError, match=r"\[lint\.rules\.SEC013\]"):
        SEC013().check(schema, {"allowlist": "not_a_list"})


def test_sec013_bad_allowlist_entry_shape_raises_clearly() -> None:
    # Two-part entries (table refs) aren't valid for SEC013's
    # policy-ID-shaped allowlist; the helper rejects them with the
    # rule_id in the error. SEC013 follows the same shape as
    # SEC003/SEC005/SEC006 et al. so its allowlist is unambiguous
    # across same-named triggers on different tables.
    schema = Schema(tables=())
    with pytest.raises(TypeError, match="SEC013"):
        SEC013().check(schema, {"allowlist": ["public.invoices"]})


def test_sec013_does_not_double_fire_with_sec001() -> None:
    # SEC001 fires on rls_enabled=False; SEC013 only fires on
    # rls_enabled=True. The two are disjoint by construction. Pin
    # that an RLS-off table with a trigger doesn't trip SEC013.
    schema = Schema(
        tables=(
            _table(
                "no_rls_with_trigger",
                rls=False,
                triggers=(_trigger("audit_insert"),),
            ),
        )
    )
    assert SEC013().check(schema, {}) == []


def test_sec013_message_mentions_audit_action() -> None:
    # The rule message is intentionally a prompt-to-audit (SEC013
    # can't read PL/pgSQL function bodies to prove leakage). The
    # message must direct the user to either audit the body or
    # allowlist the trigger ID — pin both halves so a future
    # message reword doesn't drop the actionability.
    schema = Schema(
        tables=(
            _table(
                "invoices",
                triggers=(_trigger("audit_insert"),),
            ),
        )
    )
    [v] = SEC013().check(schema, {})
    assert "audit" in v.message.lower()
    assert "allowlist" in v.message.lower()
    assert "SEC013" in v.message
