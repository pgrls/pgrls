"""Unit tests for SEC051 — Realtime-published table with RLS disabled.

SEC051 (warning) fires on a table that is a member of a Realtime publication
(default ``supabase_realtime``) and has RLS disabled — Realtime then broadcasts
its row changes to every subscriber without policy filtering. An RLS-enabled
member is filtered by Realtime per-policy and is not flagged; a table in only a
non-Realtime publication is not flagged.
"""
from __future__ import annotations

import pytest

from pgrls.model import Schema, Table
from pgrls.rules.sec051 import SEC051


def _table(
    *,
    name: str = "messages",
    schema: str = "public",
    rls_enabled: bool = False,
    in_publications: tuple[str, ...] = ("supabase_realtime",),
) -> Table:
    return Table(
        schema=schema,
        name=name,
        rls_enabled=rls_enabled,
        force_rls=False,
        policies=(),
        in_publications=in_publications,
    )


def _check(table: Table, options: dict | None = None) -> list:
    return SEC051().check(Schema(tables=(table,)), options or {})


# --- firing --------------------------------------------------------------


def test_fires_rls_off_in_realtime() -> None:
    [v] = _check(_table())
    assert v.rule_id == "SEC051"
    assert v.severity == "warning"
    assert v.location == "public.messages"
    assert "supabase_realtime" in v.message
    assert "broadcast" in v.message


def test_fires_even_when_also_in_other_publications() -> None:
    # Membership in a FOR ALL TABLES publication alongside supabase_realtime
    # still counts — the realtime channel is what matters.
    [v] = _check(_table(in_publications=("pub_all", "supabase_realtime")))
    assert v.location == "public.messages"


def test_message_lists_only_the_realtime_publication() -> None:
    [v] = _check(_table(in_publications=("pub_all", "supabase_realtime")))
    # The non-realtime pub_all is not named in the finding.
    assert "supabase_realtime" in v.message
    assert "pub_all" not in v.message


def test_fires_custom_publication_via_config() -> None:
    [v] = _check(
        _table(in_publications=("my_realtime",)),
        {"publications": ["my_realtime"]},
    )
    assert v.location == "public.messages"


# --- not firing ----------------------------------------------------------


def test_silent_rls_enabled() -> None:
    # RLS on → Realtime evaluates policies per change → filtered.
    assert _check(_table(rls_enabled=True)) == []


def test_silent_not_in_any_publication() -> None:
    assert _check(_table(in_publications=())) == []


def test_silent_only_in_non_realtime_publication() -> None:
    # In a FOR ALL TABLES publication but NOT the realtime one → not broadcast
    # to Realtime subscribers, so not flagged by default.
    assert _check(_table(in_publications=("pub_all", "logical_repl"))) == []


def test_silent_default_does_not_match_custom_publication() -> None:
    # The table is in "my_realtime" but the default set only watches
    # supabase_realtime → silent unless configured.
    assert _check(_table(in_publications=("my_realtime",))) == []


def test_silent_rls_on_even_if_in_custom_publication() -> None:
    assert (
        _check(
            _table(rls_enabled=True, in_publications=("my_realtime",)),
            {"publications": ["my_realtime"]},
        )
        == []
    )


# --- options + metadata --------------------------------------------------


def test_allowlist_suppresses() -> None:
    assert _check(_table(), {"allowlist": ["public.messages"]}) == []


def test_allowlist_honors_bare_table_name() -> None:
    # The shared parser accepts a bare table name; the rule must honor it (not
    # silently no-op), matching every other table-scoped rule.
    assert _check(_table(), {"allowlist": ["messages"]}) == []


def test_allowlist_bad_type_raises_typeerror() -> None:
    with pytest.raises(TypeError):
        _check(_table(), {"allowlist": "public.messages"})


def test_publications_bad_type_raises_typeerror() -> None:
    with pytest.raises(TypeError):
        _check(_table(), {"publications": "supabase_realtime"})


def test_only_the_rls_off_realtime_member_is_reported() -> None:
    schema = Schema(
        tables=(
            _table(name="open", rls_enabled=False),
            _table(name="secured", rls_enabled=True),
            _table(name="private", in_publications=()),
        )
    )
    vs = SEC051().check(schema, {})
    assert [v.location for v in vs] == ["public.open"]


def test_metadata() -> None:
    rule = SEC051()
    assert rule.id == "SEC051"
    assert rule.severity == "warning"
    assert rule.title
