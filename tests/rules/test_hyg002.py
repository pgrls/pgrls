"""Unit tests for HYG002 — placeholder-named policy."""
from __future__ import annotations

import pytest

from pgrls.model import Policy, Schema, Table
from pgrls.rules.hyg002 import HYG002


def _policy(name: str = "p", *, command: str = "SELECT") -> Policy:
    return Policy(
        name=name,
        command=command,  # type: ignore[arg-type]
        permissive=True,
        roles=("PUBLIC",),
        using_sql="true",
        with_check_sql=None,
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


@pytest.mark.parametrize(
    "name",
    [
        "todo",
        "fixme",
        "wip",
        "tmp",
        "temp",
        "hack",
        "xxx",
        "draft",
        "debug",
        "todo_filter",
        "fixme_owner",
        "TmpReadAll",  # case-insensitive match
        "wip-policy",  # word-boundary inside identifier
        "PLACEHOLDER",
        # SCREAMING_SNAKE — the SCREAMING_SNAKE branch of the
        # tokenizer requires `_` in the boundary lookahead;
        # without it `WIP_POLICY` was tokenized as ['wi','policy']
        # and the rule silently missed every screaming case.
        "WIP_POLICY",
        "TODO_OWNER",
        "FIXME_LATER",
    ],
)
def test_hyg002_fires_on_placeholder_words(name: str) -> None:
    schema = _wrap(_policy(name=name))
    violations = HYG002().check(schema, {})
    assert len(violations) == 1, f"Expected violation on {name!r}"
    assert violations[0].rule_id == "HYG002"
    assert violations[0].severity == "warning"


@pytest.mark.parametrize(
    "name",
    [
        "tenant_isolation",
        "owner_read",
        "select_own",
        "admin_only_read",
        "team_member_visibility",
        "p",  # short but not a placeholder word
        "stop",  # contains "top" but not a flagged token
    ],
)
def test_hyg002_silent_on_clean_names(name: str) -> None:
    schema = _wrap(_policy(name=name))
    assert HYG002().check(schema, {}) == []


def test_hyg002_silent_when_no_policies() -> None:
    schema = Schema(
        tables=(
            Table(
                schema="public",
                name="t",
                rls_enabled=True,
                force_rls=True,
                policies=(),
                columns=("id",),
            ),
        )
    )
    assert HYG002().check(schema, {}) == []


def test_hyg002_allowlist_exempts_qualified_policy_id() -> None:
    schema = _wrap(_policy(name="todo_keep_me"))
    options = {"allowlist": ["public.t.todo_keep_me"]}
    assert HYG002().check(schema, options) == []


def test_hyg002_custom_words_replaces_default() -> None:
    # Override convention matches PERF001 / SEC004: provided list
    # REPLACES the default. This is intentional — a custom-word
    # config means the user knows their full vocabulary.
    schema = _wrap(_policy(name="todo_filter"))
    # Default config: fires.
    assert len(HYG002().check(schema, {})) == 1
    # Custom config that does NOT include "todo": silent.
    out = HYG002().check(schema, {"placeholder_words": ["scratch"]})
    assert out == []
    # Custom config that DOES include the word: fires again.
    schema2 = _wrap(_policy(name="scratch_pad"))
    assert len(
        HYG002().check(schema2, {"placeholder_words": ["scratch"]})
    ) == 1


def test_hyg002_bad_allowlist_type_raises_clearly() -> None:
    schema = _wrap(_policy(name="todo"))
    with pytest.raises(TypeError, match="allowlist"):
        HYG002().check(schema, {"allowlist": "public.t.todo"})  # type: ignore[dict-item]


def test_hyg002_bad_placeholder_words_type_raises_clearly() -> None:
    schema = _wrap(_policy(name="todo"))
    with pytest.raises(TypeError, match="placeholder_words"):
        HYG002().check(schema, {"placeholder_words": "todo"})  # type: ignore[dict-item]


def test_hyg002_fires_on_each_offending_policy_independently() -> None:
    schema = Schema(
        tables=(
            Table(
                schema="public",
                name="t",
                rls_enabled=True,
                force_rls=True,
                columns=("id",),
                policies=(
                    _policy(name="todo_a"),
                    _policy(name="real_owner"),
                    _policy(name="wip_b"),
                ),
            ),
        )
    )
    locations = sorted(v.location for v in HYG002().check(schema, {}))
    assert locations == ["public.t.todo_a", "public.t.wip_b"]


def test_hyg002_metadata_present() -> None:
    rule = HYG002()
    assert rule.id == "HYG002"
    assert rule.severity == "warning"
    assert rule.title
