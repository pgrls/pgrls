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
        "tmp",
        "hack",
        "xxx",
        "debug",
        "todo_filter",
        "fixme_owner",
        "TmpReadAll",  # case-insensitive match
        "tmp-policy",  # word-boundary inside identifier
        "PLACEHOLDER",
        # SCREAMING_SNAKE — the SCREAMING_SNAKE branch of the
        # tokenizer requires `_` in the boundary lookahead;
        # without it `TMP_POLICY` was tokenized as `['tm','policy']`
        # and the rule silently missed every screaming case.
        "TMP_POLICY",
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
        # `temp`, `draft`, `wip` are real domain words; the default
        # vocabulary deliberately excludes them. Each of these
        # names is plausible in a real schema and HYG002 must not
        # false-fire.
        "temp_humidity_sensor_policy",  # IoT temperature, not "temporary"
        "draft_visible_to_author",  # CMS publish state
        "wip_orders_visibility",  # WIP = "work in process" inventory
        "draft",  # domain word, not placeholder
        "wip",
        "temp",
    ],
)
def test_hyg002_silent_on_clean_names(name: str) -> None:
    schema = _wrap(_policy(name=name))
    assert HYG002().check(schema, {}) == []


def test_hyg002_default_vocabulary_excludes_overloaded_domain_words() -> None:
    # Pin the explicit vocabulary so a future PR adding `temp`/
    # `draft`/`wip` back to the default list (a tempting "be
    # more thorough" change) trips this test and re-surfaces the
    # false-positive risk in code review.
    from pgrls.rules.hyg002 import _DEFAULT_PLACEHOLDER_WORDS

    excluded = {"temp", "draft", "wip"}
    overlap = excluded & set(_DEFAULT_PLACEHOLDER_WORDS)
    assert overlap == set(), (
        f"HYG002 default vocabulary must exclude overloaded domain "
        f"words but contains: {sorted(overlap)}. These words collide "
        "with legitimate uses (temperature sensors, CMS draft "
        "states, work-in-process inventory)."
    )


def test_hyg002_user_can_opt_into_broader_vocabulary() -> None:
    # Defaults exclude `wip` to avoid false positives on real WIP
    # inventory schemas. A user whose codebase wants the broader
    # scaffolding-detection set opts back in via
    # `placeholder_words`. Pin that the override re-enables them.
    schema = _wrap(_policy(name="wip_orders_visibility"))
    assert HYG002().check(schema, {}) == []
    expanded = ["todo", "fixme", "tmp", "wip", "temp", "draft"]
    out = HYG002().check(schema, {"placeholder_words": expanded})
    assert len(out) == 1


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
                    _policy(name="tmp_b"),
                ),
            ),
        )
    )
    locations = sorted(v.location for v in HYG002().check(schema, {}))
    assert locations == ["public.t.tmp_b", "public.t.todo_a"]


def test_hyg002_metadata_present() -> None:
    rule = HYG002()
    assert rule.id == "HYG002"
    assert rule.severity == "warning"
    assert rule.title


def test_hyg002_message_mentions_only_default_vocabulary_examples() -> None:
    # The violation message gives example placeholder words. They
    # must come from the actual default vocabulary — Round 26 caught
    # the message naming `wip`, which Round 18 had removed from the
    # default set. A message advertising example matches the rule
    # itself will never produce on default config is a credibility
    # leak.
    from pgrls.rules.hyg002 import _DEFAULT_PLACEHOLDER_WORDS

    schema = _wrap(_policy(name="todo_thing"))
    msg = HYG002().check(schema, {})[0].message
    # No removed-from-defaults words.
    for stale in ("wip", "draft", "temp"):
        assert stale not in msg, (
            f"HYG002 violation message contains {stale!r} which is "
            "no longer in the default vocabulary."
        )
    # At least one default vocabulary word appears as an example.
    assert any(
        f"`{word}`" in msg for word in _DEFAULT_PLACEHOLDER_WORDS
    )
