"""Unit tests for `pgrls.rules._allowlist` shape validators.

These helpers exist to close a footgun: earlier versions had
every per-policy rule do its own `_parse_allowlist` that only
checked `isinstance(raw, list)` and silently accepted entries
with the wrong shape (e.g. unqualified `"users"` in a policy-ID
allowlist). The mismatch never matched any policy, never raised,
never warned — the user's exemption was silently ignored.
"""
from __future__ import annotations

import pytest

from pgrls.rules._allowlist import (
    parse_policy_id_allowlist,
    parse_qualified_table_allowlist,
    parse_table_ref_allowlist,
)


# --- parse_policy_id_allowlist ---------------------------------


def test_policy_id_allowlist_accepts_qualified_id() -> None:
    out = parse_policy_id_allowlist(
        "SEC003", {"allowlist": ["public.users.tenant_isolation"]}
    )
    assert out == {"public.users.tenant_isolation"}


def test_policy_id_allowlist_rejects_unqualified_table_name() -> None:
    # The original-finding case: copy-paste from SEC001 example
    # into SEC003 produces an entry like `users` that silently
    # never matches. Now it raises with a clear hint.
    with pytest.raises(TypeError, match="not a valid policy ID"):
        parse_policy_id_allowlist(
            "SEC003", {"allowlist": ["users"]}
        )


def test_policy_id_allowlist_rejects_table_only() -> None:
    with pytest.raises(TypeError, match="not a valid policy ID"):
        parse_policy_id_allowlist(
            "SEC003", {"allowlist": ["public.users"]}
        )


def test_policy_id_allowlist_accepts_more_than_three_dots_as_dotted_policy_name() -> None:
    # rsplit('.', 2) right-anchors the parse so a policy name
    # containing `.` is allowlistable. `a.b.c.d` resolves as
    # schema=a.b, table=c, policy=d would be ambiguous, but Postgres
    # never produces a `.` in nspname/relname (rejected at CREATE).
    # The user's responsibility is to ensure the entry matches the
    # `policy_id` string the rule actually emits; we accept the
    # rsplit and trust the introspection invariants.
    out = parse_policy_id_allowlist(
        "SEC003", {"allowlist": ["a.b.c.d"]}
    )
    assert out == {"a.b.c.d"}


def test_policy_id_allowlist_rejects_empty_part() -> None:
    # A double-dot like `public..policy` parses into 3 parts but
    # the middle one is empty — also invalid.
    with pytest.raises(TypeError, match="not a valid policy ID"):
        parse_policy_id_allowlist(
            "SEC003", {"allowlist": ["public..policy"]}
        )


def test_policy_id_allowlist_rule_id_in_message() -> None:
    # The error message names the rule_id so the user knows which
    # `[lint.rules.X]` section is at fault.
    try:
        parse_policy_id_allowlist(
            "PERF001", {"allowlist": ["bad"]}
        )
    except TypeError as exc:
        assert "PERF001" in str(exc)
        assert "bad" in str(exc)
    else:
        raise AssertionError("expected TypeError")


def test_policy_id_allowlist_rejects_non_list() -> None:
    with pytest.raises(TypeError, match="must be a list"):
        parse_policy_id_allowlist(
            "SEC003", {"allowlist": "public.users.p"}
        )


def test_policy_id_allowlist_rejects_non_str_item() -> None:
    with pytest.raises(TypeError, match="must be a list"):
        parse_policy_id_allowlist(
            "SEC003", {"allowlist": ["public.users.p", 42]}
        )


def test_policy_id_allowlist_empty_list_is_fine() -> None:
    out = parse_policy_id_allowlist("SEC003", {"allowlist": []})
    assert out == set()


def test_policy_id_allowlist_missing_key_returns_empty_set() -> None:
    out = parse_policy_id_allowlist("SEC003", {})
    assert out == set()


def test_policy_id_allowlist_accepts_dot_in_policy_name() -> None:
    # Policy names CAN contain `.` — Postgres allows `"weird.name"`.
    # Right-anchoring the split (rsplit('.', 2)) lets the user
    # allowlist such a finding. Without this, the rule would fire
    # forever because the validator rejected the only entry that
    # could match.
    out = parse_policy_id_allowlist(
        "SEC003", {"allowlist": ["public.users.weird.name"]}
    )
    assert out == {"public.users.weird.name"}


def test_policy_id_allowlist_still_rejects_too_few_parts() -> None:
    # rsplit doesn't loosen the "must have schema and table" check.
    # 2-part `users.weird` is still invalid.
    with pytest.raises(TypeError, match="not a valid policy ID"):
        parse_policy_id_allowlist(
            "SEC003", {"allowlist": ["users.weird"]}
        )


# --- parse_table_ref_allowlist ---------------------------------


def test_table_ref_allowlist_accepts_unqualified() -> None:
    out = parse_table_ref_allowlist(
        "SEC001", {"allowlist": ["users"]}
    )
    assert out == {"users"}


def test_table_ref_allowlist_accepts_qualified() -> None:
    out = parse_table_ref_allowlist(
        "SEC001", {"allowlist": ["public.users"]}
    )
    assert out == {"public.users"}


def test_table_ref_allowlist_rejects_three_parts() -> None:
    # `schema.table.policy` is a policy ID, not a table ref —
    # users who paste this into SEC001 should hear about it.
    with pytest.raises(TypeError, match="not a valid table reference"):
        parse_table_ref_allowlist(
            "SEC001", {"allowlist": ["public.users.tenant_isolation"]}
        )


def test_table_ref_allowlist_rejects_empty_part() -> None:
    with pytest.raises(TypeError, match="not a valid table reference"):
        parse_table_ref_allowlist("SEC001", {"allowlist": [".users"]})


# --- parse_qualified_table_allowlist ---------------------------


def test_qualified_table_allowlist_accepts_qualified() -> None:
    out = parse_qualified_table_allowlist(
        "SEC007", {"allowlist": ["public.users"]}
    )
    assert out == {"public.users"}


def test_qualified_table_allowlist_rejects_unqualified() -> None:
    with pytest.raises(TypeError, match="not a valid qualified table ID"):
        parse_qualified_table_allowlist(
            "SEC007", {"allowlist": ["users"]}
        )


def test_qualified_table_allowlist_rejects_three_parts() -> None:
    with pytest.raises(TypeError, match="not a valid qualified table ID"):
        parse_qualified_table_allowlist(
            "SEC007", {"allowlist": ["public.users.policy"]}
        )
