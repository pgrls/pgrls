"""Tests for pgrls.diff.ast_compare.compare_predicates.

Tests cover identity/parse-failure paths, AND patterns, OR patterns,
and requires-review cases. Each test pins exactly one return value.
"""
from __future__ import annotations

from pgrls.diff.ast_compare import compare_predicates


# ---------------------------------------------------------------------------
# Identity / parse-failure paths
# ---------------------------------------------------------------------------


def test_both_none_returns_unchanged():
    assert compare_predicates(None, None) == "unchanged"


def test_both_empty_returns_unchanged():
    assert compare_predicates("", "") == "unchanged"


def test_one_none_base_returns_requires_review():
    assert compare_predicates(None, "a = 1") == "requires_review"


def test_one_none_head_returns_requires_review():
    assert compare_predicates("a = 1", None) == "requires_review"


def test_parse_failure_returns_requires_review():
    # Deliberately malformed SQL that pglast cannot parse.
    assert compare_predicates("WHERE :::", "a = 1") == "requires_review"


def test_whitespace_only_diff_returns_unchanged():
    assert compare_predicates("a = 1", "a   =   1") == "unchanged"


# ---------------------------------------------------------------------------
# AND patterns
# ---------------------------------------------------------------------------


def test_and_tightened_appended_clause():
    # base < head: head adds a new conjunct
    assert compare_predicates("a = 1", "a = 1 AND b = 2") == "tightened_and"


def test_and_tightened_prepended_clause():
    # set comparison is order-independent — prepended clause still tightened
    assert compare_predicates("a = 1", "b = 2 AND a = 1") == "tightened_and"


def test_and_loosened_drop():
    # head is a proper subset of base
    assert compare_predicates("a = 1 AND b = 2", "a = 1") == "loosened_and_drop"


def test_and_chain_extended():
    # 2-clause base grows to 3-clause head
    assert compare_predicates("a = 1 AND b = 2", "a = 1 AND b = 2 AND c = 3") == "tightened_and"


def test_and_chain_shrunk():
    # 3-clause base shrinks to 2-clause head
    assert compare_predicates("a = 1 AND b = 2 AND c = 3", "a = 1 AND b = 2") == "loosened_and_drop"


# ---------------------------------------------------------------------------
# OR patterns
# ---------------------------------------------------------------------------


def test_or_loosened_appended_disjunct():
    # head adds a new disjunct — more rows pass, so policy loosened
    assert compare_predicates("a = 1", "a = 1 OR b = 2") == "loosened_or"


def test_or_tightened_drop():
    # head is proper subset of base disjuncts — fewer rows pass, tightened
    assert compare_predicates("a = 1 OR b = 2", "a = 1") == "tightened_or_drop"


def test_or_chain_extended():
    # 2-disjunct base grows to 3-disjunct head
    assert compare_predicates("a = 1 OR b = 2", "a = 1 OR b = 2 OR c = 3") == "loosened_or"


# ---------------------------------------------------------------------------
# Requires-review cases
# ---------------------------------------------------------------------------


def test_operator_change_returns_requires_review():
    assert compare_predicates("a = 1", "a > 1") == "requires_review"


def test_function_arg_change_returns_requires_review():
    assert compare_predicates("current_user = 'alice'", "current_user = 'bob'") == "requires_review"


def test_two_unrelated_predicates_return_requires_review():
    assert compare_predicates("a = 1", "b = 2") == "requires_review"


def test_and_to_or_returns_requires_review():
    assert compare_predicates("a = 1 AND b = 2", "a = 1 OR b = 2") == "requires_review"


def test_drop_two_clauses_returns_requires_review():
    # Only single-clause add/drop is detected; dropping two falls through
    assert compare_predicates("a = 1 AND b = 2 AND c = 3", "a = 1") == "requires_review"


def test_or_drop_two_disjuncts_returns_requires_review():
    # Mirror of test_drop_two_clauses_returns_requires_review for OR.
    assert (
        compare_predicates("a = 1 OR b = 2 OR c = 3", "a = 1")
        == "requires_review"
    )


# ---------------------------------------------------------------------------
# Parse-failure variants (M-1 from Task 8 review): ensure all three failure
# locations route to requires_review, not just base-only.
# ---------------------------------------------------------------------------


def test_parse_failure_on_head_returns_requires_review():
    assert compare_predicates("a = 1", "WHERE :::") == "requires_review"


def test_parse_failure_on_both_returns_requires_review():
    assert compare_predicates("WHERE :::", "WHERE :::") == "requires_review"


# ---------------------------------------------------------------------------
# Canonicalization equivalences (M-5): exercise more shapes that should
# survive RawStream normalization as "unchanged" so a future RawStream
# regression surfaces here, not in production diffs.
# ---------------------------------------------------------------------------


def test_extra_outer_parens_returns_unchanged():
    # `(a = 1)` and `a = 1` parse to the same expression — the wrapper
    # parens are redundant, RawStream strips them.
    assert compare_predicates("(a = 1)", "a = 1") == "unchanged"


def test_outer_paren_wrap_around_and_chain_returns_unchanged():
    # Confirm RawStream also strips parens around a multi-conjunct chain.
    assert (
        compare_predicates("(a = 1 AND b = 2)", "a = 1 AND b = 2")
        == "unchanged"
    )


# ---------------------------------------------------------------------------
# Implicit-behavior pins (I-1, I-2 from Task 8 review): the set-based
# comparison and the "literal canonical equality" check together produce a
# few non-obvious classifications. Pin them as deliberate choices so a
# future refactor that switches to list-based / Counter-based comparison
# surfaces here rather than silently changing classifications.
# ---------------------------------------------------------------------------


def test_clause_reorder_returns_requires_review():
    # `a = 1 AND b = 2` and `b = 2 AND a = 1` are commutatively equal in
    # propositional logic, but RawStream preserves source ordering, so the
    # canonical strings differ and neither is a strict subset of the other.
    # v0.2 chooses the conservative classification: requires_review. This
    # test pins that choice — a future relaxation should remove this test
    # as part of the same change so the intent is visible in the diff.
    assert (
        compare_predicates("a = 1 AND b = 2", "b = 2 AND a = 1")
        == "requires_review"
    )


def test_duplicate_clause_dedup_then_add_returns_tightened_and():
    # `a = 1 AND a = 1` and `a = 1 AND a = 1 AND b = 2` deduplicate to
    # canonical sets {"a = 1"} and {"a = 1", "b = 2"}. Set delta is 1, so
    # the function returns tightened_and. This is *probably* still safe
    # (the head predicate is at least as restrictive as base), but the
    # detection is via deduplication, not via the spec's literal `P → P
    # AND Q` shape. Pin so a future Counter-based switch surfaces here.
    assert (
        compare_predicates(
            "a = 1 AND a = 1",
            "a = 1 AND a = 1 AND b = 2",
        )
        == "tightened_and"
    )


# ---------------------------------------------------------------------------
# location / clause kwargs (Task 9 extension): smoke test that the new kwargs
# are forwarded to parse_expr — identical SQL with kwargs should still return
# "unchanged" (i.e. kwargs don't alter the classification).
# ---------------------------------------------------------------------------


def test_location_and_clause_kwargs_do_not_alter_result():
    # Passing kwargs should not change the classification outcome.
    assert (
        compare_predicates(
            "a = 1",
            "a = 1 AND b = 2",
            location="public.mytable.mypolicy",
            clause="USING",
        )
        == "tightened_and"
    )


def test_location_and_clause_kwargs_unchanged():
    assert (
        compare_predicates(
            "a = 1",
            "a = 1",
            location="public.orders.tenant_isolation",
            clause="WITH CHECK",
        )
        == "unchanged"
    )
