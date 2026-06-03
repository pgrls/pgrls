"""Unit tests for ``pgrls.diff._z3_compare`` (Z3-backed predicate
implication, Phase 1).

These tests exercise the AST → Z3 translator and the implication
classifier on the supported subset (bool/int/text + comparisons,
boolean connectives, NULL tests, IN-of-literals). Anything outside
the supported subset must return None from the translator and fall
through to ``requires_review`` at the ``compare_predicates`` boundary.
"""
from __future__ import annotations

import pytest

# Skip the whole module if z3 isn't installed — Phase 1's testing
# matrix uses `pgrls[diff-z3]` (which pulls in z3-solver), so a
# missing z3 means a wider environment problem; better to surface
# that as a skip than to crash module-load.
z3_solver = pytest.importorskip("z3")

from pgrls.ast_utils import parse_expr  # noqa: E402
from pgrls.diff._z3_compare import (  # noqa: E402
    Z3_AVAILABLE,
    anon_read_counterexample,
    classify_via_z3,
    counterexample,
)


def _classify(base_sql: str, head_sql: str) -> object:
    """Helper: parse + classify, surfacing parse failures clearly."""
    base = parse_expr(base_sql)
    head = parse_expr(head_sql)
    assert base is not None and head is not None, (
        "test predicate should parse"
    )
    return classify_via_z3(base, head)


def test_z3_is_available_when_installed():
    # Sanity check: if `pgrls[diff-z3]` is installed the module's
    # `Z3_AVAILABLE` flag flips True. The pytest `importorskip` above
    # already gates the module on `import z3`, so this is belt+
    # suspenders.
    assert Z3_AVAILABLE is True


# ---------------------------------------------------------------------------
# Equivalence (both implications hold)
# ---------------------------------------------------------------------------


def test_identical_predicate_is_semantic_equivalent():
    assert _classify("a = 1", "a = 1") == "semantic_equivalent"


def test_and_reorder_is_semantic_equivalent():
    # Commutativity of AND.
    assert _classify("a = 1 AND b = 2", "b = 2 AND a = 1") == "semantic_equivalent"


def test_or_reorder_is_semantic_equivalent():
    # Commutativity of OR.
    assert _classify("a = 1 OR b = 2", "b = 2 OR a = 1") == "semantic_equivalent"


def test_de_morgan_law_is_semantic_equivalent():
    # NOT (a AND b) ⟺ (NOT a) OR (NOT b). Z3's Boolean reasoning
    # should prove both implications.
    assert (
        _classify("NOT (a AND b)", "(NOT a) OR (NOT b)") == "semantic_equivalent"
    )


# ---------------------------------------------------------------------------
# Tightening (head → base only)
# ---------------------------------------------------------------------------


def test_drop_or_disjunct_is_semantic_tightened():
    # `a=1 OR b=2 OR c=3` admits more rows than `a=1 OR b=2`.
    # Head is strictly stricter — semantic_tightened.
    assert (
        _classify("a = 1 OR b = 2 OR c = 3", "a = 1 OR b = 2")
        == "semantic_tightened"
    )


def test_add_and_clause_via_z3_is_semantic_tightened_or_falls_through():
    # `a=1` → `a=1 AND b=2`: head admits a strict subset (only rows
    # where a=1 AND b=2). The syntactic AND-tighten pattern catches
    # this BEFORE Z3 fires (returning "tightened_and"), so this
    # test is a sanity check that Z3 alone would also classify
    # correctly when called in isolation.
    assert _classify("a = 1", "a = 1 AND b = 2") == "semantic_tightened"


def test_int_range_intersection_is_semantic_tightened():
    # `x > 0` admits all positive ints; `x > 0 AND x < 10` admits
    # only positive ints below 10. Head is stricter.
    assert _classify("x > 0", "x > 0 AND x < 10") == "semantic_tightened"


# ---------------------------------------------------------------------------
# Loosening (base → head only)
# ---------------------------------------------------------------------------


def test_add_or_disjunct_is_semantic_loosened():
    # Mirror of test_drop_or_disjunct: adding admits more rows.
    # The syntactic OR-loosen pattern catches single-disjunct adds;
    # Z3 catches the multi-disjunct case symmetrically.
    assert (
        _classify("a = 1", "a = 1 OR b = 2 OR c = 3")
        == "semantic_loosened"
    )


def test_and_to_or_is_semantic_loosened():
    # `a=1 AND b=2` requires both; `a=1 OR b=2` requires either.
    # OR is strictly looser than AND for the same operands.
    assert _classify("a = 1 AND b = 2", "a = 1 OR b = 2") == "semantic_loosened"


def test_int_range_widening_is_semantic_loosened():
    # `x > 5` ⊂ `x > 0` (every row satisfying x > 5 satisfies x > 0).
    # Head is the wider range — looser.
    assert _classify("x > 5", "x > 0") == "semantic_loosened"


# ---------------------------------------------------------------------------
# Incomparable (neither implication holds) → None → requires_review
# ---------------------------------------------------------------------------


def test_disjoint_predicates_are_incomparable():
    # `a = 1` and `b = 2`: neither implies the other (rows can satisfy
    # one but not the other). Z3 returns None.
    assert _classify("a = 1", "b = 2") is None


def test_partially_overlapping_ranges_are_incomparable():
    # `x > 0` and `x < 10`: rows can be in one set, the other set,
    # both, or neither. Neither set is a subset of the other.
    assert _classify("x > 0", "x < 10") is None


def test_different_columns_with_same_constant_are_incomparable():
    assert _classify("foo = 'a'", "bar = 'a'") is None


# ---------------------------------------------------------------------------
# IN list (literal RHS)
# ---------------------------------------------------------------------------


def test_in_list_subset_is_semantic_tightened():
    # `x IN (1,2,3,4)` admits more rows than `x IN (1,2)`.
    # Head is the smaller set — stricter.
    assert (
        _classify("x IN (1, 2, 3, 4)", "x IN (1, 2)")
        == "semantic_tightened"
    )


def test_in_list_superset_is_semantic_loosened():
    assert (
        _classify("x IN (1, 2)", "x IN (1, 2, 3, 4)")
        == "semantic_loosened"
    )


def test_in_list_equal_is_semantic_equivalent():
    # IN-list rendering may differ but semantically equal.
    assert _classify("x IN (1, 2, 3)", "x IN (3, 2, 1)") == "semantic_equivalent"


def test_in_list_string_subset_is_semantic_tightened():
    # IN-list with string literals — same logic, different sort.
    assert (
        _classify("role IN ('admin', 'user')", "role IN ('admin')")
        == "semantic_tightened"
    )


# ---------------------------------------------------------------------------
# NULL tests (opaque markers)
# ---------------------------------------------------------------------------


def test_is_null_with_added_predicate_is_semantic_tightened():
    # `col IS NULL` ⊃ `col IS NULL AND tenant = 'a'`. The added
    # AND-conjunct only restricts. NULL is treated as opaque so the
    # tenant-comparison and the IS NULL marker share the same column
    # variable per the translator's binding policy.
    assert (
        _classify("col IS NULL", "col IS NULL AND tenant = 'a'")
        == "semantic_tightened"
    )


def test_is_null_negated_is_incomparable_to_unrelated():
    # `IS NOT NULL` and an unrelated column comparison: neither
    # implies the other.
    assert _classify("col IS NOT NULL", "other = 'x'") is None


# ---------------------------------------------------------------------------
# Phase 3 — function calls (uninterpreted), COALESCE, CASE, BETWEEN
# ---------------------------------------------------------------------------


def test_identical_function_call_in_predicate_is_semantic_equivalent():
    # Phase 3: `current_setting(...)` is modeled as an opaque Z3
    # String constant keyed by canonical shape. Identical calls on
    # both sides reuse the same Z3 var, so the predicates are
    # equivalent. (Phase 1 returned None — see the v0.4.0
    # changelog entry; v0.4.1 reclassifies.)
    assert (
        _classify(
            "tenant_id = current_setting('app.tenant')",
            "tenant_id = current_setting('app.tenant')",
        )
        == "semantic_equivalent"
    )


def test_function_call_with_added_and_clause_is_semantic_tightened():
    # Both predicates reference `auth.uid()`; head adds an AND
    # clause. Z3 sees the same opaque var on both sides and proves
    # head → base. Head is stricter.
    assert (
        _classify(
            "user_id = auth.uid()",
            "user_id = auth.uid() AND deleted_at IS NULL",
        )
        == "semantic_tightened"
    )


def test_different_function_call_args_are_incomparable():
    # `current_setting('app.tenant')` and `current_setting('app.role')`
    # are different opaque vars — Z3 can't relate them.
    assert (
        _classify(
            "x = current_setting('app.tenant')",
            "x = current_setting('app.role')",
        )
        is None
    )


def test_between_is_translated_as_and_of_inequalities():
    # Phase 3: BETWEEN translates to `lo <= expr AND expr <= hi`,
    # so `x BETWEEN 1 AND 10` and `x >= 1 AND x <= 10` are
    # semantically equivalent.
    assert (
        _classify("x BETWEEN 1 AND 10", "x >= 1 AND x <= 10")
        == "semantic_equivalent"
    )


def test_between_widening_is_semantic_loosened():
    # `x BETWEEN 1 AND 5` is a strict subset of `x BETWEEN 1 AND 10`.
    # Head admits more rows.
    assert (
        _classify("x BETWEEN 1 AND 5", "x BETWEEN 1 AND 10")
        == "semantic_loosened"
    )


def test_not_between_is_negation_of_between():
    # `x NOT BETWEEN 1 AND 10` translates to `Not(1 <= x AND x <= 10)`,
    # equivalent to `x < 1 OR x > 10`.
    assert (
        _classify("x NOT BETWEEN 1 AND 10", "x < 1 OR x > 10")
        == "semantic_equivalent"
    )


def test_identical_coalesce_is_semantic_equivalent():
    # CoalesceExpr is treated as an opaque Z3 var keyed by canonical
    # shape. Identical COALESCE on both sides → same var → equivalent.
    assert (
        _classify(
            "COALESCE(role, 'guest') = 'admin'",
            "COALESCE(role, 'guest') = 'admin'",
        )
        == "semantic_equivalent"
    )


def test_identical_case_is_semantic_equivalent():
    # CaseExpr is treated as an opaque Z3 var keyed by canonical
    # shape. Identical CASE on both sides → same var → equivalent.
    assert (
        _classify(
            "CASE WHEN role = 'admin' THEN tenant ELSE 'none' END = 'tenant_a'",
            "CASE WHEN role = 'admin' THEN tenant ELSE 'none' END = 'tenant_a'",
        )
        == "semantic_equivalent"
    )


def test_coalesce_with_added_and_clause_is_semantic_tightened():
    # The opaque COALESCE var must be the same across base and head
    # for the AND-tightening to be detectable. Z3 sees them as the
    # same var → head → base holds → tightened.
    assert (
        _classify(
            "COALESCE(tenant, 'default') = 'foo'",
            "COALESCE(tenant, 'default') = 'foo' AND active = true",
        )
        == "semantic_tightened"
    )


# ---------------------------------------------------------------------------
# Unsupported AST nodes → None (translator aborts; caller falls through)
# ---------------------------------------------------------------------------


def test_typecast_to_text_of_string_literal_is_semantic_equivalent():
    # Phase 4: `'a'::text` is supported — text → String sort matches
    # the inner literal's String sort, so the cast is a no-op and
    # both sides reduce to the same Z3 expression.
    # (v0.4.0/v0.4.1 returned None.)
    assert (
        _classify("col = 'a'::text", "col = 'a'") == "semantic_equivalent"
    )


def test_typecast_to_int_of_int_literal_is_semantic_equivalent():
    # `5::int` matches the inner Integer's Int sort.
    assert (
        _classify("col = 5::int", "col = 5") == "semantic_equivalent"
    )


def test_typecast_sort_changing_uses_opaque_var():
    # `id::text` casts an Int column to text. Phase 4 models the
    # cast as opaque under the target sort. Two predicates with the
    # same `id::text = 'a'` shape collapse to the same opaque Z3
    # variable on both sides → semantic_equivalent.
    assert (
        _classify("id::text = 'a'", "id::text = 'a'") == "semantic_equivalent"
    )


def test_subquery_in_is_unsupported_returns_none():
    # `IN (SELECT ...)` is AEXPR_IN_SUB-style; not supported in any
    # phase (the subquery scoping is out of scope for the predicate-
    # implication contract).
    assert (
        _classify(
            "col IN (SELECT id FROM other)",
            "col IN (SELECT id FROM other)",
        )
        is None
    )


def test_arithmetic_in_predicate_is_semantic_equivalent():
    # Phase 4: `col + 1 > 0` is equivalent to `col > -1` (Z3 proves
    # both implications). v0.4.0/v0.4.1 returned None because the
    # arithmetic translator wasn't implemented.
    assert (
        _classify("col + 1 > 0", "col > -1") == "semantic_equivalent"
    )


def test_arithmetic_widening_constant_is_semantic_loosened():
    # `col + 5 > 0` (i.e. col > -5) is strictly looser than
    # `col + 1 > 0` (col > -1).
    assert (
        _classify("col + 1 > 0", "col + 5 > 0") == "semantic_loosened"
    )


def test_arithmetic_subtraction_is_supported():
    # `col - 3 > 0` ⟺ `col > 3`.
    assert (
        _classify("col - 3 > 0", "col > 3") == "semantic_equivalent"
    )


# ---------------------------------------------------------------------------
# Mixed-shape: predicates that the syntactic patterns CAN'T decide but
# Z3 CAN. These are the v0.4 marquee — REQUIRES_REVIEW used to be the
# answer; now we get a real classification.
# ---------------------------------------------------------------------------


def test_drop_multiple_and_clauses_via_z3_is_semantic_loosened():
    # The syntactic loosened_and_drop pattern only catches dropping
    # one clause. Dropping two falls through to Z3.
    assert (
        _classify("a = 1 AND b = 2 AND c = 3", "a = 1")
        == "semantic_loosened"
    )


def test_drop_multiple_or_disjuncts_via_z3_is_semantic_tightened():
    # Symmetric: syntactic tightened_or_drop only catches single-
    # disjunct drops; Z3 catches multi-drop.
    assert (
        _classify("a = 1 OR b = 2 OR c = 3", "a = 1")
        == "semantic_tightened"
    )


# ---------------------------------------------------------------------------
# Soundness pin: type conflict aborts the translator (returns None
# rather than producing a misleading classification).
# ---------------------------------------------------------------------------


def test_type_conflict_on_column_returns_none():
    # `col = 5` then `col = 'foo'` would bind `col` to two different
    # Z3 sorts (Int and String). The translator refuses and returns
    # None rather than misclassifying.
    assert _classify("col = 5", "col = 'foo'") is None


# ---------------------------------------------------------------------------
# Counterexample emitter (H1) — assert the PROPERTY that the reported
# row genuinely satisfies `head ∧ ¬base`, never a nondeterministic exact
# value. The Z3 model is not stable across solver versions; the only
# stable contract is "this row leaks".
# ---------------------------------------------------------------------------


def _counterexample(base_sql: str, head_sql: str):
    base = parse_expr(base_sql)
    head = parse_expr(head_sql)
    assert base is not None and head is not None
    return counterexample(base, head)


def _row_satisfies_head_not_base(base_sql, head_sql, row) -> bool:
    """Re-feed the reported row through the translator and check that
    pinning every reported column to its value keeps ``head ∧ ¬base``
    SAT — i.e. the row really is a member of ``head ∖ base``.

    The pin var is fetched from the freshly-rebuilt context's
    ``_vars`` so it is byte-identical to the variable already inside
    ``h`` / ``b`` (same name + sort); no sort is guessed from the
    Python value (which would mis-handle ``bool`` vs ``int``).
    """
    from pgrls.diff._z3_compare import _Context, _to_z3

    ctx = _Context()
    base = parse_expr(base_sql)
    head = parse_expr(head_sql)
    b = _to_z3(base, ctx)
    h = _to_z3(head, ctx)
    s = z3_solver.Solver()
    s.add(z3_solver.And(h, z3_solver.Not(b)))
    for key, val in row.items():
        var = ctx.column(key, _py_value_sort(val))
        assert var is not None, f"reported column {key!r} not bindable"
        s.add(var == val)
    return s.check() == z3_solver.sat


def _py_value_sort(val):
    """Z3 sort for a Python value. `bool` BEFORE `int` — `isinstance(
    True, int)` is True, so an Int dispatch would mis-bind a Bool."""
    if isinstance(val, bool):
        return z3_solver.BoolSort()
    if isinstance(val, int):
        return z3_solver.IntSort()
    if isinstance(val, float):
        return z3_solver.RealSort()
    return z3_solver.StringSort()


def test_counterexample_present_on_or_loosen():
    base, head = "tenant_id = 1", "tenant_id = 1 OR tenant_id = 2"
    # Tie the counterexample to the verdict it explains.
    assert _classify(base, head) == "semantic_loosened"
    cx = _counterexample(base, head)
    assert cx is not None
    # Every key is a REAL column — no synthetic vars leaked.
    assert all(not k.startswith(("_isnull__", "_opaque__")) for k in cx)
    # SOUNDNESS: the row genuinely satisfies head ∧ ¬base.
    assert _row_satisfies_head_not_base(base, head, cx)


def test_counterexample_present_on_range_loosen():
    # base `x > 5` → head `x > 0`: every model has 0 < x ≤ 5; we assert
    # the property, never the exact int Z3 happens to pick.
    base, head = "x > 5", "x > 0"
    assert _classify(base, head) == "semantic_loosened"
    cx = _counterexample(base, head)
    assert cx is not None
    assert _row_satisfies_head_not_base(base, head, cx)


def test_counterexample_string_column():
    base, head = "name = 'a'", "name = 'a' OR name = 'b'"
    assert _classify(base, head) == "semantic_loosened"
    cx = _counterexample(base, head)
    assert cx is not None
    assert _row_satisfies_head_not_base(base, head, cx)


def test_no_counterexample_when_equivalent():
    # Semantically equal predicates: head ∧ ¬base is UNSAT.
    assert _classify("a = 1", "1 = a") == "semantic_equivalent"
    assert _counterexample("a = 1", "1 = a") is None


def test_no_counterexample_when_tightened():
    # Head stricter than base: head ∧ ¬base UNSAT.
    assert _classify("a = 1 OR a = 2", "a = 1") == "semantic_tightened"
    assert _counterexample("a = 1 OR a = 2", "a = 1") is None


def test_no_counterexample_when_null_dependent_loosen():
    # SOUNDNESS GATE (the critique's fatal case): base `active = true`,
    # head `active = true OR deleted_at IS NULL` classifies loosened,
    # but the leak hinges on `deleted_at IS NULL` — a synthetic NULL
    # marker, not a column value. The real-column projection
    # `{active: False}` does NOT leak on its own, so the emitter must
    # return None (degrade to label-only) rather than a non-leaking row.
    assert _classify("active = true", "active = true OR deleted_at IS NULL") == (
        "semantic_loosened"
    )
    assert _counterexample(
        "active = true", "active = true OR deleted_at IS NULL"
    ) is None


def test_no_counterexample_when_opaque_only_loosen():
    # SOUNDNESS GATE: GUC / function-based tenancy — the single most
    # common real RLS shape. base `current_setting('app.t') = 'a'`,
    # head adds `OR current_setting('app.t') = 'b'`. The leak requires
    # the GUC to equal 'b' (an opaque var), which no column row can
    # express; the real-column projection is empty and insufficient,
    # so the emitter returns None.
    base = "current_setting('app.t') = 'a'"
    head = "current_setting('app.t') = 'a' OR current_setting('app.t') = 'b'"
    assert _classify(base, head) == "semantic_loosened"
    assert _counterexample(base, head) is None


def test_counterexample_for_loosen_via_public_helper():
    # Exercises the re-parse public helper `counterexample_for` (the
    # entry point policies.py actually calls) end-to-end.
    from pgrls.diff.ast_compare import counterexample_for

    cx = counterexample_for("tenant_id = 1", "tenant_id = 1 OR tenant_id = 2")
    assert cx is not None
    assert all(not k.startswith(("_isnull__", "_opaque__")) for k in cx)
    assert _row_satisfies_head_not_base(
        "tenant_id = 1", "tenant_id = 1 OR tenant_id = 2", cx
    )


# ---------------------------------------------------------------------------
# H2 (SEC038) — `anon_read_counterexample`: the Kleene 3VL anonymous-read
# validity prover. Additive; the 2-valued path above is untouched.
#
# Contract: returns a dict (a proof artifact) iff the USING predicate is
# anon-VALID — TRUE for every row under an anonymous session (every auth
# function NULL) — else None. We assert the dict/None *shape*, never exact
# column values (the validity criterion yields an empty model, but the
# stable contract is "fires" vs "doesn't"), mirroring the H1 discipline.
# ---------------------------------------------------------------------------

_OWNER = "owner_id = '00000000-0000-0000-0000-000000000001'::uuid"


def _anon(sql: str) -> object:
    node = parse_expr(sql)
    assert node is not None, "test predicate should parse"
    return anon_read_counterexample(node)


# --- VALID (fires): a dict is returned --------------------------------------


def test_anon_fires_on_not_wrapped_is_not_null() -> None:
    # P1 — the NOT-wrapped variant SEC004 misses.
    assert _anon(f"NOT ((SELECT auth.uid()) IS NOT NULL) OR {_OWNER}") is not None


def test_anon_fires_on_is_null_or_true() -> None:
    # P2.
    assert _anon("(SELECT auth.uid()) IS NULL OR true") is not None


def test_anon_fires_on_bool_cast_is_null() -> None:
    # P4 — the `::bool`-cast variant; the TypeCast wraps a _TV inner
    # (amendment #4). Asserted at the encoder level, not just the rule.
    assert _anon(f"((SELECT auth.uid()) IS NULL)::bool OR {_OWNER}") is not None


def test_anon_fires_on_unknown_type_cast_of_auth_call_is_null() -> None:
    # R11 #3: a cast of an anon-null auth call to an UNKNOWN target type
    # (jsonb/inet/date/… — the common Supabase shapes) must keep the
    # null-flag carry-through (`cast of NULL is NULL`), so the inverted
    # `auth.uid()::jsonb IS NULL OR <owner>` proves valid and fires. This
    # exercises the _anon_typecast unknown-target-type branch — the one
    # the `::bool` test does not reach.
    for cast_type in ("jsonb", "inet", "date", "timestamp"):
        sql = f"((SELECT auth.uid())::{cast_type}) IS NULL OR {_OWNER}"
        assert _anon(sql) is not None, cast_type


def test_anon_clean_on_unknown_type_cast_tenant_predicate() -> None:
    # The mirror: a tenant/owner predicate whose auth value is cast to an
    # unknown type is Kleene U under anon (col = NULL), not valid → no
    # fire. Guards the carry-through against being mis-encoded as a fresh
    # non-null value (which would turn a real inverted-auth leak into a
    # MISS after a refactor).
    assert _anon(
        "owner_id = ((SELECT current_setting('app.o', true))::jsonb)"
    ) is None


def test_anon_fires_on_corpus_inverted_auth_shape() -> None:
    # P3 / sec004-inverted-auth.
    assert _anon(
        "(SELECT current_setting('app.user_id', true))::uuid IS NULL "
        "OR owner_id = (SELECT auth.uid())"
    ) is not None


def test_anon_fires_on_multiple_auth_is_null() -> None:
    # P6.
    assert _anon(
        "(SELECT auth.role()) IS NULL OR (SELECT auth.uid()) IS NULL "
        "OR tenant_id = (SELECT current_setting('app.t', true)::uuid)"
    ) is not None


def test_anon_fires_on_bare_sqlvaluefunction_when_configured() -> None:
    # `current_user` / `session_user` written WITHOUT parens parse as
    # SQLValueFunction nodes — a distinct AST class from FuncCall. They
    # are NOT in the DEFAULT anon set (they always return the session
    # role name, never NULL — R11 #1), so by default they do NOT fire.
    # But when a project explicitly configures them, the _ANON_SVFOP_NAMES
    # branch of `_is_anon_null_leaf` still models them as anon-NULL and
    # the inverted disjunct fires — this exercises the SQLValueFunction
    # leaf path.
    for fn in ("current_user", "session_user"):
        node = parse_expr(f"{fn} IS NULL OR {_OWNER}")
        assert node is not None
        assert anon_read_counterexample(node, {fn}) is not None


def test_anon_clean_on_never_null_role_svfop_by_default() -> None:
    # R11 #1: with the default anon set, `current_user IS NULL` is NOT
    # treated as anon-NULL (current_user is never NULL in Postgres), so
    # the inverted disjunct does not prove valid — no false fire.
    assert _anon(f"current_user IS NULL OR {_OWNER}") is None
    assert _anon(f"session_user IS NULL OR {_OWNER}") is None


def test_anon_fires_on_bare_true() -> None:
    assert _anon("true") is not None


def test_anon_fires_on_trivial_tautology() -> None:
    assert _anon("1 = 1") is not None


# --- NOT VALID (no fire): None is returned ----------------------------------


def test_anon_clean_on_bare_sqlvaluefunction_equality() -> None:
    # `current_user = 'admin'` under anon is `NULL = 'admin'` → Kleene U
    # → not valid → no fire. Guards the SQLValueFunction leaf against
    # being mis-encoded as a concrete (non-null) value, which would
    # leak a false positive.
    assert _anon("current_user = 'admin'") is None


def test_anon_clean_on_owner_predicate() -> None:
    # N2 — col = NULL is Kleene U, never a satisfiable 2VL Bool.
    assert _anon("owner_id = (SELECT auth.uid())") is None


def test_anon_clean_on_tenant_predicate() -> None:
    # N1.
    assert _anon(
        "tenant_id = (SELECT current_setting('app.tenant_id', true)::uuid)"
    ) is None


def test_anon_clean_on_is_null_under_and() -> None:
    # N4 (make-or-break): U OR (U AND T) = U.
    assert _anon(
        "owner_id = (SELECT auth.uid()) OR "
        "(owner_id = (SELECT current_setting('app.public_owner', true)::uuid) "
        "AND (SELECT auth.uid()) IS NULL)"
    ) is None


def test_anon_clean_on_is_not_null_guard() -> None:
    # N6: F AND U = F.
    assert _anon(
        "(SELECT auth.uid()) IS NOT NULL AND owner_id = (SELECT auth.uid())"
    ) is None


def test_anon_clean_on_narrow_public_carveout() -> None:
    # S1: a constant carve-out is TRUE only for some rows → not valid.
    assert _anon(
        "tenant_id = '00000000-0000-0000-0000-000000000000'::uuid "
        "OR owner_id = (SELECT auth.uid())"
    ) is None


def test_anon_clean_on_shared_bool_carveout() -> None:
    # S2: a boolean comparison operand (amendment #3) — not valid.
    assert _anon("shared = true OR owner_id = (SELECT auth.uid())") is None


def test_anon_clean_on_coerced_guc_count() -> None:
    # P5-excluded: 0 = NULL is U → U OR U = U → not valid.
    assert _anon(
        "0 = (SELECT current_setting('app.uid_count', true))::int "
        "OR owner_id = (SELECT auth.uid())"
    ) is None


def test_anon_clean_on_untranslatable_exists_subquery() -> None:
    # An EXISTS subquery is left opaque (not unwrapped) → abort → None.
    assert _anon(
        "owner_id = (SELECT auth.uid()) OR EXISTS "
        "(SELECT 1 FROM t WHERE (SELECT auth.uid()) IS NULL)"
    ) is None


def test_anon_clean_on_in_list() -> None:
    # AEXPR_IN is an untranslatable shape in v1 → abort → None.
    assert _anon("owner_id IN ('a', 'b') OR (SELECT auth.uid()) IS NULL") is None


def test_anon_returns_none_when_z3_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import pgrls.diff._z3_compare as z3c

    monkeypatch.setattr(z3c, "Z3_AVAILABLE", False)
    assert _anon("(SELECT auth.uid()) IS NULL OR true") is None


def test_anon_bool_column_leaf_cannot_be_true_and_null() -> None:
    # Amendment #1 (soundness): a bool-column leaf lifted to a _TV must
    # carry the exclusivity constraint, so value ∧ null_flag is UNSAT —
    # otherwise an unsound VALID verdict (false fire) becomes reachable.
    from pgrls.diff._z3_compare import (
        _DEFAULT_AUTH_FUNCTIONS,
        _anon_3vl,
        _Context,
        _lift_to_tv,
    )

    ctx = _Context()
    assertions: list[object] = []
    node = parse_expr("flag OR owner_id = (SELECT auth.uid())")
    assert node is not None
    _lift_to_tv(
        _anon_3vl(node, ctx, set(_DEFAULT_AUTH_FUNCTIONS), assertions),
        assertions,
    )
    flag = ctx.column("flag", z3_solver.BoolSort())
    flag_nullflag = ctx.null_flag("flag")
    solver = z3_solver.Solver()
    for a in assertions:
        solver.add(a)
    solver.add(z3_solver.And(flag, flag_nullflag))
    assert solver.check() == z3_solver.unsat


def test_bare_constant_predicate_degrades_instead_of_crashing() -> None:
    # A non-boolean bare predicate — USING (1), USING (42), USING ('x') —
    # translates to a non-Bool Z3 sort. z3.Not / z3.And on it raise
    # Z3Exception, which used to crash classify_via_z3 / counterexample
    # (and therefore `pgrls diff`). Both must now degrade to None so the
    # caller falls through to requires_review. Postgres rejects such a
    # USING at policy creation, but a hand-built / snapshot-loaded
    # predicate can still reach the differ.
    bool_node = parse_expr("active")
    for bare in ("1", "42", "'x'"):
        bare_node = parse_expr(bare)
        assert classify_via_z3(bool_node, bare_node) is None
        assert classify_via_z3(bare_node, bool_node) is None
        assert classify_via_z3(bare_node, bare_node) is None
        assert counterexample(bool_node, bare_node) is None
        assert counterexample(bare_node, bool_node) is None
    # A bare BOOLEAN constant is a valid predicate and must NOT be gated
    # out: USING (true) still classifies normally.
    assert (
        classify_via_z3(parse_expr("true"), parse_expr("true"))
        == "semantic_equivalent"
    )


def test_null_marker_disconnection_is_a_documented_safe_limitation() -> None:
    # CHARACTERIZATION of the deliberate NullTest limitation (module
    # docstring): the IS NULL marker is modelled DISCONNECTED from the
    # column's value var — a 2-valued approximation of Postgres 3VL.
    #
    # A faithful 2-valued linkage was attempted and rejected as UNSOUND
    # under negation (z3.Not is 2-valued; Postgres `NOT (col = x)` is
    # 3-valued — NULL when col is NULL), so it would only trade these
    # over-reports for a new class of `NOT (...)` false alarms. A correct
    # fix needs a full Kleene 3VL re-encoding of the diff path.
    #
    # `col IS NOT NULL AND col = x` is EQUIVALENT to `col = x` in Postgres
    # (a value comparison already excludes NULL rows), but the disconnected
    # marker over-reports it. Pinned so a future 3VL fix flips this
    # deliberately, not by accident.
    assert (
        classify_via_z3(
            parse_expr("active IS NOT NULL AND active = true"),
            parse_expr("active = true"),
        )
        == "semantic_loosened"
    )
    assert (
        classify_via_z3(
            parse_expr("active = true"),
            parse_expr("active IS NOT NULL AND active = true"),
        )
        == "semantic_tightened"
    )


def test_null_limitation_does_not_compromise_soundness() -> None:
    # The limitation must never cost the verifier its safety guarantees —
    # these are exactly the invariants a naive null-guard "fix" broke, and
    # that any real fix must preserve.
    #
    # Arithmetic equivalence holds (a naive guard flipped this to
    # `tightened`):
    assert (
        classify_via_z3(parse_expr("col - 3 > 0"), parse_expr("col > 3"))
        == "semantic_equivalent"
    )
    # A genuine NULL-admitting loosening is STILL flagged DANGEROUS — the
    # coarse model never MISSES a real loosening (the safety-critical
    # direction is intact):
    assert (
        classify_via_z3(
            parse_expr("col = 5"), parse_expr("col = 5 OR col IS NULL")
        )
        == "semantic_loosened"
    )
    # A genuine value loosening is flagged AND still yields the concrete
    # leaking row (col = 6 is the unique member of head \ base):
    assert (
        classify_via_z3(parse_expr("col = 5"), parse_expr("col = 5 OR col = 6"))
        == "semantic_loosened"
    )
    assert counterexample(
        parse_expr("col = 5"), parse_expr("col = 5 OR col = 6")
    ) == {"col": 6}


def test_counterexample_empty_row_for_all_rows_leak() -> None:
    # Regression (round-5): when head ∧ ¬base is a tautology (base rejects
    # every row, head admits all), the verifier's most important admit-case
    # is "every row leaks" — a sound EMPTY-projection witness. Pin the {}
    # return and the witness gate accepting the empty pin.
    from pgrls.diff._z3_compare import (
        _Context,
        _row_is_sufficient_witness,
        _to_z3,
    )

    base = parse_expr("a IS NULL AND a IS NOT NULL")  # always false
    head = parse_expr("true")
    assert counterexample(base, head) == {}
    ctx = _Context()
    base_z3 = _to_z3(base, ctx)
    head_z3 = _to_z3(head, ctx)
    assert _row_is_sufficient_witness({}, base_z3, head_z3, ctx) is True


def test_counterexample_decodes_real_column_as_float() -> None:
    # Regression (round-5): the RealSort decode path (as_fraction -> float)
    # is otherwise untested; a Z3/pglast upgrade could silently break it.
    cx = counterexample(parse_expr("price > 5.0"), parse_expr("price > 0.0"))
    assert cx is not None
    assert isinstance(cx["price"], float)
    assert _row_satisfies_head_not_base("price > 5.0", "price > 0.0", cx)
