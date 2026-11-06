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


def test_or_mixing_comparison_and_bare_boolean_funccall_returns_none():
    # Regression: `is_admin()` translates as an opaque String marker, so
    # `z3.Or(<Int-comparison Bool>, <String opaque>)` raised an uncaught
    # `z3.Z3Exception: sort mismatch` and crashed `pgrls diff` on a
    # realistic policy edit. The boolean connective now degrades to None
    # (→ requires_review), like every other untranslatable operator.
    assert _classify("tenant_id = 2", "tenant_id = 1 OR is_admin()") is None


def test_and_mixing_comparison_and_bare_boolean_funccall_returns_none():
    # Same sort-mismatch guard for the AND connective.
    assert _classify("tenant_id = 2", "tenant_id = 1 AND is_admin()") is None


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
# NULL tests (a column's null-flag)
# ---------------------------------------------------------------------------


def test_is_null_with_added_predicate_is_semantic_tightened():
    # `col IS NULL` ⊃ `col IS NULL AND tenant = 'a'`. The added
    # AND-conjunct only restricts. The IS NULL test reads `col`'s null-flag,
    # the same in both predicates.
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
        _classify("col = 'a'::text AND n = 1", "col = 'a'::text") == "semantic_loosened"
    )
    # Against the bare `'a'` it is no change only for a text column: a
    # `citext` or `char(n)` one compares `'a'::text` as text, `'a'` as itself.
    assert _classify("col = 'a'::text", "col = 'a'") is None


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


def test_arithmetic_on_a_column_of_unknown_type_decides_nothing():
    # `col + 1 > 0` is `col > -1` over the integers, but the text does not
    # say `col` is one, and over a `numeric` / `float8` (NaN, Infinity,
    # rounding) Z3's reals are not Postgres's: the diff abstains.
    assert _classify("col + 1 > 0", "col > -1") is None
    assert _classify("col - 3 > 0", "col > 3") is None
    # A loosening on the integers is a row that newly leaks for any type.
    assert _classify("col + 1 > 0", "col + 5 > 0") == "semantic_loosened"


def test_a_string_compared_with_a_column_reads_by_the_columns_type():
    from pgrls.diff.ast_compare import compare_predicates

    def diff(base, head, **types):
        return compare_predicates(base, head, column_types=types)

    # A `text` column reads every spelling of a string alike ...
    assert diff("email = ANY (ARRAY['A'::text])", "email = 'A'", email="text") == (
        "semantic_equivalent")
    # ... a `citext` or `char(n)` one compares a typed string as text, a bare
    # one as itself, and a list's members in their common type.
    for base, head in (("email = ANY (ARRAY['A'::text])", "email = 'A'"),
                       ("b IN (email = 'A'::text)", "b IN (email = 'A')"),
                       ("COALESCE(email, 'a'::text) = x", "COALESCE(email, 'a') = x"),
                       ("email = ANY (ARRAY['a '::text, 'b'::text])",
                        "email IN ('a '::text, 'b'::text)")):
        for kind in ("citext", "char(4)"):
            assert diff(base, head, email=kind, x=kind, b="boolean") == "requires_review", (
                base, kind)
    # A column against a column of another string type compares in a type
    # either may decide (`citext_col IS NOT DISTINCT FROM text_col` is text).
    assert diff("x IS NOT DISTINCT FROM y AND y = 'a'", "x = 'a' AND y = 'a'",
                x="citext", y="text") == "requires_review"
    assert diff("x = (SELECT y) AND y = 'a'", "x = 'a' AND y = 'a'",
                x="citext", y="text") == "requires_review"
    # So does a function's result (`auth.email()` is text).
    assert diff("email IS NOT DISTINCT FROM auth.email() AND auth.email() = 'a'",
                "email IS NOT DISTINCT FROM 'a' AND auth.email() = 'a'",
                email="citext") == "requires_review"
    # A bare string beside a column in a COALESCE meets another in the
    # column's type on a NULL row (`'0' = '0.00'` numeric, `'A' = 'a'`
    # citext, `'f' = 'false'` bool): only a text one reads it as Z3 does.
    for base, head, kind in (("price = '0.00'", "COALESCE(price, '0') = '0.00'", "numeric"),
                             ("e = 'a'", "COALESCE(e, 'A') = 'a'", "citext"),
                             ("e = 'false'", "COALESCE(e, 'f') = 'false'", "boolean"),
                             ("e = 'a'", "COALESCE(e, 'A') = 'a'", "unknown")):
        assert diff(base, head, price=kind, e=kind) == "requires_review", (head, kind)
        assert compare_predicates(base, head) == "requires_review", head
    assert diff("status = 'x'", "COALESCE(status, 'active') = 'x'", status="text") == (
        "semantic_equivalent")
    # An arm that is no literal (`auth.email()`, text) types the COALESCE.
    for base, head in (("COALESCE(e, auth.email()) = 'A' AND t = 1",
                        "(COALESCE(e, auth.email()) = 'A' OR e = 'A') AND t = 1"),
                       ("COALESCE(e, (SELECT auth.email())) = 'A'", "e = 'A'")):
        assert diff(base, head, e="citext", t="int") == "requires_review", head
    assert diff("COALESCE(e, auth.email()) = 'A' AND t = 1",
                "(COALESCE(e, auth.email()) = 'A' OR e = 'A') AND t = 1",
                e="text", t="int") == "semantic_equivalent"
    # A literal cast to the column's own type (`pg_get_expr`'s enum literal)
    # reads as a bare one: widening an enum role is still DANGEROUS.
    assert diff("org = 1 AND role = 'admin'::app_role",
                "org = 1 AND (role = 'admin'::app_role OR role = 'member'::app_role)",
                org="bigint", role="app_role") == "semantic_loosened"
    # Only `pg_catalog.text` is text: `app.text` may be a domain over citext.
    assert diff("email = ANY (ARRAY['a'::text, 'b'::text])", "email IN ('a', 'b')",
                email="app.text") == "requires_review"
    # A value that is no column is read by its own type: a function's
    # (unknown) or a cast's (`email::citext` on a text column).
    assert diff("(SELECT app.current_role()) = 'admin'::text", "(SELECT app.current_role()) = 'admin'",
                ) == "requires_review"
    assert diff("email::citext IS NOT DISTINCT FROM 'B'::text", "email::citext IS NOT DISTINCT FROM 'B'",
                email="text") == "requires_review"
    # ... in a COALESCE arm too, which takes the arms' common type.
    assert diff("app.current_role() = 'admin'::text",
                "(SELECT COALESCE(app.current_role(), '')) = 'admin'") == "requires_review"
    # A quoted type name is a user type's, whatever it spells.
    assert diff("email = ANY (ARRAY['A'::text])", "email = 'A'", email='"Text"') == (
        "requires_review")
    # A column whose type is unknown is read one way only, as with no types:
    # the canonical tenant clause still cancels.
    assert diff("tenant_id = current_setting('app.t')::bigint AND status = 'active'",
                "tenant_id = current_setting('app.t')::bigint AND status IN ('active', 'pending')",
                tenant_id="unknown", status="unknown") == "semantic_loosened"
    # The canonical tenant clause shared by both sides still cancels.
    tenant = "tenant_id = current_setting('app.tenant_id')::uuid"
    assert diff(f"{tenant} AND status = 'active'",
                f"(tenant_id = '00000000-0000-0000-0000-000000000000' OR {tenant})"
                " AND status = 'active'", tenant_id="uuid", status="text") == "semantic_loosened"


def test_a_cast_of_a_coalesce_is_no_proof():
    # A COALESCE takes a column's type, which a cast may change: a float8
    # `score` rounds to numeric, a citext `s` compares case-sensitively as
    # text, a char(n) one drops trailing spaces. Off the diff path these
    # were proven isolated.
    from pgrls.diff._z3_compare import prove_anon_isolation, prove_cross_tenant_isolation
    for using in ("tenant_id = auth.uid() OR (COALESCE(score, 0)::numeric = 100 AND score > 100)",
                  "tenant_id = auth.uid() OR (s = 'A' AND COALESCE(s, 'x')::text <> 'A')",
                  "tenant_id = auth.uid() OR (s = 'A' AND COALESCE(s, 'x'::text) <> 'A')",
                  "tenant_id = auth.uid() OR ('x ' = s AND COALESCE(s, 'a')::text <> 'x ')",
                  "x::float8::numeric = 1 AND x::float8 <> 1"):
        assert prove_anon_isolation(parse_expr(using))[0] != "isolated", using
        assert prove_cross_tenant_isolation(parse_expr(using))[0] != "isolated", using
    # Two columns meeting through a COALESCE (a numeric and a float8,
    # compared through a double), and a column arm beside a typed one that
    # is no cast (`(SELECT '')`, a function's text), are no proof either.
    t = "tenant_id = (SELECT auth.uid())"
    for using in (f"{t} OR (COALESCE(n, 0) = COALESCE(f, 0) AND n > 0.5 AND f <= 0.5)",
                  f"{t} OR (n = COALESCE(f, 0) AND n > 0.5 AND f <= 0.5)",
                  f"{t} OR (COALESCE(e, (SELECT '')) <> 'A' AND COALESCE(e, '') = 'A')",
                  f"{t} OR (COALESCE(e, auth.email()) <> 'A' AND COALESCE(e, '') = 'A')"):
        assert prove_anon_isolation(parse_expr(using))[0] != "isolated", using
        assert prove_cross_tenant_isolation(parse_expr(using))[0] != "isolated", using
    assert _classify("x = 1", "(x = 1 OR n = COALESCE(f, 0)) AND (x = 1 OR (n > 0.5 AND f <= 0.5))"
                     ) is None
    # A bare string beside a column takes its type: on a NULL row
    # `COALESCE(discount, '0') = '0.00'` is TRUE (numeric), not as text.
    using = (f"{t} OR (COALESCE(discount, '0') = '0.00' "
             f"AND COALESCE(discount, '5') <> '0.00')")
    assert prove_anon_isolation(parse_expr(using))[0] != "isolated"
    assert prove_cross_tenant_isolation(parse_expr(using))[0] != "isolated"
    # A COALESCE of a column and a bare literal still reads exactly.
    assert prove_anon_isolation(parse_expr(f"{t} AND COALESCE(level, 0) < 3"))[0] == "isolated"
    # The session identity's cast keeps its proof.
    assert prove_cross_tenant_isolation(parse_expr(
        "tenant_id = current_setting('app.tenant_id')::bigint"))[0] == "isolated"


def test_a_non_number_cast_in_a_list_keeps_the_provers_verdict():
    # `pg_get_expr` casts every uuid / enum literal in a list; only a number
    # cast that may round its kin abstains (off the diff path).
    from pgrls.diff._z3_compare import (
        cross_tenant_session_identity, prove_anon_isolation, prove_cross_tenant_isolation,
    )
    inverted = ("auth.uid() IS NULL OR (tenant_id = auth.uid() AND status = ANY "
                "(ARRAY['draft'::post_status, 'published'::post_status]))")
    assert prove_anon_isolation(parse_expr(inverted))[0] == "leak"
    scoped = ("tenant_id = (SELECT auth.uid()) AND project_id = ANY (ARRAY["
              "'11111111-1111-1111-1111-111111111111'::uuid, "
              "'22222222-2222-2222-2222-222222222222'::uuid])")
    assert prove_anon_isolation(parse_expr(scoped))[0] == "isolated"
    assert prove_cross_tenant_isolation(parse_expr(scoped))[0] == "isolated"
    assert prove_anon_isolation(parse_expr(
        "tenant_id = COALESCE(auth.uid(), '00000000-0000-0000-0000-000000000000'::uuid)"
    ))[0] == "leak"
    # Float arithmetic is a value of its own off the diff path.
    assert prove_anon_isolation(parse_expr(
        "tenant_id = (SELECT auth.uid()) AND score * (100)::double precision >= 50"
    ))[0] == "isolated"
    assert prove_anon_isolation(parse_expr(
        "tenant_id = (SELECT auth.uid()) OR score * (2)::double precision > 1"
    ))[0] == "leak"
    # A `char(n)` literal as `pg_get_expr` writes it keeps the leaking row.
    assert prove_anon_isolation(parse_expr(
        "tenant_id = current_setting('app.tenant_id', true)::bigint"
        " OR kind = ANY (ARRAY['demo'::bpchar, 'shared'::bpchar])"))[1] in (
            {"kind": "demo"}, {"kind": "shared"})
    # A `bpchar` member gives its type to a bare literal beside it: 'b ' is 'b'.
    assert prove_anon_isolation(parse_expr(
        "x = 'b' AND x = ANY(ARRAY['a'::bpchar, 'b ']) AND x <> 'a'::bpchar"))[0] != "isolated"
    assert prove_anon_isolation(parse_expr(
        "x IS NULL AND COALESCE(x::bpchar, 'b ') = 'b'"))[0] != "isolated"
    # A leak only the integer pass finds still names its tenant axis.
    assert cross_tenant_session_identity(parse_expr(
        "tenant_id = auth.uid() OR org_id = 1234567890123456789")) == ("tenant_id", "auth.uid()")


def test_an_integer_literal_does_not_make_its_column_an_integer():
    # `score >= 1` and `score > 0` are one over the integers, not over a
    # `numeric` (0.5): an offline snapshot's text does not say which.
    assert _classify("tenant_id = (SELECT auth.uid()) AND score >= 1",
                     "tenant_id = (SELECT auth.uid()) AND score > 0") is None
    assert _classify("false", "n * 2 = 1") is None
    # A loosening on the integers is one on every numeric type.
    assert _classify("a >= 1", "a >= 0") == "semantic_loosened"
    assert _counterexample("a >= 1", "a >= 0") == {"a": 0}
    # ... and the provers: an empty integer range may hold a numeric row.
    from pgrls.diff._z3_compare import prove_anon_isolation, prove_cross_tenant_isolation

    using = parse_expr("user_id = auth.uid() OR (n > 0 AND n < 1)")
    assert prove_anon_isolation(using)[0] == "unverified"
    assert prove_cross_tenant_isolation(using)[0] == "unverified"
    assert prove_anon_isolation(parse_expr("user_id = auth.uid() OR n = 2")) == ("leak", {"n": 2})
    # A cast that wraps (`oid`) or raises (past `int4`) is no constant.
    assert _classify("c <> 4294967040", "c = (-256)::oid") is None
    assert prove_anon_isolation(parse_expr(
        "user_id = auth.uid() OR (c = (-256)::oid AND c > 0)"))[0] != "isolated"
    # An integer is read exactly where no float4 reads it (past 2^24) ...
    assert prove_anon_isolation(parse_expr(
        "tenant_id = (SELECT current_setting('app.t', true)::bigint) OR tenant_id = 123456789")
    ) == ("leak", {"tenant_id": 123456789})
    # A string cast to an integer type is an integer literal too.
    assert _classify("c > '9007199254740992'::int8 AND c < '9007199254740994'::int8",
                     "c = '9007199254740993'::int8") is None
    assert _classify("g = '16777217'::int", "g IN ('16777217'::int, '16777217'::int)") is None
    assert prove_anon_isolation(parse_expr(
        "c = '9007199254740993'::int8 AND c <= 9007199254740992"))[0] != "isolated"
    # A COALESCE, or an array with a column in it, gives a literal its
    # column's type, a float4's too (rounded past 2^24), as an IN list does.
    assert _classify("g = 16777216", "COALESCE(g, 16777217) = 16777216") is None
    assert _classify("g = 16777216", "16777216 = ANY(ARRAY[g, 16777217])") is None
    assert prove_anon_isolation(parse_expr(
        "user_id = auth.uid() OR (COALESCE(g, 16777217) = 16777216 AND COALESCE(g, 0) = 0)")
    )[0] != "isolated"
    # A literal cast to float4 is no plain constant: it gives its
    # neighbours the float4 type.
    assert _classify("tenant_id = (select auth.uid()) OR false",
                     "tenant_id = (select auth.uid()) OR COALESCE(16777217, 1::real) = 16777216"
                     ) is None
    assert prove_anon_isolation(parse_expr(
        "tenant_id = current_setting('app.t', true)::int OR "
        "COALESCE(16777217, 1::real) = 16777216"))[0] != "isolated"
    # An IN list of ids past 2^24 still loosens or leaks, on the integers.
    assert _classify("tenant_id IN (100000001, 100000002)",
                     "tenant_id IN (100000001, 100000002, 100000003)") == "semantic_loosened"
    assert prove_anon_isolation(parse_expr(
        "tenant_id = (SELECT auth.uid()) OR org_id IN (100000001, 100000002)"))[0] == "leak"
    # ... and the integer check does not read an integer a float element
    # of the list rounds (`IN (16777217, 1::real)` is a `real[]`).
    # (Each comparison in the list is then a truth of its own: a `bigint`
    # `id` 16777217 is in it, so no proof, and no row is claimed.)
    assert prove_anon_isolation(parse_expr("id IN (16777217, 1::real) AND id = 16777217")) \
        == ("leak", None)
    assert _classify("g::int IN (16777217, 1::real)",
                     "g::int IN (16777216, 16777217, 1::real)") is None
    assert _classify("g IN (9007199254740993, 1::float8)",
                     "g IN (9007199254740993, 9007199254740992, 1::float8)") is None
    # A COALESCE or IN list with a float cast in it rounds its column too:
    # no verdict.
    assert prove_anon_isolation(parse_expr(
        "COALESCE(id, 2::real) = 16777216 AND id = 16777217"))[0] != "isolated"
    assert _classify("tenant_id = 16777217 AND false",
                     "COALESCE(tenant_id, 0::real) = 16777216 AND tenant_id = 16777217") is None
    assert _classify("tenant_id::real IN (16777217, 1)",
                     "tenant_id::real IN (16777217, 16777216, 1)") is None
    # ... as does one hidden in a sub-select or float arithmetic, and a
    # column compared with a float is converted to it (rounded).
    assert prove_anon_isolation(parse_expr(
        "COALESCE(id, (SELECT 0::real)) = 16777216 AND id = 16777217"))[0] != "isolated"
    assert prove_anon_isolation(parse_expr(
        "a = 1::float8 AND b = 1::float8 AND b = 1 AND a > 1"))[0] != "isolated"
    assert _classify("tenant_id = (select auth.uid())",
                     "(tenant_id = (select auth.uid()) OR amount = 1::float8) AND "
                     "(tenant_id = (select auth.uid()) OR (cap = 1::float8 AND cap = 1 AND amount > 1))"
                     ) is None
    assert prove_cross_tenant_isolation(parse_expr(
        "tenant_id = auth.uid() AND amount > 0.5::float8"))[0] == "isolated"
    # ... and so does one with two values of its own (a float column's type
    # rounds the other), a float built-in, and an array with a column in it.
    assert _classify("x <= 1", "COALESCE(x, f, 1) <= 1 AND x IS NOT NULL") is None
    for using in ("COALESCE(x, a + 0) = 1 AND x > 1", "a = pi() AND b = pi() AND a <> b",
                  "x = ANY(ARRAY[a + 0, 1]) AND x > 1 AND (a + 0) IS NULL"):
        assert prove_anon_isolation(parse_expr(using))[0] != "isolated", using
    # A column meeting a value cast to a number type (not a literal) takes it
    # through the column's type, a float's too, which the text does not say.
    assert _classify("amount = 1 AND current_setting('app.v')::numeric = 1",
                     "amount = 1 AND amount = current_setting('app.v')::numeric") is None
    assert _classify("x IS NULL AND current_setting('a.b')::numeric = 1",
                     "x IS NULL AND COALESCE(x, current_setting('a.b')::numeric) = 1") is None
    for head in ("COALESCE(amount, 0) = current_setting('app.v')::numeric",
                 "COALESCE((SELECT amount), 0) <= current_setting('app.v')::numeric",
                 "COALESCE(amount, 0) IN (current_setting('app.v')::numeric)",
                 "COALESCE(amount, 0) BETWEEN current_setting('app.v')::numeric AND 2"):
        assert _classify("amount = 1 AND current_setting('app.v')::numeric = 1",
                         f"amount = 1 AND {head}") is None, head
    # Such a comparison is still one truth wherever the same text is, either
    # way round: the canonical tenant clause both sides share cancels.
    tenant = "tenant_id = current_setting('app.tenant_id')::bigint"
    assert _classify(f"{tenant} AND level < 3", f"{tenant} AND level < 4") == "semantic_loosened"
    assert _classify(tenant, "current_setting('app.tenant_id')::bigint = tenant_id") == (
        "semantic_equivalent")
    assert _classify(f"{tenant} OR is_shared", f"is_shared OR {tenant} OR {tenant}") == (
        "semantic_equivalent")
    # It is an order: `=` → `>=` is a loosening, `<` → `<=` too.
    assert _classify(tenant, tenant.replace("=", ">=", 1)) == "semantic_loosened"
    assert _classify("lvl < current_setting('a.b')::int",
                     "lvl <= current_setting('a.b')::int") == "semantic_loosened"
    assert _classify("t >= current_setting('a.b')::int OR t = 1",
                     "NOT (t < current_setting('a.b')::int) OR t = 1") == "semantic_equivalent"
    # A column read against a typed string (`'A'::text`, `(SELECT 'A')`,
    # `COALESCE('A', '')`, a typed list member) and a bare one compares as text
    # in one and as itself (`citext`, `char(n)`) in the other.
    for base, head in (("email = ANY (ARRAY['A'::text])", "email = 'A'"),
                       ("email IN ('A', 'b'::text)", "email IN ('A', 'b')"),
                       ("email = (SELECT 'A')", "email = 'A'"),
                       ("email = COALESCE('A', '')", "email = 'A'"),
                       ("COALESCE(email, ''::text) = 'A'", "COALESCE(email, '') = 'A'"),
                       ("x = 'a'", "x = ANY(ARRAY['a'::text, 'A'::text])")):
        assert _classify(base, head) is None, (base, head)
    # Read one way on both sides, a change still decides.
    assert _classify("status = ANY (ARRAY['active'::text])",
                     "status = ANY (ARRAY['active'::text, 'trial'::text])") == "semantic_loosened"
    assert _classify("status = 'a'", "status IN ('a', 'b')") == "semantic_loosened"
    # `x = ANY(ARRAY['US '])` compares as text (a `text[]`), `x = 'US '` as
    # `x`'s type: a `char(n)` or `citext` `x` reads them differently.
    for left in ("code::bpchar", "email::citext", "code"):
        assert _classify(f"{left} = ANY (ARRAY['US '])", f"{left} = 'US '") is None, left
    # In an `IN` list the value takes the list's type (a `real` column's
    # float4), not the column's, so it is not the same comparison.
    assert _classify("amount = current_setting('app.v')::numeric OR amount = 1",
                     "amount IN (current_setting('app.v')::numeric, 1)") is None
    # The integer check reads an exact cast of an integer as that integer.
    assert _classify("a IN (16777217, 1) AND a > 0::numeric",
                     "a IN (16777217, 1) AND a >= 0::numeric") is None
    # ... and a nested IN does not end the outer one's rule.
    nested = "COALESCE(g, (a IN (1, 2))::int::float4)"
    assert _classify(f"{nested} = 1",
                     f"{nested} IN (16777217, 1) AND {nested} <> 16777217") is None
    # A numeric tenant key leaks through its OR as an integer one does.
    assert prove_cross_tenant_isolation(parse_expr(
        "tenant_id = (SELECT current_setting('app.tenant_id', true)::numeric) OR is_public")
    ) == ("leak", {"is_public": True})
    # ... and the integer pass makes a column compared with decimals an integer.
    assert _classify("a > 0.9", "a > 0.5") is None
    assert prove_anon_isolation(parse_expr("user_id = auth.uid() OR (a > 0.5 AND a < 0.9)"))[0] \
        == "unverified"


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

    The pin var comes from the freshly-rebuilt context, so it is the
    variable already inside ``h`` / ``b`` (same name + sort). A ``None``
    pins the column NULL.
    """
    from pgrls.diff._z3_compare import _diff_truths

    truths = _diff_truths(parse_expr(base_sql), parse_expr(head_sql))
    assert truths is not None
    ctx, assertions, b, h = truths
    s = z3_solver.Solver()
    s.add(*assertions)
    s.add(z3_solver.And(h.is_true, z3_solver.Not(b.is_true)))
    for key, val in row.items():
        if val is None:
            s.add(ctx.null_flag(key))
            continue
        var = ctx.column(key, _py_value_sort(val))
        assert var is not None, f"reported column {key!r} not bindable"
        s.add(var == val, z3_solver.Not(ctx.null_flag(key)))
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
    assert all(not k.startswith(("_nullflag__", "_opaque__")) for k in cx)
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


def test_counterexample_present_on_incomparable_pair():
    # R19 #2: the documented non-None "incomparable" admit-path — neither
    # base→head nor head→base holds, yet head ∧ ¬base is SAT (partially
    # overlapping ranges). classify_via_z3 returns None (requires_review),
    # so production (policies.py, which calls the emitter only on
    # "semantic_loosened") never reaches this path today. The test pins
    # the admit-path's soundness DIRECTLY, so a future feature that wires
    # counterexample() to the incomparable verdict cannot silently emit a
    # row that does not actually leak.
    base, head = "x > 0", "x < 10"
    # Incomparable → no loosened/tightened/equivalent verdict.
    assert _classify(base, head) is None
    cx = _counterexample(base, head)
    assert cx is not None
    assert all(not k.startswith(("_nullflag__", "_opaque__")) for k in cx)
    # SOUNDNESS: the returned row genuinely lies in head ∖ base.
    assert _row_satisfies_head_not_base(base, head, cx)


def test_no_counterexample_when_equivalent():
    # Semantically equal predicates: head ∧ ¬base is UNSAT.
    assert _classify("a = 1", "1 = a") == "semantic_equivalent"
    assert _counterexample("a = 1", "1 = a") is None


def test_no_counterexample_when_tightened():
    # Head stricter than base: head ∧ ¬base UNSAT.
    assert _classify("a = 1 OR a = 2", "a = 1") == "semantic_tightened"
    assert _counterexample("a = 1 OR a = 2", "a = 1") is None


def test_null_dependent_loosen_names_the_null_column():
    # The leak hinges on `deleted_at IS NULL`: `{active: False}` alone does
    # not leak, so the row must say deleted_at is NULL too.
    base, head = "active = true", "active = true OR deleted_at IS NULL"
    assert _classify(base, head) == "semantic_loosened"
    cx = _counterexample(base, head)
    assert cx is not None and cx["deleted_at"] is None
    assert _row_satisfies_head_not_base(base, head, cx)


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
    assert all(not k.startswith(("_nullflag__", "_opaque__")) for k in cx)
    assert _row_satisfies_head_not_base(
        "tenant_id = 1", "tenant_id = 1 OR tenant_id = 2", cx
    )


# ---------------------------------------------------------------------------
# H2 (SEC038) — `anon_read_counterexample`: the Kleene 3VL anonymous-read
# validity prover — the encoder the diff path above shares.
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


def test_anon_clean_on_never_null_current_setting() -> None:
    # R13 #2 (SEC038 mirror of the SEC004 fix): a never-NULL builtin
    # current_setting — the one-arg form, or the two-arg
    # `current_setting(name, false)` (missing_ok=false also raises on an
    # unset GUC) — is not anon-NULL, so the inverted `… IS NULL OR owner`
    # must NOT prove valid (no false fire). The shared
    # `is_never_null_current_setting` guard backs both the rule and this
    # encoder, so the 1-arg and 2-arg-false cases can no longer drift.
    assert _anon(f"current_setting('app.x') IS NULL OR {_OWNER}") is None
    assert _anon(f"current_setting('app.x', false) IS NULL OR {_OWNER}") is None
    assert _anon(
        f"pg_catalog.current_setting('app.x', false::boolean) IS NULL OR {_OWNER}"
    ) is None
    # The genuinely-NULLable `, true` form still fires (no false negative).
    assert _anon(f"current_setting('app.x', true) IS NULL OR {_OWNER}") is not None


def test_anon_fires_on_bare_true() -> None:
    assert _anon("true") is not None


def test_anon_fires_on_trivial_tautology() -> None:
    assert _anon("1 = 1") is not None


def test_anon_witness_is_always_empty_under_validity() -> None:
    # R14 #4: under the v1 validity criterion the predicate is TRUE for
    # EVERY assignment of the real columns, so no column value
    # characterizes the leak — anon_read_counterexample returns the empty
    # model {} (the honest "all rows" artifact), NEVER an arbitrary
    # satisfying assignment. A valid predicate carrying a FREE real bool
    # column (`flag OR NOT flag`) previously leaked `{'flag': False}` from
    # the witness model, contradicting both the docstring and the SEC038
    # dead-witness pragma. Pin == {} (not just `is not None`) so the
    # contract cannot silently drift.
    assert _anon("(SELECT auth.uid()) IS NULL OR flag OR NOT flag") == {}
    assert _anon("(SELECT auth.uid()) IS NULL OR true") == {}
    assert _anon("true") == {}


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


def test_anon_in_list_is_translated_as_membership() -> None:
    # The deliberate flip this pin asked for: a hand-written `x IN (a, b)`
    # (AEXPR_IN) is the same membership test as the `= ANY (ARRAY[...])` the
    # catalog renders it to, and is now desugared onto the same `_anon_binop`
    # machinery. This predicate is a real unconditional anon leak — the
    # `auth.uid() IS NULL` disjunct is TRUE for a JWT-less session — so SEC038
    # reports it (`{}` = every row) instead of abstaining.
    assert _anon("owner_id IN ('a', 'b') OR (SELECT auth.uid()) IS NULL") == {}
    # Membership alone, with no anon-TRUE disjunct, is not a leak.
    assert _anon("owner_id IN ('a', 'b')") is None


def test_anon_clean_on_case_expr_aborts() -> None:
    # R12 #9: the v1 3VL encoder does not model CaseExpr — it returns
    # None (declines to prove validity = the safe direction). Pin that
    # abort so any future change adding CASE support to _anon_3vl is a
    # deliberate, reviewed flip rather than a silent SEC038 FP/FN.
    assert _anon(
        "CASE WHEN (SELECT auth.uid()) IS NULL THEN true "
        "ELSE owner_id = (SELECT auth.uid()) END"
    ) is None


def test_anon_clean_on_string_sorted_arithmetic_no_crash() -> None:
    # R13 #1: the Z3 Python operator overloads raise a plain TypeError
    # (NOT z3.Z3Exception) when arithmetic `-`/`*`/`/`/`%` is applied to
    # String-sorted operands — which happens routinely for opaque values
    # (now()/current_setting/an unknown-target cast) and for `col OP col`
    # (both default to StringSort). Before the fix this escaped the
    # operator-application catch and crashed SEC038 (and, via the cli
    # dispatch loop, the WHOLE lint run). Each predicate must now degrade
    # to None (untranslatable -> NO-OP), not raise. The headline case is
    # a benign, idiomatic "recent rows" window policy.
    assert _anon("created_at > now() - interval '7 days'") is None
    assert _anon("created_at <> now() - interval '7 days'") is None
    # `col OP col` arithmetic (both sides default to StringSort):
    for op in ("-", "*", "/", "%"):
        assert _anon(f"a {op} b > c OR (SELECT auth.uid()) IS NULL") is None, op


def test_anon_clean_on_bool_sorted_comparison_no_crash() -> None:
    # R13 #1 (sibling): `<`/`>`/`<=`/`>=` on two Bool-sorted operands —
    # e.g. comparing two IS NULL tests — also raises a plain TypeError
    # from the Z3 overload, not z3.Z3Exception. The 3VL comparison site
    # must degrade to None rather than crash.
    assert _anon("(owner_id IS NULL) > (tenant_id IS NULL)") is None
    assert _anon("(owner_id IS NULL) <= (tenant_id IS NULL)") is None


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


def test_string_arithmetic_predicate_degrades_instead_of_crashing() -> None:
    # R13 #1: String-sorted arithmetic (`-`/`*`/`/`/`%`)
    # makes the Z3 operator overload raise a plain TypeError, not
    # z3.Z3Exception. classify_via_z3 / counterexample used to let it
    # escape and crash `pgrls diff`; both must now degrade to None so the
    # caller falls through to requires_review. Sibling of
    # test_bare_constant_predicate_degrades_instead_of_crashing (which
    # pins the Z3Exception case).
    base = parse_expr("created_at > now() - interval '1 day'")
    head = parse_expr("created_at > now() - interval '7 days'")
    assert classify_via_z3(base, head) is None
    assert classify_via_z3(head, base) is None
    assert counterexample(base, head) is None
    # `col OP col` arithmetic — both operands default to StringSort:
    cc = parse_expr("a - b > c")
    assert classify_via_z3(cc, cc) is None
    assert counterexample(cc, cc) is None


def test_reserved_marker_prefix_column_cannot_alias_the_null_flag() -> None:
    # R15 #3: the null-flag for column `x` is minted as
    # z3.Bool("_nullflag__x"); a REAL column literally named `_nullflag__x`
    # (legal via a quoted identifier) would be bound as
    # z3.Const("_nullflag__x", Bool) and — since Z3 keys a constant by
    # name+sort — alias the flag, collapsing distinct predicates to
    # `semantic_equivalent`. `_column_key` refuses to bind a reserved-prefix
    # column, so the predicate degrades to requires_review (None).
    assert _classify("x IS NULL AND y = 1", '"_nullflag__x" AND y = 1') is None
    # _column_key returns "" for every reserved synthetic prefix...
    from pgrls.diff._z3_compare import _column_key, _Context

    for name in ("_opaque__foo", "_nullflag__z", "_session__a"):
        ref = parse_expr(f'"{name}" = 1').lexpr
        assert _column_key(ref, _Context()) == "", name
    # ...but a near-miss / ordinary name still binds normally.
    assert _column_key(parse_expr('"_nullflagx" = 1').lexpr, _Context()) == "_nullflagx"
    assert _column_key(parse_expr("owner_id = 1").lexpr, _Context()) == "owner_id"


def test_a_column_spelled_two_ways_is_one_column() -> None:
    from pgrls.diff._z3_compare import prove_anon_isolation, prove_cross_tenant_isolation

    # pg_get_expr writes `t.a` in a sub-select and `a` outside it: one
    # column, which as two gave a leaking row that cannot exist.
    assert _classify("a = 1 AND b = 1",
                     "((a = 1) AND ((b = 1) OR (( SELECT t.a) = 2)))") == "semantic_equivalent"
    assert _classify("coalesce(a, b) = 'x' AND c = 1",
                     "coalesce(a, b) = 'x' AND (c = 1 OR (SELECT COALESCE(t.a, t.b)) = 'y')"
                     ) == "semantic_equivalent"
    assert prove_anon_isolation(parse_expr(
        "COALESCE(a, b) = 'x' AND (SELECT COALESCE(t.a, t.b)) <> 'x'"))[0] == "isolated"
    # ... and a column a helper reads stays the one compared (Supabase's wrap).
    using = ("((user_id = ( SELECT auth.uid() AS uid)) AND "
             "(( SELECT private.tier(v1.user_id) AS tier) = 'pro'::text))")
    for bare in (using, "user_id = auth.uid() AND private.tier(user_id) = 'pro'"):
        assert prove_anon_isolation(parse_expr(bare))[0] == "isolated", bare
        assert prove_cross_tenant_isolation(parse_expr(bare))[0] == "isolated", bare
    # Two qualifiers are two relations: nothing is decided.
    assert _classify("t.a = 1 AND m.a = 2", "t.a = 1") is None


def test_a_null_test_is_tied_to_its_columns_value() -> None:
    # `col IS NOT NULL AND col = x` is EQUIVALENT to `col = x`: a value
    # comparison already hides the NULL row. (The 2-valued model kept the
    # IS NULL test apart from the column's value and called it loosened.)
    assert classify_via_z3(
        parse_expr("active IS NOT NULL AND active = true"),
        parse_expr("active = true"),
    ) == "semantic_equivalent"
    assert classify_via_z3(
        parse_expr("tenant_id = 1"),
        parse_expr("tenant_id IS NOT NULL AND tenant_id = 1"),
    ) == "semantic_equivalent"


@pytest.mark.parametrize(("base", "head", "verdict"), [
    # A predicate passes a row only when it is exactly TRUE; NULL hides it.
    # `x OR NOT x`-style rewrites are not tautologies: they hide NULL rows.
    ("(c OR false) = (d OR c)", "c OR false = d OR c", "semantic_loosened"),
    ("a = 1 OR a <> 1", "true", "semantic_loosened"),
    ("a = 1 OR NOT (a = 1)", "true", "semantic_loosened"),
    ("x OR NOT x", "true", "semantic_loosened"),
    ("true", "a > 1 OR a <= 1", "semantic_tightened"),
    # `=` / `<>` are NULL on a NULL operand; IS [NOT] DISTINCT FROM never is.
    ("c = d", "c IS NOT DISTINCT FROM d", "semantic_loosened"),
    ("c IS NOT DISTINCT FROM d", "c = d", "semantic_tightened"),
    ("c <> d", "c IS DISTINCT FROM d", "semantic_loosened"),
    ("c IS DISTINCT FROM d", "NOT (c IS NOT DISTINCT FROM d)", "semantic_equivalent"),
    ("a = 1", "a IS NOT DISTINCT FROM 1", "semantic_equivalent"),
    # A boolean comparison nested in another.
    ("(c = d) = e", "(c = d) IS NOT DISTINCT FROM e", "semantic_loosened"),
    # BETWEEN is its AND of comparisons.
    ("x BETWEEN 1 AND 5", "x >= 1 AND x <= 5", "semantic_equivalent"),
    ("x NOT BETWEEN 1 AND 5", "x < 1 OR x > 5", "semantic_equivalent"),
])
def test_three_valued_classification(base: str, head: str, verdict: str) -> None:
    assert _classify(base, head) == verdict


@pytest.mark.parametrize(("base", "head"), [
    # Z3 and Postgres disagree here, so the comparison abstains.
    ("COALESCE(a, b) = 1", "COALESCE(a, b) = 2"),       # bare columns: no sort
    ("COALESCE(a, b) = 1", "COALESCE(a, b) > 0"),
    ("a % 2 = 1 OR a % 2 = 0", "a IS NOT NULL"),        # -1 % 2 is -1 in PG
    ("a / 2 = -1", "a = -2 OR a = -1"),                 # PG truncates
    ("a + b >= a", "a IS NOT NULL AND b IS NOT NULL"),  # Z3 + on text concatenates
    ("'B' < 'b'", "c <> true"),                         # collation order
    # ... also once an equality pins a column, or through a COALESCE.
    ("(s = 'B' AND u = 'a' AND s < u) OR a = 1", "(s = 'B' AND u = 'a') OR a = 1"),
    ("c", "NOT (NOT ((COALESCE(f(), 'a') < s AND s < COALESCE(f(), 'B') "
     "AND f() IS NULL) OR c))"),
    # Postgres rounds a numeric quotient.
    ("(x = 1.0 AND (x / 3.0) * 3.0 = x) OR c", "x = 1.0 OR c"),
    # Z3's reals have no NaN / Infinity.
    ("n * 0.0 = 0.0", "n IS NOT NULL"),
    # A cast that can change the value: precision, truncation, padding, wrap.
    ("f = 0.5", "f = '0.5'::float4"),
    ("n = 1.25", "n = '1.25'::numeric(3,1)"),
    ("c = 'abcdef'", "c = 'abcdef'::varchar(3)"),
    ("c = 'abc'", "c = 'abc'::char"),
    ("a > 0", "a::oid > 0"),
    # A policy's backslash is a backslash, not an escape.
    ("s = 'A'", "s = '\\u{41}'"),
    # Numeric literals past double precision are distinct.
    ("c = 9007199254740992", "c = 9007199254740993"),
    ("n = 0.1", "n = 0.10000000000000000001"),
    # A cast of a value whose type is unknown can change it, even to a type
    # of the same sort.
    ("s::float8 = 0.3", "s::float8::numeric = 0.3"),
    ("s::oid < 0", "s::oid::int4 < 0"),
    ("abs(n)::text = '5'", "abs(n) = '5'"),
])
def test_where_z3_and_postgres_disagree_nothing_is_decided(base: str, head: str) -> None:
    assert _classify(base, head) is None


def test_a_quoted_column_named_like_a_call_has_its_own_null_flag() -> None:
    from pgrls.diff._z3_compare import prove_anon_isolation

    assert _classify('"f()" IS NULL', "f() IS NULL") is None
    # Sharing one null-flag made these a total leak and an isolated policy.
    assert anon_read_counterexample(parse_expr('"f()" IS NULL OR f() IS NOT NULL')) is None
    assert prove_anon_isolation(parse_expr(
        'tenant_id = auth.uid() OR ("f()" IS NULL AND f() IS NOT NULL)'))[0] != "isolated"


def test_a_huge_numeric_literal_does_not_crash() -> None:
    from pgrls.diff._z3_compare import prove_anon_isolation, prove_cross_tenant_isolation

    assert _classify("n > 1e400 OR o = 1", "n > 1e400 AND o = 1") is None
    assert anon_read_counterexample(parse_expr("n > 1e400 OR o = current_setting('app.u', true)")) is None
    assert _counterexample("c > 1e400", "c > 1e399") is None
    for using in ("n > 1e400", "tenant_id = auth.uid() OR n > 1e400"):
        prove_anon_isolation(parse_expr(using))
        prove_cross_tenant_isolation(parse_expr(using))


def test_a_value_beyond_a_doubles_range_is_left_out_of_a_leaking_row() -> None:
    import z3

    from pgrls.diff._z3_compare import _Context, _decode_model

    ctx = _Context()
    n = ctx.column("n", z3.RealSort())
    solver = z3.Solver()
    solver.add(n == z3.RealVal(10**400))
    assert solver.check() == z3.sat
    assert _decode_model(solver.model(), ctx) == {}


@pytest.mark.parametrize(("base", "head"), [
    # A `float8` column compares with the literal rounded to a double, a
    # `numeric` one exactly: the head admits 0.1 on float8 only.
    ("score > 0.1", "score >= 0.10000000000000000001"),
    # The same literal against a `numeric` and a `float8` column.
    ("a = 1.00000000000000001 AND b = 1.00000000000000001 AND "
     "((a > 1.0 AND b > 1.0) OR (a <= 1.0 AND b <= 1.0))",
     "NOT (a <> 1.00000000000000001 OR b <> 1.00000000000000001)"),
    # A `float4` column's `IN` list of two rounds each to a single.
    ("c = 0.1 OR c = 7.0", "c IN (0.1, 7.0)"),
    ("c = 16777217.0", "c IN (16777217.0, 16777217.0)"),
])
def test_a_decimal_column_types_read_differently_decides_nothing(base, head) -> None:
    assert _classify(base, head) is None


def test_a_decimal_a_single_holds_still_translates() -> None:
    # Loosened only on a `numeric` (0.5): an integer column reads both as
    # `n >= 1`, and the text does not say which.
    assert _classify("n > 0.5", "n >= 0.5") is None
    assert _classify("n > 0.5", "n >= 0") == "semantic_loosened"
    assert _counterexample("n > 0.5", "n >= 0") == {"n": 0}
    assert _classify("n > 2.25", "n > 2.25 AND x = 1") == "semantic_tightened"


@pytest.mark.parametrize("using", [
    # Through a float both bounds were -0.1, an empty range; a row holding
    # -0.100000000000000000015 is read.
    "n < '-0.10000000000000000001'::numeric AND n > '-0.10000000000000000002'::numeric",
    "a = 1.00000000000000001 AND 1.00000000000000001 > 1.0 AND a <= 1.0",
    "c IN (0.1, 0.1) AND c <> 0.1",
    # A cast that changes the value is a value of its own on every path.
    "tenant_id = auth.uid() OR '16777217'::float4 = 16777216.0",
    "tenant_id = auth.uid() OR '1.25'::numeric(3,1) <> 1.25",
])
def test_the_provers_do_not_prove_what_a_column_type_decides(using) -> None:
    from pgrls.diff._z3_compare import prove_anon_isolation, prove_cross_tenant_isolation

    assert prove_anon_isolation(parse_expr(using))[0] != "isolated"
    assert prove_cross_tenant_isolation(parse_expr(using))[0] != "isolated"


@pytest.mark.parametrize("using", [
    # Postgres reads `Infinity + 0.5` as `Infinity`, and rounds a float8 sum.
    "tenant_id = auth.uid() OR f + 0.5 = f",
    "tenant_id = auth.uid() OR (f + 0.25 = 0.5 AND f <> 0.25)",
    # Postgres truncates: `-1 % 2` is -1.
    "tenant_id = auth.uid() OR (a % 2) = -1",
    # Postgres orders text by collation: under en_US `'ab'` is both
    # `< 'B'` and `> 'a'`.
    "tenant_id = auth.uid() OR (s < 'B' AND s > 'a')",
    # Text standing for a timestamp or an interval does not order as text
    # (`'10 days' < '7 days'` by code point).
    "tenant_id = auth.uid() OR (now() - created_at > '7 days' AND now() - created_at < '10 days')",
])
def test_arithmetic_z3_does_not_compute_as_postgres_proves_nothing(using) -> None:
    from pgrls.diff._z3_compare import prove_anon_isolation, prove_cross_tenant_isolation

    assert prove_anon_isolation(parse_expr(using))[0] != "isolated"
    assert prove_cross_tenant_isolation(parse_expr(using))[0] != "isolated"


@pytest.mark.parametrize("using", [
    # An unset GUC raises before its NULL reaches `IS NULL` / COALESCE.
    "(current_setting('app.v', true)::numeric % current_setting('app.u')::numeric) IS NULL",
    "COALESCE(current_setting('app.v', true)::numeric % current_setting('app.u')::numeric, 0.5) "
    "= ANY(ARRAY[0.5])",
    "current_setting('app.t')::int + 0 = 5 OR current_setting('app.t')::int + 0 <> 5",
    "(current_setting('app.t')::int + 0 = 5) IS NULL",
    "COALESCE(current_setting('app.t')::int + 0 = 5, true)",
])
def test_arithmetic_on_an_unset_guc_is_not_an_anonymous_leak(using) -> None:
    assert _anon(using) is None


def test_arithmetic_beside_the_identity_keeps_the_proof() -> None:
    from pgrls.diff._z3_compare import prove_anon_isolation, prove_cross_tenant_isolation

    for using in ("tenant_id = auth.uid() AND price * 2.5 > 10",
                  "tenant_id = auth.uid() AND COALESCE(a, b) = 1",
                  "tenant_id = auth.uid() AND status < 'm'",
                  "tenant_id = auth.uid() AND " + " + ".join(["f"] + ["0.5"] * 200) + " > 1"):
        assert prove_anon_isolation(parse_expr(using))[0] == "isolated", using
        assert prove_cross_tenant_isolation(parse_expr(using))[0] == "isolated", using


def test_a_huge_exponent_is_refused_at_once() -> None:
    import time

    from pgrls.diff._z3_compare import _exact_real

    start = time.monotonic()
    assert _exact_real("1e999999999") is None
    assert _exact_real("1e" + "9" * 5000) is None  # past int()'s digit limit
    assert _exact_real("1e+00005") is not None  # a sign and zeros are not digits
    assert _classify("x < 1e999999999", "x < 2e999999999") is None
    assert time.monotonic() - start < 5


def test_a_uuid_or_integer_cast_of_the_identity_keeps_the_proof() -> None:
    from pgrls.diff._z3_compare import prove_anon_isolation, prove_cross_tenant_isolation

    for using in ("tenant_id = current_setting('app.t', true)::uuid",
                  "tenant_id = current_setting('app.t', true)::bigint"):
        assert prove_anon_isolation(parse_expr(using))[0] == "isolated"
        assert prove_cross_tenant_isolation(parse_expr(using))[0] == "isolated"


def test_a_guc_value_postgres_would_not_read_is_not_folded() -> None:
    # `'1/2'::float8` raises in Postgres; it is not the row {x: 0.5}.
    from pgrls.diff._z3_compare import _exact_real

    assert _exact_real("1/2") is None
    assert _exact_real("\u0661.5") is None  # Arabic-Indic digit
    assert _exact_real(" .5 ") is not None


def test_a_value_keeping_cast_still_translates() -> None:
    assert _classify("a = '5'::int", "a = 5") == "semantic_equivalent"
    assert _classify("t = 'x'::text AND n = 1", "t = 'x'::text AND n = 1 AND m = 2") == (
        "semantic_tightened")


def test_a_leaking_row_keeps_a_policys_backslash() -> None:
    assert _counterexample("s = 'B'", "s = 'B' OR s = '\\u{41}'") == {"s": "\\u{41}"}


def test_a_character_past_z3s_alphabet_decides_nothing() -> None:
    # Z3's strings end at U+2FFFF: past it StringVal makes the text of the
    # escape, which a policy's literal `'\u{30000}'` is too.
    from pgrls.diff._z3_compare import prove_anon_isolation

    assert _classify("tenant = '\\u{e0067}'", "tenant = '\U000e0067'") is None
    assert prove_anon_isolation(parse_expr(
        "label = '\U00030000' AND label <> '\\u{30000}'"))[0] != "isolated"
    assert _counterexample("label = 'a'", "label = 'a' OR label = '\U00030000'") is None


def test_a_leaking_row_prints_a_character_past_latin1() -> None:
    assert _counterexample("s = 'a'", "s = 'a' OR s = '\U00024cc8'") == {"s": "\U00024cc8"}
    assert _counterexample("s = 'a'", "s = 'a' OR s = '\u4e2d'") == {"s": "\u4e2d"}


def test_the_anon_and_cross_tenant_provers_keep_their_proofs() -> None:
    # Off the diff path a `%` is a value of its own and a text ordering a
    # truth of its own: beside the tenant equality under AND, neither can
    # make it leak.
    from pgrls.diff._z3_compare import prove_anon_isolation, prove_cross_tenant_isolation

    for using in ("tenant_id = auth.uid() AND (seq % 2) = 0",
                  "user_id = auth.uid() AND status < 'm'::text"):
        assert prove_anon_isolation(parse_expr(using))[0] == "isolated", using
        assert prove_cross_tenant_isolation(parse_expr(using))[0] == "isolated", using


def test_a_coalesce_of_bare_columns_is_a_value_of_its_own() -> None:
    # Modelled exactly, its bare columns defaulted to Bool and three text
    # columns could hold only two values — `(SELECT x)` included.
    from pgrls.diff._z3_compare import prove_anon_isolation, prove_cross_tenant_isolation

    c = "coalesce((SELECT {0}), (SELECT {0}))".format
    base = (f"x IS NOT NULL AND y IS NOT NULL AND z IS NOT NULL AND ({c('x')} = {c('y')} "
            f"OR {c('y')} = {c('z')} OR {c('x')} = {c('z')})")
    assert _classify(base, "NOT (x IS NULL OR y IS NULL OR z IS NULL)") != "semantic_equivalent"
    using = ("coalesce(x, x) <> coalesce(y, y) AND coalesce(y, y) <> coalesce(z, z) "
             "AND coalesce(x, x) <> coalesce(z, z)")
    assert prove_anon_isolation(parse_expr(using))[0] != "isolated"
    assert prove_cross_tenant_isolation(
        parse_expr(f"tenant_id = auth.uid() OR ({using})"))[0] != "isolated"


def test_a_doubly_wrapped_column_is_no_bool() -> None:
    from pgrls.diff._z3_compare import prove_anon_isolation

    d = "(SELECT (SELECT {0}))".format
    using = f"{d('x')} <> {d('y')} AND {d('y')} <> {d('z')} AND {d('x')} <> {d('z')}"
    assert _classify("false", using) == "semantic_loosened"
    assert prove_anon_isolation(parse_expr(using))[0] == "leak"


@pytest.mark.parametrize("using", [
    # `(SELECT x LIMIT 0)` and `(SELECT x OFFSET 1)` are NULL, not `x`.
    "(SELECT a LIMIT 0) IS NULL AND (SELECT a) IS NOT NULL",
    "tenant_id = auth.uid() OR ((SELECT a OFFSET 1) IS NULL AND a IS NOT NULL)",
    "(SELECT (SELECT x) LIMIT 0) IS NULL AND x IS NOT NULL",
])
def test_a_limited_scalar_select_is_no_column(using) -> None:
    from pgrls.diff._z3_compare import prove_anon_isolation

    assert prove_anon_isolation(parse_expr(using))[0] != "isolated"


def test_a_limited_scalar_select_is_no_change_of_nothing() -> None:
    assert _classify("(SELECT x LIMIT 0) = 'a'", "x = 'a'") is None


@pytest.mark.parametrize(("base", "head"), [
    # A set-returning function that yields no row makes the sub-select NULL:
    # in ORDER BY or a WINDOW, or anywhere in the target — under IS NULL, in
    # an IN list, inside a call pinned non-NULL.
    ("false", "(SELECT true ORDER BY generate_series(1, 0)) IS NULL"),
    ("(SELECT a ORDER BY generate_series(1, 0)) = 1", "a = 1"),
    ("false", "(SELECT generate_series(1, 0) IS NULL) IS NULL"),
    ("false", "(SELECT true WINDOW w AS (ORDER BY generate_series(1, 0))) IS NULL"),
    ("(SELECT tag IN (json_array_elements_text(current_setting('app.tags', true)::json), "
     "'public'))", "tag = 'public'"),
    ("false", "(SELECT current_setting(json_array_elements_text('[]'))) IS NULL"),
])
def test_a_sub_select_a_set_returning_call_can_empty_is_no_expression(base, head) -> None:
    # Never equivalent or a tightening: the head admits rows the base does not.
    assert _classify(base, head) not in ("semantic_equivalent", "semantic_tightened")


@pytest.mark.parametrize(("base", "head"), [
    # Wrapping an auth call in a sub-select (what PERF001's fix writes) is
    # no change, on the diff path too.
    ("(SELECT auth.uid()) = user_id", "auth.uid() = user_id"),
    ("tenant = (SELECT current_setting('app.tenant', true))",
     "tenant = current_setting('app.tenant', true)"),
    ("tenant = 'public' AND current_setting('app.tenant', true) IS NULL",
     "tenant = 'public' AND (SELECT current_setting('app.tenant', TRUE)) IS NULL"),
])
def test_wrapping_an_auth_call_is_no_change(base, head) -> None:
    assert _classify(base, head) == "semantic_equivalent"
    assert _classify(head, base) == "semantic_equivalent"


@pytest.mark.parametrize("head", [
    # `current_setting` is STRICT: a name read from a column is NULL where
    # the column is, whatever the form.
    "kind = 'public' OR current_setting(cfg) IS NULL",
    "kind = 'public' OR current_setting(cfg, false) IS NULL",
    "kind = 'public' OR (SELECT current_setting(cfg)) IS NULL",
    # Two calls of a built-in VOLATILE function are two values.
    "kind = 'public' OR (random() IS NULL AND random() IS NOT NULL)",
    "kind = 'public' OR (clock_timestamp() < '2020-01-01' "
    "AND clock_timestamp() >= '2020-01-01')",
    "kind = 'public' OR ((SELECT gen_random_uuid()) = x AND (SELECT gen_random_uuid()) <> x)",
    "kind = 'public' OR (array_shuffle(arr) = '{1,2}' AND array_shuffle(arr) = '{2,1}')",
    # ... and a missing_ok read from a column, or NULL, makes it NULL.
    "kind = 'public' OR current_setting('app.t', flag) IS NULL",
])
def test_a_value_that_can_differ_is_not_taken_as_one(head) -> None:
    assert _classify("kind = 'public'", head) not in ("semantic_equivalent", "semantic_tightened")


def test_a_setting_named_by_a_column_is_no_identity() -> None:
    from pgrls.diff._z3_compare import prove_anon_isolation, prove_cross_tenant_isolation

    # NULL where the column is, so anon reads that row; and the setting the
    # row names, not the session's tenant.
    for using in ("tenant_id = (SELECT auth.uid()) OR current_setting(cfg) IS NULL",
                  "tenant_id = (SELECT auth.uid()) OR current_setting(cfg, false) IS NULL"):
        assert prove_anon_isolation(parse_expr(using))[0] == "leak", using
    for using in ("tenant_id = current_setting(s)", "tenant_id = current_setting(s, true)",
                  # STRICT in missing_ok too.
                  "tenant_id = current_setting('app.t', flag) "
                  "OR current_setting('app.t', flag) IS NULL",
                  "tenant_id = current_setting('app.t', NULL) "
                  "OR current_setting('app.t', NULL) IS NULL"):
        assert prove_cross_tenant_isolation(parse_expr(using))[0] != "isolated", using


def test_a_computed_missing_ok_reads_the_setting_or_null() -> None:
    from pgrls.diff._z3_compare import prove_anon_isolation, prove_cross_tenant_isolation

    # The anon-key caller's claims are set: its role is 'anon' (a setting's
    # name is read ignoring case).
    for using in ("current_setting('request.jwt.claims', flag) IS NOT NULL",
                  "current_setting('request.jwt.claim.role', flag) = 'anon'",
                  "current_setting('REQUEST.JWT.CLAIM.ROLE', true) = 'anon'",
                  "current_setting('Request.Jwt.Claims', true) IS NOT NULL"):
        assert prove_anon_isolation(parse_expr(using))[0] == "leak", using

    # Unset under anon, so NULL or it raises; the session's own value, or
    # NULL, for a tenant.
    for using in ("tenant_id = current_setting('app.t', flag)",
                  "tenant_id = current_setting('app.t', a = 1)"):
        assert prove_anon_isolation(parse_expr(using))[0] == "isolated", using
        assert prove_cross_tenant_isolation(parse_expr(using))[0] == "isolated", using


def test_a_scalar_select_of_an_auth_call_still_unwraps() -> None:
    from pgrls.diff._z3_compare import prove_anon_isolation, prove_cross_tenant_isolation

    for using in ("tenant_id = (SELECT auth.uid())",
                  "tenant_id = (SELECT current_setting('app.t', true)::uuid)",
                  "user_id = (SELECT auth.uid()) AND (SELECT auth.uid() IS NOT NULL)"):
        assert prove_anon_isolation(parse_expr(using))[0] == "isolated", using
        assert prove_cross_tenant_isolation(parse_expr(using))[0] == "isolated", using
    # One-argument current_setting raises on an unset GUC, never NULL.
    using = "tenant = (SELECT current_setting('app.t')) OR (SELECT current_setting('app.t')) IS NULL"
    assert prove_anon_isolation(parse_expr(using))[0] == "isolated"
    assert prove_cross_tenant_isolation(parse_expr(using))[0] == "isolated"
    # The inverted-auth leak, written with sub-selects, stays a total leak.
    assert anon_read_counterexample(parse_expr(
        "user_id = (SELECT auth.uid()) OR (SELECT auth.uid() IS NULL)")) == {}
    assert _classify("tenant_id = (SELECT auth.uid())",
                     "tenant_id = (SELECT auth.uid()) AND x = 1") == "semantic_tightened"


def test_a_predicate_too_deep_for_the_stack_decides_nothing() -> None:
    import sys

    from pgrls.diff._z3_compare import prove_anon_isolation, prove_cross_tenant_isolation

    deep = "coalesce(" * 150 + "x" + ", 'a')" * 150 + " = 'b'"
    base, head, using = parse_expr("x = 'b'"), parse_expr(deep), parse_expr(deep)
    limit = sys.getrecursionlimit()
    sys.setrecursionlimit(300)  # the stack a deeper nesting would exhaust
    try:
        anon = prove_anon_isolation(using)
        cross = prove_cross_tenant_isolation(using)
        diff = classify_via_z3(base, head)
    finally:
        sys.setrecursionlimit(limit)
    assert anon == ("unverified", None) and cross == ("unverified", None) and diff is None


def test_a_deeply_nested_scalar_select_does_not_crash() -> None:
    from pgrls.diff._z3_compare import prove_anon_isolation

    using = "(SELECT " * 1200 + "a" + ")" * 1200 + " = 1"
    prove_anon_isolation(parse_expr(using))


def test_a_coalesce_column_takes_its_siblings_sort() -> None:
    # The nullable-flag idiom stays exact: `is_public` is a Bool beside `false`.
    from pgrls.diff._z3_compare import prove_anon_isolation, prove_cross_tenant_isolation

    leak = "tenant_id = current_setting('app.t', true) OR coalesce(is_public, false)"
    assert prove_anon_isolation(parse_expr(leak)) == ("leak", {"is_public": True})
    scoped = "tenant_id = current_setting('app.t', true) AND NOT coalesce(is_deleted, false)"
    assert prove_anon_isolation(parse_expr(scoped))[0] == "isolated"
    assert prove_cross_tenant_isolation(parse_expr(scoped))[0] == "isolated"


def test_a_bare_column_coalesce_is_no_total_anonymous_leak() -> None:
    # `COALESCE(level, tier) < 2` modelled the two as Bools coerced to 0/1,
    # which made this policy read as TRUE for every row (a false SEC038).
    assert anon_read_counterexample(parse_expr(
        "COALESCE(level, tier) < 2 OR (level IS NULL AND tier IS NULL)")) is None


def test_a_null_admitting_widening_names_the_null_row() -> None:
    base, head = "a = 1 OR a <> 1", "true"
    cx = _counterexample(base, head)
    assert cx == {"a": None}
    assert _row_satisfies_head_not_base(base, head, cx)


def test_null_handling_keeps_the_verifiers_invariants() -> None:
    # The invariants a naive 2-valued null-guard "fix" broke, which the
    # three-valued encoding keeps.
    #
    # Arithmetic equivalence holds (a naive guard flipped this to
    # `tightened`):
    assert (
        classify_via_z3(parse_expr("NOT (col <= 3)"), parse_expr("col > 3"))
        == "semantic_equivalent"
    )
    # A genuine NULL-admitting loosening is flagged DANGEROUS, with the
    # NULL row that leaks:
    assert (
        classify_via_z3(
            parse_expr("col = 5"), parse_expr("col = 5 OR col IS NULL")
        )
        == "semantic_loosened"
    )
    assert counterexample(
        parse_expr("col = 5"), parse_expr("col = 5 OR col IS NULL")
    ) == {"col": None}
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
    from pgrls.diff._z3_compare import _diff_truths, _diff_witness_is_sufficient

    base = parse_expr("a IS NULL AND a IS NOT NULL")  # always false
    head = parse_expr("true")
    assert counterexample(base, head) == {}
    truths = _diff_truths(base, head)
    assert truths is not None
    ctx, assertions, b, h = truths
    leaks = z3_solver.And(h.is_true, z3_solver.Not(b.is_true))
    assert _diff_witness_is_sufficient({}, leaks, ctx, assertions) is True


def test_a_leaking_row_is_an_integer_one() -> None:
    # It leaks whatever numeric type the column is.
    cx = counterexample(parse_expr("price > 5.0"), parse_expr("price > 0.0"))
    assert cx is not None
    assert isinstance(cx["price"], int) and 0 < cx["price"] <= 5
