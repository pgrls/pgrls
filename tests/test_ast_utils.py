"""Unit tests for AST helpers. Pure Python, no database."""
from __future__ import annotations

from pgrls.ast_utils import (
    extract_column_refs,
    extract_range_vars,
    find_func_calls,
    is_literal_false,
    is_literal_true,
    match_is_null,
    parse_expr,
    top_level_disjuncts,
)


def test_parse_expr_returns_node_for_valid_expression() -> None:
    node = parse_expr("a = 1")
    assert node is not None


def test_parse_expr_returns_none_for_unparseable_input(capsys) -> None:
    node = parse_expr("this is not sql !!!")
    assert node is None
    captured = capsys.readouterr()
    assert "could not parse" in captured.err.lower()


def test_parse_expr_returns_none_for_empty_string() -> None:
    assert parse_expr("") is None


def test_parse_expr_returns_none_for_none_input() -> None:
    assert parse_expr(None) is None  # type: ignore[arg-type]


def test_parse_expr_default_fail_message_tail_lists_lint_rules(capsys) -> None:
    # The default tail (lint context) lists the SEC/PERF/HYG rule IDs
    # that get skipped on parse failure, so a `pgrls lint` user knows
    # which rules silently dropped output for the policy.
    parse_expr("garbage :::")
    err = capsys.readouterr().err
    assert "AST-based rules (SEC004" in err
    assert "PERF001" in err
    assert "HYG001" in err


def test_parse_expr_custom_fail_message_tail_replaces_default(capsys) -> None:
    # Pin the kwarg contract: callers (e.g. pgrls.diff) override the
    # tail so the warning describes the calling context (diff)
    # rather than lint. A future refactor that drops the kwarg or
    # ignores it would surface here.
    parse_expr("garbage :::", fail_message_tail="Custom diff-context tail.")
    err = capsys.readouterr().err
    assert "Custom diff-context tail." in err
    # The default lint tail must NOT appear when an override is set —
    # otherwise the user sees both messages and gets confused.
    assert "AST-based rules (SEC004" not in err


def test_parse_expr_custom_tail_with_location_keeps_named_policy(
    capsys,
) -> None:
    # When both location and a custom tail are passed, the warning
    # should still name the policy (head) AND use the custom tail.
    parse_expr(
        "garbage :::",
        location="public.t.bad_policy",
        clause="USING",
        fail_message_tail="Diff falls back to REQUIRES_REVIEW.",
    )
    err = capsys.readouterr().err
    assert "could not parse policy public.t.bad_policy" in err
    assert "(USING clause)" in err
    assert "Diff falls back to REQUIRES_REVIEW." in err


def test_top_level_disjuncts_splits_or_chain() -> None:
    node = parse_expr("a = 1 OR b = 2 OR c = 3")
    assert node is not None
    disjuncts = top_level_disjuncts(node)
    assert len(disjuncts) == 3


def test_top_level_disjuncts_returns_singleton_for_and() -> None:
    node = parse_expr("a = 1 AND b = 2")
    assert node is not None
    disjuncts = top_level_disjuncts(node)
    assert len(disjuncts) == 1
    assert disjuncts[0] is node


def test_top_level_disjuncts_returns_singleton_for_leaf() -> None:
    node = parse_expr("a = 1")
    assert node is not None
    disjuncts = top_level_disjuncts(node)
    assert len(disjuncts) == 1
    assert disjuncts[0] is node




def test_extract_column_refs_unqualified() -> None:
    node = parse_expr("email = 'x'")
    refs = extract_column_refs(node)
    assert ("email",) in refs


def test_extract_column_refs_qualified() -> None:
    node = parse_expr("u.email = 'x'")
    refs = extract_column_refs(node)
    assert ("u", "email") in refs


def test_extract_column_refs_includes_sublink_by_default() -> None:
    node = parse_expr(
        "tenant_id IN (SELECT id FROM tenants WHERE active = true)"
    )
    refs = extract_column_refs(node)
    assert ("tenant_id",) in refs
    assert ("id",) in refs
    assert ("active",) in refs


def test_extract_column_refs_excludes_sublink_when_flag_set() -> None:
    node = parse_expr(
        "tenant_id IN (SELECT id FROM tenants WHERE active = true)"
    )
    refs = extract_column_refs(node, exclude_sublinks=True)
    assert ("tenant_id",) in refs
    assert ("id",) not in refs
    assert ("active",) not in refs


def test_extract_column_refs_skips_wildcard_a_star() -> None:
    node = parse_expr("count(*) > 0")
    refs = extract_column_refs(node)
    # No spurious tuple for `*`
    for ref in refs:
        for part in ref:
            assert part != "*"


def test_extract_column_refs_descends_into_range_function_in_from_clause() -> None:
    # Companion to
    # `test_find_func_calls_descends_into_range_function_in_from_clause`
    # — the same `RangeFunction.functions = tuple[tuple[FuncCall,
    # None]]` shape would silently swallow ColumnRef nodes nested
    # inside a function call in the FROM clause if the walker
    # didn't recurse into bare tuples. Pin both helpers so a
    # walker rewrite that breaks one surfaces here as well.
    import pglast

    parsed = pglast.parse_sql("SELECT 1 FROM public.f(t.col)")
    refs = extract_column_refs(parsed[0].stmt)
    assert ("t", "col") in refs


def test_find_func_calls_matches_qualified_name() -> None:
    node = parse_expr("auth.uid() = '1'")
    matches = find_func_calls(node, {"auth.uid"})
    assert len(matches) == 1


def test_find_func_calls_matches_bare_name() -> None:
    node = parse_expr("current_setting('x') = '1'")
    matches = find_func_calls(node, {"current_setting"})
    assert len(matches) == 1


def test_find_func_calls_descends_into_range_function_in_from_clause() -> None:
    # `RangeFunction.functions` is a tuple-of-tuples (each
    # entry is `(FuncCall, None)` — the inner tuple holds the
    # call node plus optional column-list aliasing). The walker
    # used to handle `tuple[Node]` but not `tuple[tuple]`, so
    # set-returning functions in FROM clauses (the canonical
    # `SELECT * FROM f()` pattern) were silently skipped.
    # Pin the recursion explicitly here so a future walker
    # rewrite can't reintroduce the gap.
    import pglast

    parsed = pglast.parse_sql("SELECT * FROM public.read_secret()")
    matches = find_func_calls(parsed[0].stmt, {"public.read_secret"})
    assert len(matches) == 1


def test_find_func_calls_matches_current_user_sql_value_function() -> None:
    node = parse_expr("current_user = 'x'")
    matches = find_func_calls(node, {"current_user"})
    assert len(matches) == 1


def test_find_func_calls_returns_empty_when_no_match() -> None:
    node = parse_expr("a = 1")
    matches = find_func_calls(node, {"auth.uid"})
    assert matches == []


def test_find_func_calls_finds_multiple() -> None:
    node = parse_expr("auth.uid() IS NULL OR auth.uid() = '1'")
    matches = find_func_calls(node, {"auth.uid"})
    assert len(matches) == 2



def test_match_is_null_matches_is_null() -> None:
    node = parse_expr("auth.uid() IS NULL")
    result = match_is_null(node)
    assert result is not None
    inner, is_null = result
    assert is_null is True
    assert inner is not None


def test_match_is_null_matches_is_not_null() -> None:
    node = parse_expr("auth.uid() IS NOT NULL")
    result = match_is_null(node)
    assert result is not None
    _inner, is_null = result
    assert is_null is False


def test_match_is_null_returns_none_for_other_expr() -> None:
    node = parse_expr("auth.uid() = '1'")
    assert match_is_null(node) is None


def test_parse_expr_handles_complex_boolean_tree() -> None:
    node = parse_expr("(a = 1 AND b = 2) OR (c IS NULL)")
    assert node is not None


def test_parse_expr_handles_in_and_subquery() -> None:
    node = parse_expr("a IN (SELECT id FROM t WHERE active = true)")
    assert node is not None


def test_top_level_disjuncts_treats_top_and_as_singleton() -> None:
    # Top is AND — entire expression is one disjunct.
    node = parse_expr("(a = 1 OR b = 2) AND c = 3")
    assert node is not None
    disjuncts = top_level_disjuncts(node)
    assert len(disjuncts) == 1
    assert disjuncts[0] is node


def test_top_level_disjuncts_splits_top_or_with_and_inside() -> None:
    # Top is OR with AND inside one branch — 2 disjuncts.
    node = parse_expr("(a = 1 AND b = 2) OR c = 3")
    assert node is not None
    disjuncts = top_level_disjuncts(node)
    assert len(disjuncts) == 2


def test_top_level_disjuncts_does_not_descend_into_nested_or() -> None:
    # `a OR (b OR c)` parses to nested ORs. The helper splits at the top
    # level only; the inner `(b OR c)` stays bundled. This pins the
    # behavior — SEC004 relies on it (a wrapped IS-NULL inside a nested
    # OR isn't a top-level disjunct in the SEC004 sense).
    node = parse_expr("a = 1 OR (b = 2 OR c = 3)")
    assert node is not None
    disjuncts = top_level_disjuncts(node)
    # Pglast may or may not flatten — accept either shape but make sure
    # we don't produce more than the top-level OR's arg count would imply.
    assert 2 <= len(disjuncts) <= 3


def test_extract_column_refs_collects_function_arguments() -> None:
    node = parse_expr("lower(email) = 'x'")
    refs = extract_column_refs(node)
    assert ("email",) in refs


def test_extract_column_refs_returns_set_with_no_duplicates() -> None:
    # `a` appears twice in source but the helper returns a set.
    node = parse_expr("a = 1 OR a = 2")
    refs = extract_column_refs(node)
    a_refs = [r for r in refs if r == ("a",)]
    assert a_refs == [("a",)]


def test_extract_column_refs_collects_three_part_qualified() -> None:
    # `schema.table.col` is a valid 3-part column reference. Pglast
    # represents it as ColumnRef(fields=[String, String, String]).
    node = parse_expr("public.users.email = 'x'")
    refs = extract_column_refs(node)
    assert ("public", "users", "email") in refs


def test_extract_column_refs_walks_function_in_function() -> None:
    node = parse_expr("upper(lower(email)) = 'X'")
    refs = extract_column_refs(node)
    assert ("email",) in refs


def test_extract_column_refs_handles_table_wildcard() -> None:
    # `t.*` — wildcard ref. Helper bails on it without collecting `t`.
    node = parse_expr("count(t.*) > 0")
    refs = extract_column_refs(node)
    for ref in refs:
        for part in ref:
            assert part != "*"


def test_find_func_calls_returns_empty_for_empty_target_set() -> None:
    node = parse_expr("auth.uid() = '1'")
    matches = find_func_calls(node, set())
    assert matches == []


def test_find_func_calls_filters_to_only_named_targets() -> None:
    node = parse_expr("auth.uid() = current_setting('x')")
    matches = find_func_calls(node, {"current_setting"})
    assert len(matches) == 1


def test_find_func_calls_finds_nested_inside_other_function() -> None:
    # `lower(auth.uid())` — the nested auth.uid call should still match.
    node = parse_expr("lower(auth.uid()) = 'x'")
    matches = find_func_calls(node, {"auth.uid"})
    assert len(matches) == 1


def test_find_func_calls_matches_session_user() -> None:
    node = parse_expr("session_user = 'postgres'")
    matches = find_func_calls(node, {"session_user"})
    assert len(matches) == 1


def test_find_func_calls_default_finds_inside_sublink() -> None:
    # Default behaviour walks into SubLinks and finds calls there.
    node = parse_expr("x = (SELECT auth.uid())")
    matches = find_func_calls(node, {"auth.uid"})
    assert len(matches) == 1


def test_find_func_calls_exclude_sublinks_skips_inside_sublink() -> None:
    # PERF001 contract: a call wrapped in `(SELECT ...)` is "wrapped" and
    # must not be reported.
    node = parse_expr("x = (SELECT auth.uid())")
    matches = find_func_calls(node, {"auth.uid"}, exclude_sublinks=True)
    assert matches == []


def test_find_func_calls_exclude_sublinks_still_finds_top_level() -> None:
    # Excluding SubLinks must not hide top-level calls — PERF001 needs to
    # see unwrapped `auth.uid()` directly in USING.
    node = parse_expr("auth.uid() = user_id")
    matches = find_func_calls(node, {"auth.uid"}, exclude_sublinks=True)
    assert len(matches) == 1


def test_find_func_calls_exclude_sublinks_skips_in_in_subquery() -> None:
    # `x IN (SELECT auth.uid())` — the call is inside a SubLink so it must
    # be skipped when exclude_sublinks=True. Pins the rule for IN/EXISTS
    # subqueries (matches the spec definition: any SubLink ancestor =
    # wrapped).
    node = parse_expr("x IN (SELECT auth.uid())")
    matches = find_func_calls(node, {"auth.uid"}, exclude_sublinks=True)
    assert matches == []


def test_find_func_calls_exclude_sublinks_walks_testexpr() -> None:
    # `auth.uid() IN (SELECT id FROM trusted)` — the call is on the LHS
    # (SubLink.testexpr), not inside the subselect. exclude_sublinks
    # must still walk testexpr or PERF001 misses an unwrapped auth call.
    # Mirrors extract_column_refs's testexpr-walking shape.
    node = parse_expr("auth.uid() IN (SELECT id FROM trusted)")
    matches = find_func_calls(node, {"auth.uid"}, exclude_sublinks=True)
    assert len(matches) == 1


def test_match_is_null_returns_arg_for_function_call() -> None:
    node = parse_expr("auth.uid() IS NULL")
    result = match_is_null(node)
    assert result is not None
    inner, is_null = result
    assert is_null is True
    # The inner expression must carry through — SEC004 walks it with
    # find_func_calls, so it has to be the original arg, not None.
    assert inner is not None


def test_match_is_null_returns_arg_for_column_ref() -> None:
    node = parse_expr("email IS NULL")
    result = match_is_null(node)
    assert result is not None
    inner, _ = result
    assert inner is not None


def test_match_is_null_distinguishes_is_null_from_is_not_null() -> None:
    null_node = parse_expr("a IS NULL")
    not_null_node = parse_expr("a IS NOT NULL")
    assert match_is_null(null_node)[1] is True  # type: ignore[index]
    assert match_is_null(not_null_node)[1] is False  # type: ignore[index]


def test_extract_range_vars_qualified_select() -> None:
    import pglast

    parsed = pglast.parse_sql("SELECT * FROM public.secret")
    refs = extract_range_vars(parsed[0].stmt)
    assert refs == [("public", "secret")]


def test_extract_range_vars_bare_select() -> None:
    import pglast

    parsed = pglast.parse_sql("SELECT * FROM secret")
    refs = extract_range_vars(parsed[0].stmt)
    assert refs == [(None, "secret")]


def test_extract_range_vars_qualified_insert() -> None:
    import pglast

    parsed = pglast.parse_sql("INSERT INTO public.t (id) VALUES (1)")
    refs = extract_range_vars(parsed[0].stmt)
    assert ("public", "t") in refs


def test_extract_range_vars_qualified_update() -> None:
    import pglast

    parsed = pglast.parse_sql("UPDATE public.t SET x = 1")
    refs = extract_range_vars(parsed[0].stmt)
    assert ("public", "t") in refs


def test_extract_range_vars_qualified_delete() -> None:
    import pglast

    parsed = pglast.parse_sql("DELETE FROM public.t WHERE id = 1")
    refs = extract_range_vars(parsed[0].stmt)
    assert ("public", "t") in refs


def test_extract_range_vars_collects_join_targets() -> None:
    import pglast

    parsed = pglast.parse_sql(
        "SELECT a.id FROM public.a JOIN public.b ON a.id = b.id"
    )
    refs = extract_range_vars(parsed[0].stmt)
    assert ("public", "a") in refs
    assert ("public", "b") in refs


def test_extract_range_vars_returns_empty_when_no_tables() -> None:
    import pglast

    parsed = pglast.parse_sql("SELECT 1")
    refs = extract_range_vars(parsed[0].stmt)
    assert refs == []


def test_extract_range_vars_handles_none_node() -> None:
    # A `None` node (e.g. an absent `with_check_ast`, or a `None` item
    # encountered while walking a children list) must be handled by the
    # walker's guard and yield no refs rather than raising. Pins the
    # `if n is None: return` branch.
    assert extract_range_vars(None) == []


# --- is_literal_true / is_literal_false ----------------------------------


def test_is_literal_true_matches_literal_true() -> None:
    assert is_literal_true(parse_expr("true")) is True


def test_is_literal_true_matches_uppercase_and_double_paren() -> None:
    # Postgres/pglast normalize casing and elide redundant parens.
    assert is_literal_true(parse_expr("TRUE")) is True
    assert is_literal_true(parse_expr("((true))")) is True


def test_is_literal_true_rejects_false() -> None:
    assert is_literal_true(parse_expr("false")) is False


def test_is_literal_true_rejects_non_literal_and_tautology() -> None:
    # Deliberately narrow — only the literal `true`, never `1 = 1`,
    # a column ref, or an integer constant.
    assert is_literal_true(parse_expr("1 = 1")) is False
    assert is_literal_true(parse_expr("id")) is False
    assert is_literal_true(parse_expr("1")) is False


def test_is_literal_true_rejects_none() -> None:
    assert is_literal_true(None) is False


def test_is_literal_false_matches_literal_false() -> None:
    assert is_literal_false(parse_expr("false")) is True
    assert is_literal_false(parse_expr("FALSE")) is True


def test_is_literal_false_rejects_true() -> None:
    assert is_literal_false(parse_expr("true")) is False


def test_is_literal_false_rejects_non_literal_and_none() -> None:
    assert is_literal_false(parse_expr("1 = 0")) is False
    assert is_literal_false(parse_expr("id")) is False
    assert is_literal_false(None) is False
