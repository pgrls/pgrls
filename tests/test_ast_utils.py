"""Unit tests for AST helpers. Pure Python, no database."""
from __future__ import annotations

import pytest

from pgrls.ast_utils import (
    extract_column_refs,
    extract_range_vars,
    find_func_calls,
    is_literal_false,
    is_literal_true,
    match_is_null,
    parse_expr,
    subselect_is_correlated,
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


def test_parse_expr_returns_none_for_setop_escape(capsys) -> None:
    # A fragment whose own unbalanced parens let it escape the
    # `SELECT (...)` wrapper into a top-level set operation (here UNION)
    # parses to a SelectStmt whose targetList is None; parse_expr must
    # return None (with the standard warning) rather than raise
    # TypeError on `targetList[0]`. Regression for the diff / AST-rule
    # crash on a corrupted or hand-edited snapshot predicate.
    assert parse_expr("1) UNION SELECT (1") is None
    assert "could not parse" in capsys.readouterr().err.lower()


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


def _subselect_of(sql: str):
    # parse_expr on an `EXISTS (…)` / `x IN (…)` fragment returns a
    # SubLink whose `.subselect` is the inner SelectStmt.
    return parse_expr(sql).subselect


def test_subselect_is_correlated_true_for_outer_qualified_ref() -> None:
    # `m.t_id = t.id` references the outer table `t`, not in the
    # subselect's own FROM — correlated.
    assert subselect_is_correlated(
        _subselect_of(
            "EXISTS (SELECT 1 FROM members m "
            "WHERE m.user_id = auth.uid() AND m.t_id = t.id)"
        )
    ) is True


def test_subselect_is_correlated_false_for_self_contained() -> None:
    # Every ref resolves inside the subselect's own FROM — uncorrelated.
    assert subselect_is_correlated(
        _subselect_of(
            "EXISTS (SELECT 1 FROM admins a WHERE a.user_id = auth.uid())"
        )
    ) is False


def test_subselect_is_correlated_false_for_scalar_subquery() -> None:
    assert subselect_is_correlated(
        _subselect_of("user_id IN (SELECT auth.uid())")
    ) is False


def test_subselect_is_correlated_three_part_outer_ref() -> None:
    # A 3-part `schema.table.col` outer reference is correlated — the
    # table qualifier (`t`) is not bound in the subselect's own scope.
    # Pins the `s.t.col` claim in the docstring (Postgres emits this form
    # via pg_get_expr when the policy's schema-qualified table is the
    # correlated relation).
    assert subselect_is_correlated(
        _subselect_of(
            "EXISTS (SELECT 1 FROM members m "
            "WHERE m.t_id = public.t.id AND m.uid = auth.uid())"
        )
    ) is True


def test_subselect_is_correlated_aliased_relname_is_outer() -> None:
    # `FROM public.shares s2` binds ONLY `s2`; a later `shares.id` is an
    # OUTER reference, not a self-reference. Pins the alias rule the
    # corpus `sec004-is-null-in-subquery-safe` case relies on.
    assert subselect_is_correlated(
        _subselect_of(
            "EXISTS (SELECT 1 FROM public.shares s2 "
            "WHERE s2.id = shares.id)"
        )
    ) is True


def test_subselect_is_correlated_false_for_set_operation() -> None:
    # UNION arms each have their own FROM; conservatively uncorrelated.
    assert subselect_is_correlated(
        _subselect_of("id IN (SELECT a FROM x UNION SELECT b FROM y)")
    ) is False


def test_subselect_is_correlated_false_through_lateral_documented_limit() -> None:
    # DOCUMENTED LIMITATION: a correlation reaching the outer query only
    # THROUGH a LATERAL subquery in the FROM is conservatively NOT
    # detected — `RangeSubselect` subqueries aren't descended into. A
    # sound under-report (never a false positive), pinned so the
    # conservative behavior stays intentional. Rare shape; no corpus case.
    assert subselect_is_correlated(
        _subselect_of(
            "EXISTS (SELECT 1 FROM members m, "
            "LATERAL (SELECT auth.uid() AS u WHERE m.id = t.owner_id) s "
            "WHERE m.user_id = s.u)"
        )
    ) is False


def test_find_func_calls_descends_into_correlated_sublink_opt_in() -> None:
    node = parse_expr(
        "EXISTS (SELECT 1 FROM members m "
        "WHERE m.user_id = auth.uid() AND m.t_id = t.id)"
    )
    # Default: the correlated subselect is skipped.
    assert find_func_calls(node, {"auth.uid"}, exclude_sublinks=True) == []
    # Opt-in: the nested call is found.
    assert len(
        find_func_calls(
            node,
            {"auth.uid"},
            exclude_sublinks=True,
            descend_correlated_sublinks=True,
        )
    ) == 1


def test_find_func_calls_skips_uncorrelated_sublink_when_opted_in() -> None:
    node = parse_expr("user_id IN (SELECT auth.uid())")
    assert find_func_calls(
        node,
        {"auth.uid"},
        exclude_sublinks=True,
        descend_correlated_sublinks=True,
    ) == []


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


# --- BEGIN ATOMIC function bodies (MF8) ------------------------------------


def test_function_body_sql_unwraps_begin_atomic() -> None:
    # A SQL-standard `BEGIN ATOMIC … END` body (PG14+) lives PARSED in
    # `pg_proc.prosqlbody`; `prosrc` is empty and `pg_get_function_sqlbody`
    # deparses it back WITH the wrapper. pglast cannot parse that wrapper —
    # `BEGIN` is a transaction command in bare SQL — so every body-reading
    # caller caught the ParseError and analyzed nothing.
    import pglast

    from pgrls.ast_utils import function_body_sql

    body = "BEGIN ATOMIC\n SELECT id FROM docs LIMIT 5;\nEND"
    with pytest.raises(pglast.parser.ParseError):
        pglast.parse_sql(body)
    parsed = pglast.parse_sql(function_body_sql(body))
    assert [type(s.stmt).__name__ for s in parsed] == ["SelectStmt"]


def test_function_body_sql_leaves_other_bodies_alone() -> None:
    from pgrls.ast_utils import function_body_sql

    # A classic `AS $$ … $$` body has no wrapper.
    assert function_body_sql(" SELECT 1 ") == " SELECT 1 "
    # Only the TRAILING `END` is stripped, so an `END` closing a CASE survives.
    assert "CASE" in function_body_sql(
        "BEGIN ATOMIC SELECT CASE WHEN a THEN 1 ELSE 2 END; END"
    )
    # A plpgsql `BEGIN … END` block (no ATOMIC) is NOT a SQL-standard body and
    # must not be unwrapped — it is opaque to the parser either way.
    assert function_body_sql("BEGIN RETURN 1; END").startswith("BEGIN")
