"""Unit tests for AST helpers. Pure Python, no database."""
from __future__ import annotations

from pgrls.ast_utils import parse_expr


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


from pgrls.ast_utils import top_level_disjuncts


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


from pgrls.ast_utils import extract_column_refs


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


from pgrls.ast_utils import find_func_calls


def test_find_func_calls_matches_qualified_name() -> None:
    node = parse_expr("auth.uid() = '1'")
    matches = find_func_calls(node, {"auth.uid"})
    assert len(matches) == 1


def test_find_func_calls_matches_bare_name() -> None:
    node = parse_expr("current_setting('x') = '1'")
    matches = find_func_calls(node, {"current_setting"})
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


from pgrls.ast_utils import match_is_null


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
