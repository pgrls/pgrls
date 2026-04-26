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
