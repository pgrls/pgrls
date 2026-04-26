"""Pure-function helpers over pglast trees.

Used by AST-based rules (SEC004, HYG001) and by introspection to populate
Policy.using_ast / Policy.with_check_ast.

This module is internal; no API stability promise yet. Plugin interface
stability is a v1.0 commitment per DESIGN §3.
"""
from __future__ import annotations

import sys
from typing import Any

import pglast
from pglast.ast import A_Star, BoolExpr, ColumnRef, Node, String, SubLink
from pglast.enums import BoolExprType


def parse_expr(sql: str | None) -> Any | None:
    """Parse a USING/WITH CHECK SQL fragment into a pglast AST node.

    Returns the expression node, or None if the input is empty or pglast
    cannot parse it. On parse failure, prints a one-line warning to stderr.
    """
    if not sql:
        return None
    wrapped = f"SELECT ({sql}) AS _expr"
    try:
        parsed = pglast.parse_sql(wrapped)
    except Exception:
        print(
            f"pgrls: warning: could not parse SQL fragment: {sql!r}",
            file=sys.stderr,
        )
        return None
    select_stmt = parsed[0].stmt
    target = select_stmt.targetList[0]
    return target.val


def top_level_disjuncts(node: Any) -> list[Any]:
    """If node is a top-level OR expression, return its disjunct children.

    Otherwise return a single-element list containing the node itself.
    """
    if isinstance(node, BoolExpr) and node.boolop == BoolExprType.OR_EXPR:
        return list(node.args or ())
    return [node]


def extract_column_refs(
    node: Any, *, exclude_sublinks: bool = False
) -> set[tuple[str, ...]]:
    """Walk the tree and return the set of ColumnRef name tuples.

    A column referenced as `email` produces `("email",)`. A qualified
    reference `users.email` produces `("users", "email")`. Wildcards (`*`)
    are skipped. When `exclude_sublinks=True`, refs inside SubLink nodes
    are not collected — used by HYG001 to avoid false positives on
    subquery columns from other tables.
    """
    refs: set[tuple[str, ...]] = set()

    def walk(n: Any) -> None:
        if n is None:
            return
        if exclude_sublinks and isinstance(n, SubLink):
            # Walk the test expression (e.g. `tenant_id` in `tenant_id IN (...)`)
            # but skip the inner subquery to avoid collecting refs from other tables.
            walk(n.testexpr)
            return
        if isinstance(n, ColumnRef):
            names: list[str] = []
            for f in n.fields or ():
                if isinstance(f, String):
                    names.append(f.sval)
                elif isinstance(f, A_Star):
                    return  # bail out — wildcard ref like t.* or *
            if names:
                refs.add(tuple(names))
            return
        if isinstance(n, Node):
            for field_name in n:
                value = getattr(n, field_name, None)
                if isinstance(value, (list, tuple)):
                    for item in value:
                        walk(item)
                elif isinstance(value, Node):
                    walk(value)

    walk(node)
    return refs
