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
