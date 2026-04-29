"""Common-case AST patterns for USING/WITH CHECK predicate diff.

Recognizes a small set of structural transformations:

  * unchanged           — identical after pglast canonicalization
  * tightened_and       — base AND new_clause (more conditions)
  * loosened_and_drop   — head AND dropped_clause (fewer conditions)
  * loosened_or         — base OR new_disjunct (more alternatives)
  * tightened_or_drop   — head OR dropped_disjunct (fewer alternatives)
  * requires_review     — anything else

Anything outside the table falls through to requires_review. The
v0.2 design defers SAT-style implication checking to v0.5+ — see
the design spec's non-goals section.
"""
from __future__ import annotations

from typing import Any, Literal

from pglast.ast import BoolExpr
from pglast.enums import BoolExprType
from pglast.stream import RawStream

from pgrls.ast_utils import parse_expr


def _and_clauses(node: Any) -> list[Any]:
    """Return the top-level AND conjuncts of `node`.

    If `node` is a BoolExpr(AND_EXPR), return its args list.
    Otherwise return a single-element list containing the node itself.
    """
    if isinstance(node, BoolExpr) and node.boolop == BoolExprType.AND_EXPR:
        return list(node.args or ())
    return [node]


def _or_clauses(node: Any) -> list[Any]:
    """Return the top-level OR disjuncts of `node`.

    If `node` is a BoolExpr(OR_EXPR), return its args list.
    Otherwise return a single-element list containing the node itself.
    """
    if isinstance(node, BoolExpr) and node.boolop == BoolExprType.OR_EXPR:
        return list(node.args or ())
    return [node]


def _canon(node: Any) -> str:
    """Canonicalize a pglast node to a stable SQL string via RawStream."""
    # `RawStream` is the canonical pglast renderer. pglast doesn't
    # ship type stubs, so mypy --strict sees `RawStream()` as
    # `Any`-typed and the call site as returning `Any` from a
    # `str`-declared function. The runtime contract is fine — every
    # RawStream call returns a str.
    rendered: str = RawStream()(node)  # type: ignore[no-untyped-call]
    return rendered


def compare_predicates(
    base_sql: str | None,
    head_sql: str | None,
    *,
    location: str | None = None,
    clause: str | None = None,
) -> Literal[
    "unchanged",
    "tightened_and",
    "loosened_and_drop",
    "loosened_or",
    "tightened_or_drop",
    "requires_review",
]:
    """Compare two SQL predicate strings and classify the structural change.

    Parameters
    ----------
    base_sql:
        The predicate SQL from the base schema (e.g. the deployed branch).
        Pass None or empty string to represent "no predicate".
    head_sql:
        The predicate SQL from the head schema (e.g. the feature branch).
        Pass None or empty string to represent "no predicate".
    location:
        Optional policy location string (e.g. ``"public.mytable.mypolicy"``).
        Forwarded to ``parse_expr`` so parse-failure warnings name the policy
        rather than emitting a generic ``could not parse SQL fragment`` message.
    clause:
        Optional clause label (e.g. ``"USING"`` or ``"WITH CHECK"``).
        Forwarded to ``parse_expr`` alongside ``location``.

    Returns
    -------
    One of the six classification literals described in the module docstring.
    """
    base_empty = not base_sql
    head_empty = not head_sql

    # Both absent — no change.
    if base_empty and head_empty:
        return "unchanged"

    # One side absent — predicate added or removed; needs manual review.
    if base_empty or head_empty:
        return "requires_review"

    # Both non-empty: attempt to parse. Pass a diff-context fail
    # message tail so a parse failure during `pgrls diff` doesn't
    # tell the user about SEC/PERF/HYG lint rules that don't run
    # during diff. The classification falls through to
    # requires_review (handled below) when either parse returns None.
    fail_tail = (
        "Diff falls back to REQUIRES_REVIEW for this predicate."
    )
    base_node = parse_expr(
        base_sql,
        location=location,
        clause=clause,
        fail_message_tail=fail_tail,
    )
    head_node = parse_expr(
        head_sql,
        location=location,
        clause=clause,
        fail_message_tail=fail_tail,
    )

    # Parse failure on either side — cannot classify structurally.
    if base_node is None or head_node is None:
        return "requires_review"

    # Canonicalize and compare.
    base_canon = _canon(base_node)
    head_canon = _canon(head_node)

    if base_canon == head_canon:
        return "unchanged"

    # AND patterns — build canonical-string sets of top-level conjuncts.
    base_and = {_canon(c) for c in _and_clauses(base_node)}
    head_and = {_canon(c) for c in _and_clauses(head_node)}

    if base_and < head_and and len(head_and) - len(base_and) == 1:
        return "tightened_and"

    if head_and < base_and and len(base_and) - len(head_and) == 1:
        return "loosened_and_drop"

    # OR patterns — build canonical-string sets of top-level disjuncts.
    base_or = {_canon(d) for d in _or_clauses(base_node)}
    head_or = {_canon(d) for d in _or_clauses(head_node)}

    if base_or < head_or and len(head_or) - len(base_or) == 1:
        return "loosened_or"

    if head_or < base_or and len(base_or) - len(head_or) == 1:
        return "tightened_or_drop"

    return "requires_review"
