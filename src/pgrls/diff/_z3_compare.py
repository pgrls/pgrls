"""SAT-based predicate implication via Z3 (Phases 1, 3, and 4).

Z3 is an optional dependency (``pip install pgrls[diff-z3]``). When
unavailable, ``Z3_AVAILABLE`` is False and ``classify_via_z3``
returns None — callers fall through to whatever existing syntactic
classifier they were using. ``compare_predicates`` (the public
entry point in ``ast_compare.py``) imports this module lazily so
the Z3 codepath can never break the lint / non-diff paths even if
``z3-solver`` is missing or fails to import. When Z3 is installed,
predicates that fall outside the syntactic patterns can be
re-checked via implication:

* ``base → head`` AND ``head → base``: predicates are semantically
  equivalent. Z3 says the row sets are identical even though the
  ASTs differ. Maps to ``"semantic_equivalent"`` (no Change).
* ``base → head`` AND NOT (``head → base``): head admits at least
  every row base admits, plus more. Head is strictly weaker —
  DANGEROUS. Maps to ``"semantic_loosened"``.
* ``head → base`` AND NOT (``base → head``): head admits at most the
  rows base admits, possibly fewer. Head is strictly stronger —
  SAFE. Maps to ``"semantic_tightened"``.
* Neither implication holds: predicates are incomparable. Maps to
  None — the caller falls through to ``requires_review``.

Implication is decided by checking unsatisfiability of the negation:
``base → head`` is valid iff ``base AND NOT head`` is UNSAT.

Phase 1 supports a deliberate subset of pglast nodes. Unsupported
nodes return None from the translator, which propagates up to
``classify_via_z3`` returning None.

Phase 3 (v0.4.1) extended the supported set with function calls
(modeled as uninterpreted Z3 constants keyed by canonical shape so
the same call in base and head reuses the same Z3 variable),
``COALESCE`` and ``CASE`` (treated opaquely the same way), and
``BETWEEN`` (translated to the equivalent AND-of-comparisons).

Phase 4 (v0.4.2) adds ``TypeCast`` (e.g. ``'a'::text``,
``col::int``) — supported when the cast target's Z3 sort matches
the inner expression's sort, otherwise opaque — and basic
arithmetic operators (``+``, ``-``, ``*``, ``/``, ``%``) for Int
and Real operands.

Supported AST nodes (Phases 1 + 3 + 4):

* ``ColumnRef`` — single-table column references resolve to Z3
  free variables. Type is inferred from comparison context (Int
  if compared to integer literal, String otherwise). Repeated
  references to the same column reuse the same Z3 variable.
* ``A_Const`` — Integer, String, Float, Boolean. Float is approximated
  as Real.
* ``A_Expr`` with comparison operators (``=``, ``!=``, ``<``, ``>``,
  ``<=``, ``>=``) — translated to the matching Z3 comparison.
* ``A_Expr`` with ``IN`` (literal RHS list) — translated to
  Or-of-equalities. Non-literal RHS (subquery) → unsupported.
* ``BoolExpr`` (AND, OR, NOT) — translated to ``z3.And``, ``z3.Or``,
  ``z3.Not``.
* ``NullTest`` (IS NULL, IS NOT NULL) — modeled as opaque Z3
  Booleans (``is_null_<col>``). Sound but coarse: comparisons are
  not constrained to be non-null, so 3VL nuances may produce
  inconclusive results in either direction. The caller falls
  through to ``requires_review`` rather than misclassifying.
* ``A_Expr`` with ``BETWEEN`` / ``NOT BETWEEN`` (Phase 3) —
  translated to the equivalent AND/OR of inequalities. Symmetric
  variants (``BETWEEN SYMMETRIC``) currently abort.
* ``FuncCall`` (Phase 3) — translated to a fresh Z3 String constant
  keyed by ``<funcname>(<canonical-args>)``. Repeated identical
  calls reuse the same Z3 variable across base and head, so two
  predicates that reference the same function call (e.g.
  ``auth.uid()``, ``current_setting('app.tenant')``) can be
  compared via implication. Aggregates and window functions abort.
* ``CoalesceExpr`` and ``CaseExpr`` (Phase 3) — treated as opaque
  uninterpreted Z3 String constants, keyed by their canonical
  RawStream rendering. Two predicates with ``COALESCE(col, 'x')``
  on each side reuse the same Z3 variable; nuanced reasoning about
  the WHEN/ELSE branches is deferred to a later phase. Sound but
  coarse: predicates that differ only inside the COALESCE/CASE
  fall through to ``requires_review`` because the canonical strings
  differ and Z3 sees two unrelated free variables.
* ``TypeCast`` (Phase 4) — ``'a'::text``, ``col::int`` etc. The
  target type name (last segment of ``pg_catalog.<type>``-style
  qualified names) is mapped to a Z3 sort via a small table:
  ``text``/``varchar``/``uuid`` → String, ``int``/``bigint`` → Int,
  ``numeric``/``float`` → Real, ``bool`` → Bool. When the resolved
  sort matches the inner expression's sort, the cast is a no-op
  and the inner translation is returned; otherwise the cast is
  treated as opaque (keyed by its full canonical rendering, so
  identical casts on base and head reuse the same Z3 variable).
* ``A_Expr(AEXPR_OP)`` with arithmetic operators (Phase 4) —
  ``+``, ``-``, ``*``, ``/``, ``%``. Translated to the matching
  Z3 op. Type inference flows through the non-column operand,
  same as comparisons. ``col + col`` two-column arithmetic
  defaults both columns to String for type-inference reasons,
  which Z3 then refuses, so the translator falls through to None
  for that shape — fine in practice because real RLS predicates
  use ``col + literal``, not ``col + col``.

Type unification per column: the first comparison fixes the type.
A subsequent reference with a conflicting type (e.g. ``col = 5``
then ``col = 'foo'``) returns None from the translator (unsound to
proceed). Real RLS predicates don't mix types on the same column,
so this is a defensive guardrail rather than a real limitation.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

try:
    import z3

    Z3_AVAILABLE = True
except ImportError:  # pragma: no cover — exercised by the no-z3 install path
    Z3_AVAILABLE = False
    z3 = None  # noqa: F811  # rebind to None when import failed

from pglast.ast import (
    A_Const,
    A_Expr,
    Boolean,
    BoolExpr,
    CaseExpr,
    CoalesceExpr,
    ColumnRef,
    Float,
    FuncCall,
    Integer,
    NullTest,
    ResTarget,
    SelectStmt,
    SQLValueFunction,
    String,
    SubLink,
    TypeCast,
)
from pglast.enums import (
    A_Expr_Kind,
    BoolExprType,
    NullTestType,
    SQLValueFunctionOp,
    SubLinkType,
)
from pglast.stream import RawStream

from pgrls.ast_utils import func_name_parts


# Comparison operator strings appearing in `A_Expr.name[0].sval` for
# the supported subset. Each maps to a Z3 lambda the translator
# applies to the (left, right) pair. Equality and inequality work
# across all supported types; ordered comparisons (`<`, `>`, etc.)
# work for Int and Real but not Bool — we defer the type check to
# Z3 itself, which raises if the operands' sorts disagree.
_COMPARISON_OPS: dict[str, Any] = {
    "=":  lambda a, b: a == b,
    "!=": lambda a, b: a != b,
    "<>": lambda a, b: a != b,
    "<":  lambda a, b: a < b,
    ">":  lambda a, b: a > b,
    "<=": lambda a, b: a <= b,
    ">=": lambda a, b: a >= b,
}

# Phase 4 — arithmetic operators. The Z3 ExprRef class overloads
# the Python operators, so the lambdas just produce the
# corresponding z3.ArithRef expressions when both operands are
# Int or Real. Z3 raises Z3Exception if the operands' sorts don't
# support arithmetic (e.g. String); the caller catches and
# returns None.
_ARITHMETIC_OPS: dict[str, Any] = {
    "+": lambda a, b: a + b,
    "-": lambda a, b: a - b,
    "*": lambda a, b: a * b,
    "/": lambda a, b: a / b,
    "%": lambda a, b: a % b,
}

# Postgres type-name (last segment of `pg_catalog.<type>`-style
# qualified names) → Z3 sort, for Phase 4 TypeCast resolution.
# Coarse on purpose: numeric / decimal collapse to Real, the
# integer variants collapse to Int, character variants collapse
# to String. Casts to a target NOT in this table fall through to
# the opaque-variable codepath.
_STRING_TYPES = frozenset({
    "text", "varchar", "char", "character", "bpchar", "uuid",
    "name", "citext",
})
_INT_TYPES = frozenset({
    "int", "int2", "int4", "int8", "integer", "smallint",
    "bigint", "oid",
})
_REAL_TYPES = frozenset({
    "float4", "float8", "real", "double", "numeric", "decimal",
})
_BOOL_TYPES = frozenset({"bool", "boolean"})


class _Context:
    """Shared variable + type-inference context across base and head.

    `base` and `head` predicates referring to the same column must
    map to the same Z3 free variable so the implication query is
    meaningful. `_Context` tracks the variable and its inferred
    Z3 sort, refusing to re-bind a column to a conflicting sort.
    """

    def __init__(self) -> None:
        self._vars: dict[str, Any] = {}  # column-key → z3.ExprRef
        self._null_vars: dict[str, Any] = {}  # column-key → z3.BoolRef
        # Phase 3 — opaque expressions (function calls,
        # COALESCE, CASE) keyed by their canonical-string shape.
        # Same key on both sides of the diff yields the same Z3
        # variable, enabling implication checks across predicates
        # that reference identical opaque expressions.
        self._opaque_vars: dict[str, Any] = {}
        # H2 (SEC038) — Kleene three-valued null-flags, keyed per
        # column / opaque-expr. SEPARATE namespace + dict from
        # `_null_vars` (the 2-valued path's disconnected marker) so the
        # diff path stays byte-for-byte untouched. Decl names are
        # prefixed `_nullflag__` and never land in `_vars`, so
        # `is_real_column` excludes them and `_decode_model` drops them
        # from the witness exactly like `_isnull__*` / `_opaque__*`.
        self._nullflag_vars: dict[str, Any] = {}

    def column(self, key: str, sort: Any) -> Any:
        """Return the Z3 variable for `key`, binding it on first use.

        On a subsequent call with a different `sort`, returns None to
        signal a type-conflict abort.
        """
        existing = self._vars.get(key)
        if existing is None:
            var = z3.Const(key, sort)
            self._vars[key] = var
            return var
        if existing.sort() == sort:
            return existing
        return None  # type conflict — translation aborts

    def null_marker(self, key: str) -> Any:
        """Return the Z3 Bool for `<col> IS NULL` opaque marker."""
        existing = self._null_vars.get(key)
        if existing is None:
            existing = z3.Bool(f"_isnull__{key}")
            self._null_vars[key] = existing
        return existing

    def opaque(self, key: str, sort: Any) -> Any:
        """Return a Z3 free variable for an opaque expression keyed by
        its canonical shape. Bound to ``sort`` on first use; subsequent
        calls with a different sort return None (type-conflict abort).
        """
        existing = self._opaque_vars.get(key)
        if existing is None:
            var = z3.Const(f"_opaque__{key}", sort)
            self._opaque_vars[key] = var
            return var
        if existing.sort() == sort:
            return existing
        return None

    def null_flag(self, key: str) -> Any:
        """Free Kleene null-flag (a Z3 Bool) for the value keyed by ``key``.

        H2 (SEC038) only. A separate namespace + dict from
        ``null_marker`` (the 2-valued diff path's disconnected marker),
        so the diff path is untouched. The decl name is prefixed
        ``_nullflag__`` and the var never enters ``_vars``, so
        ``is_real_column`` returns False for it and ``_decode_model``
        drops it from the witness — keeping the emitted row real-columns
        only, exactly like ``_isnull__*`` / ``_opaque__*``.
        """
        existing = self._nullflag_vars.get(key)
        if existing is None:
            existing = z3.Bool(f"_nullflag__{key}")
            self._nullflag_vars[key] = existing
        return existing

    def is_real_column(self, name: str) -> bool:
        """True iff `name` is a real column var (not a null/opaque marker).

        `column()` binds via ``z3.Const(key, sort)`` (the var's decl name
        is exactly ``key``), whereas ``null_marker`` / ``opaque`` prefix
        their decl names with ``_isnull__`` / ``_opaque__`` and live in
        the separate ``_null_vars`` / ``_opaque_vars`` dicts. So a model
        decl whose name is a key of ``_vars`` is authoritatively a real
        column; everything else is a synthetic marker. Preferred over
        prefix-string matching, which a user column literally named
        ``_isnull__x`` could otherwise spoof.
        """
        return name in self._vars


def _column_key(node: ColumnRef) -> str:
    """Render `ColumnRef.fields` as a `.`-joined identifier key.

    A column reference's `fields` is a tuple of `String` nodes (or
    `A_Star` for wildcards, which we don't support). Returns None
    for unsupported shapes.
    """
    parts = []
    for field in node.fields or ():
        if isinstance(field, String):
            parts.append(field.sval)
        else:
            return ""  # unsupported (e.g., A_Star)
    return ".".join(parts)


def _const_to_z3(node: A_Const) -> Any:
    """Translate an A_Const literal to a Z3 expression. Returns None for unsupported."""
    val = node.val
    if isinstance(val, Integer):
        return z3.IntVal(val.ival)
    if isinstance(val, String):
        return z3.StringVal(val.sval)
    if isinstance(val, Boolean):
        return z3.BoolVal(val.boolval)
    if isinstance(val, Float):
        # pglast keeps Float values as a string; parse to Python float.
        try:
            return z3.RealVal(float(val.fval))
        except (ValueError, TypeError):
            return None
    # Anything else (NULL literal, BitString, etc.) — out of scope.
    # In particular, `col = NULL` is always-false in Postgres but
    # users express that with `IS NULL` instead; if we see a literal
    # NULL on either side of a comparison, return None and let the
    # caller fall through to requires_review.
    return None


def _infer_sort(node: Any) -> Any:
    """Infer a Z3 sort from a literal or expression. Returns None if unknown."""
    if isinstance(node, A_Const):
        val = node.val
        if isinstance(val, Integer):
            return z3.IntSort()
        if isinstance(val, String):
            return z3.StringSort()
        if isinstance(val, Boolean):
            return z3.BoolSort()
        if isinstance(val, Float):
            return z3.RealSort()
    return None


def _to_z3(node: Any, ctx: _Context) -> Any:
    """Translate a pglast AST node to a Z3 expression.

    Returns None for unsupported nodes — the caller propagates None
    upward, ultimately producing None from `classify_via_z3` which
    causes `compare_predicates` to fall through to requires_review.
    """
    # Boolean connectives.
    if isinstance(node, BoolExpr):
        args = [_to_z3(a, ctx) for a in (node.args or ())]
        if any(a is None for a in args):
            return None
        if node.boolop == BoolExprType.AND_EXPR:
            return z3.And(*args) if len(args) >= 2 else (args[0] if args else None)
        if node.boolop == BoolExprType.OR_EXPR:
            return z3.Or(*args) if len(args) >= 2 else (args[0] if args else None)
        if node.boolop == BoolExprType.NOT_EXPR:
            if len(args) != 1:
                return None
            return z3.Not(args[0])
        return None

    # NULL tests — opaque Bool markers; not related to comparison
    # variables in Phase 1. See module docstring for the trade-off.
    if isinstance(node, NullTest):
        if not isinstance(node.arg, ColumnRef):
            # IS NULL on an arbitrary expression — out of scope.
            return None
        key = _column_key(node.arg)
        if not key:
            return None
        marker = ctx.null_marker(key)
        if node.nulltesttype == NullTestType.IS_NULL:
            return marker
        if node.nulltesttype == NullTestType.IS_NOT_NULL:
            return z3.Not(marker)
        return None

    # Comparison expressions.
    if isinstance(node, A_Expr):
        # Only handle the simple AOP_OP / IN / BETWEEN kinds.
        if node.kind == A_Expr_Kind.AEXPR_OP:
            return _binop_to_z3(node, ctx)
        if node.kind == A_Expr_Kind.AEXPR_IN:
            return _in_to_z3(node, ctx)
        if node.kind == A_Expr_Kind.AEXPR_BETWEEN:
            return _between_to_z3(node, ctx, negate=False)
        if node.kind == A_Expr_Kind.AEXPR_NOT_BETWEEN:
            return _between_to_z3(node, ctx, negate=True)
        return None

    # Phase 3 — function calls, COALESCE, CASE: each becomes an
    # opaque Z3 variable keyed by canonical shape.
    if isinstance(node, FuncCall):
        return _func_call_to_z3(node, ctx)
    if isinstance(node, (CoalesceExpr, CaseExpr)):
        return _opaque_expression(node, ctx, sort=z3.StringSort())

    # Phase 4 — TypeCast. Resolve the target type to a Z3 sort and,
    # if it matches the inner expression's sort, return the inner
    # translation unchanged (the cast is a no-op for our purposes).
    # Otherwise the cast is opaque, keyed by canonical rendering.
    if isinstance(node, TypeCast):
        return _type_cast_to_z3(node, ctx)

    # Bare ColumnRef appearing as a Boolean (e.g. `WHERE is_admin`).
    if isinstance(node, ColumnRef):
        key = _column_key(node)
        if not key:
            return None
        var = ctx.column(key, z3.BoolSort())
        return var

    # Bare A_Const Boolean (true / false).
    if isinstance(node, A_Const):
        return _const_to_z3(node)

    return None


def _binop_to_z3(node: A_Expr, ctx: _Context) -> Any:
    """Translate `A_Expr(AEXPR_OP)` — a binary comparison or arithmetic op.

    Either side may be a ColumnRef, A_Const, or any other supported
    node (FuncCall in Phase 3, COALESCE/CASE in Phase 3, TypeCast
    in Phase 4). Type inference for a bare ColumnRef on one side
    reads the sort of the other side's translation. Arithmetic
    operators (Phase 4: ``+``, ``-``, ``*``, ``/``, ``%``) produce
    a Z3 ArithRef; comparisons produce a Z3 BoolRef.
    """
    # `node.name` is a tuple-of-String per pglast; exact length is
    # operator-dependent (`OPERATOR(schema.+)` shapes can be 2-tuples).
    # Phase 1+ only handles single-name operators.
    op_names = list(node.name or ())
    if len(op_names) != 1 or not isinstance(op_names[0], String):
        return None
    op = op_names[0].sval
    op_fn = _COMPARISON_OPS.get(op) or _ARITHMETIC_OPS.get(op)
    if op_fn is None:
        return None  # unsupported operator

    lhs, rhs = _resolve_binop_operands(node.lexpr, node.rexpr, ctx)
    if lhs is None or rhs is None:
        return None
    try:
        return op_fn(lhs, rhs)
    except z3.Z3Exception:
        return None


def _resolve_binop_operands(
    lexpr: Any, rexpr: Any, ctx: _Context
) -> tuple[Any, Any]:
    """Translate both sides of a binary comparison, inferring column
    types from the other side when one side is a bare ColumnRef.

    Returns ``(None, None)`` on any unsupported / type-conflict path.
    """
    l_is_col = isinstance(lexpr, ColumnRef)
    r_is_col = isinstance(rexpr, ColumnRef)

    if l_is_col and not r_is_col:
        rhs = _to_z3(rexpr, ctx)
        if rhs is None:
            return (None, None)
        lhs = _bind_column(lexpr, rhs.sort(), ctx)
        return (lhs, rhs)
    if r_is_col and not l_is_col:
        lhs = _to_z3(lexpr, ctx)
        if lhs is None:
            return (None, None)
        rhs = _bind_column(rexpr, lhs.sort(), ctx)
        return (lhs, rhs)
    if l_is_col and r_is_col:
        # `col OP col`: bind both sides as String by default — pglast
        # introspection can't tell us the actual Postgres type. Z3
        # equality across mismatched sorts would raise; defaulting to
        # String works for the common UUID-vs-UUID and text-vs-text
        # shapes. Two String columns compared with `<` will succeed
        # (Z3 strings have lex order); Int-vs-Int comparisons need a
        # prior literal context that we don't have here.
        lhs = _bind_column(lexpr, z3.StringSort(), ctx)
        rhs = _bind_column(rexpr, z3.StringSort(), ctx)
        return (lhs, rhs)
    # Neither side is a column — translate generically.
    return (_to_z3(lexpr, ctx), _to_z3(rexpr, ctx))


def _bind_column(node: ColumnRef, sort: Any, ctx: _Context) -> Any:
    """Bind ``node`` to a Z3 free variable of ``sort``."""
    key = _column_key(node)
    if not key:
        return None
    return ctx.column(key, sort)


def _type_cast_to_z3(node: TypeCast, ctx: _Context) -> Any:
    """Translate ``<expr>::<type>`` (Phase 4).

    Strategy:

    * Resolve the target type to a Z3 sort. If unknown, the cast is
      opaque (keyed by full canonical rendering).
    * Translate the inner expression. If it failed (None), abort
      and produce an opaque variable for the whole cast — that way
      ``COALESCE(...)::text`` on both sides is still comparable
      via canonical-string keying even though the inner COALESCE
      itself is opaque.
    * If the inner expression's sort matches the target sort, return
      the inner translation unchanged (the cast is a no-op for
      Z3's purposes — e.g. ``int8 → integer`` both resolve to Int).
    * Otherwise, the cast is sort-changing (e.g. ``Int → Text`` for
      ``id::text``); model as opaque so an identical cast on the
      other side reuses the same Z3 variable.
    """
    target_sort = _typename_segments_to_sort(node.typeName)
    inner = _to_z3(node.arg, ctx)

    if target_sort is None:
        # Unknown target type — fall back to opaque, keyed by the
        # whole cast's canonical form so identical casts collapse.
        return _opaque_expression(node, ctx, sort=z3.StringSort())

    if inner is None:
        # Inner expression unsupported — opaque the whole cast,
        # under the target sort so subsequent comparisons can match.
        return _opaque_expression(node, ctx, sort=target_sort)

    inner_sort = inner.sort()
    if inner_sort == target_sort:
        # Cast is a no-op at the Z3 level (e.g. `'a'::text` where
        # the inner is already a Z3 String).
        return inner

    # Sort-changing cast (`id::text`, `created_at::date`). Model as
    # opaque under the target sort so identical casts on both sides
    # collapse to the same Z3 variable.
    return _opaque_expression(node, ctx, sort=target_sort)


def _typename_segments_to_sort(typename: Any) -> Any:
    """Resolve a pglast ``TypeName`` to a Z3 sort, or None."""
    if typename is None:
        return None
    segments = typename.names or ()
    if not segments:
        return None
    last = segments[-1]
    if not isinstance(last, String):
        return None
    name = last.sval.lower()
    if name in _STRING_TYPES:
        return z3.StringSort()
    if name in _INT_TYPES:
        return z3.IntSort()
    if name in _REAL_TYPES:
        return z3.RealSort()
    if name in _BOOL_TYPES:
        return z3.BoolSort()
    return None


def _between_to_z3(node: A_Expr, ctx: _Context, *, negate: bool) -> Any:
    """`<expr> BETWEEN <lo> AND <hi>` ⇒ ``lo <= expr AND expr <= hi``.

    pglast represents BETWEEN as ``A_Expr(kind=AEXPR_BETWEEN,
    lexpr=<expr>, rexpr=[<lo>, <hi>])``. NOT BETWEEN is the same
    shape with ``kind=AEXPR_NOT_BETWEEN``; translates as the
    ``Not(...)`` of the same body.

    Built from two ``_resolve_binop_operands`` calls so that bare
    ColumnRef on the lexpr side gets typed by the lo/hi literals
    (otherwise the column would default to Bool sort and the Int
    comparisons would silently coerce via ``If(x, 1, 0)``).

    Symmetric variants (``BETWEEN SYMMETRIC``) use
    ``AEXPR_BETWEEN_SYM`` / ``AEXPR_NOT_BETWEEN_SYM`` and abort
    here — supporting them needs ``min(lo, hi) <= expr AND expr <=
    max(lo, hi)`` which Z3 can express but the translation is
    non-trivial; deferred until a real RLS predicate uses it.
    """
    lexpr = node.lexpr
    rexpr_list = node.rexpr
    if not isinstance(rexpr_list, (list, tuple)) or len(rexpr_list) != 2:
        return None
    lo, hi = rexpr_list

    # `lo <= expr` (sorted as `_resolve_binop_operands(lo, expr)`)
    lo_z3, expr_z3_low = _resolve_binop_operands(lo, lexpr, ctx)
    if lo_z3 is None or expr_z3_low is None:
        return None
    # `expr <= hi`
    expr_z3_high, hi_z3 = _resolve_binop_operands(lexpr, hi, ctx)
    if expr_z3_high is None or hi_z3 is None:
        return None

    try:
        body = z3.And(lo_z3 <= expr_z3_low, expr_z3_high <= hi_z3)
    except z3.Z3Exception:
        return None
    return z3.Not(body) if negate else body


def _func_call_to_z3(node: FuncCall, ctx: _Context) -> Any:
    """Translate a function call to an opaque Z3 String constant.

    The call is keyed by ``<funcname>(<canonical-args>)`` so the
    same call on base and head sides yields the same Z3 variable.
    Aggregates, window functions, and DISTINCT-aggregates abort —
    those don't appear in RLS predicates.

    Args may be literals, ColumnRefs, or other supported nodes;
    each must translate via ``_to_z3`` (which is itself recursive).
    The argument list is canonicalized via RawStream so cosmetic
    differences (whitespace, redundant parens) collapse. Two calls
    that differ only in canonical arg ordering are NOT considered
    equal — RawStream preserves source order.
    """
    if node.agg_filter is not None:
        return None  # FILTER (WHERE ...) — out of scope
    if node.agg_within_group:
        return None  # WITHIN GROUP (ORDER BY ...) — out of scope
    if node.over is not None:
        return None  # window function — out of scope
    if node.agg_star:
        return None  # `count(*)` etc. — out of scope
    funcname_parts = node.funcname or ()
    if not all(isinstance(part, String) for part in funcname_parts):
        return None
    func_name = ".".join(p.sval for p in funcname_parts)
    if not func_name:
        return None

    # Sanity-check args translate. We don't actually consume the
    # translated Z3 expressions here — the function call is opaque
    # — but if any argument is unsupported, abort upward so we
    # don't synthesize a misleading Z3 variable for an unparseable
    # signature.
    for arg in (node.args or ()):
        if _to_z3(arg, ctx) is None:
            return None

    # Use the syntactic canonical rendering as the cache key. Two
    # base/head predicates that reference the exact same call (e.g.
    # `current_setting('app.tenant')`) get the same Z3 variable.
    key = _canon(node)
    return ctx.opaque(key, z3.StringSort())


def _opaque_expression(node: Any, ctx: _Context, *, sort: Any) -> Any:
    """Generic opaque-Z3-variable wrapper for nodes whose semantics
    Phase 3 doesn't fully model (currently CoalesceExpr, CaseExpr).

    Two identical RawStream renderings on base and head produce the
    same Z3 variable, so predicates like ``COALESCE(col, 'default')
    = 'foo'`` are comparable across base and head when they appear
    verbatim. Predicates whose CASE/COALESCE bodies differ get
    different variables and Z3 reports them as incomparable
    (caller falls through to ``requires_review``).
    """
    key = _canon(node)
    return ctx.opaque(key, sort)


def _canon(node: Any) -> str:
    """Canonical RawStream rendering of an AST node."""
    rendered: str = RawStream()(node)
    return rendered


def _in_to_z3(node: A_Expr, ctx: _Context) -> Any:
    """Translate `<col> IN (literal, literal, ...)` to Or-of-equalities.

    pglast represents `IN` as `A_Expr(kind=AEXPR_IN, name=[String('=')],
    lexpr=<col>, rexpr=<list of A_Const>)`. A subquery RHS lands in a
    different kind — unsupported in Phase 1.
    """
    lexpr = node.lexpr
    if not isinstance(lexpr, ColumnRef):
        return None
    rexpr = node.rexpr
    if not isinstance(rexpr, (list, tuple)):
        return None
    if not all(isinstance(item, A_Const) for item in rexpr):
        return None
    if not rexpr:
        return z3.BoolVal(False)  # empty IN list — never matches
    # Use the first literal's sort to bind the column.
    first_sort = _infer_sort(rexpr[0])
    if first_sort is None:
        return None
    key = _column_key(lexpr)
    if not key:
        return None
    var = ctx.column(key, first_sort)
    if var is None:
        return None
    eqs = []
    for item in rexpr:
        v = _const_to_z3(item)
        if v is None:
            return None
        try:
            eqs.append(var == v)
        except z3.Z3Exception:
            return None
    return z3.Or(*eqs) if len(eqs) >= 2 else eqs[0]


_Z3Result = Literal["semantic_equivalent", "semantic_tightened", "semantic_loosened"]


def classify_via_z3(base_node: Any, head_node: Any) -> _Z3Result | None:
    """Classify a base/head predicate pair using Z3 implication.

    Returns:

    * ``"semantic_equivalent"`` — Z3 proves both implications.
      No Change should be emitted.
    * ``"semantic_tightened"`` — Z3 proves head → base only. Head is
      strictly more restrictive (SAFE).
    * ``"semantic_loosened"`` — Z3 proves base → head only. Head is
      strictly more permissive (DANGEROUS).
    * ``None`` — Z3 is unavailable, the translator hit an unsupported
      node, or neither implication holds (incomparable). Caller falls
      through to ``requires_review``.

    The pair MUST share a single ``_Context`` so column references
    resolve to the same Z3 variables in both predicates.
    """
    if not Z3_AVAILABLE:
        return None
    ctx = _Context()
    base_z3 = _to_z3(base_node, ctx)
    head_z3 = _to_z3(head_node, ctx)
    if base_z3 is None or head_z3 is None:
        return None

    # Implication check: `P → Q` is valid iff `P AND NOT Q` is UNSAT.
    base_implies_head = _implies(base_z3, head_z3)
    head_implies_base = _implies(head_z3, base_z3)

    if base_implies_head and head_implies_base:
        return "semantic_equivalent"
    if head_implies_base and not base_implies_head:
        return "semantic_tightened"
    if base_implies_head and not head_implies_base:
        return "semantic_loosened"
    return None


def _implies(p: Any, q: Any) -> bool:
    """Return True iff `p → q` is valid (i.e. `p AND NOT q` is UNSAT)."""
    solver = z3.Solver()
    # Bound the search: real-world RLS predicates resolve in
    # milliseconds, but a pathologically constructed predicate with
    # deep quantifier alternation could otherwise hang. 1 second is
    # comfortable for the supported subset.
    solver.set("timeout", 1000)
    solver.add(z3.And(p, z3.Not(q)))
    result = solver.check()
    # `unsat` ⇒ no counterexample exists ⇒ implication holds.
    # `sat` ⇒ a counterexample was found ⇒ implication fails.
    # `unknown` ⇒ solver gave up (timeout, etc.) ⇒ treat as fails
    # so we don't claim implication we couldn't verify.
    return bool(result == z3.unsat)


def _decode_model(model: Any, ctx: _Context) -> dict[str, object]:
    """Render a Z3 model into ``{column_key: python_value}``.

    Keeps only real columns (``ctx.is_real_column``) — synthetic
    ``_isnull__*`` / ``_opaque__*`` markers are dropped — and decodes
    each value by its Z3 sort, one-to-one with the constructors in
    ``_const_to_z3`` (Int → ``as_long``, String → ``as_string``,
    Bool → ``z3.is_true``, Real → ``float(as_fraction())``). Any other
    sort is omitted (defensive). ``model.decls()`` yields only the
    constants Z3 actually assigned; a don't-care column is simply
    absent and is never fabricated.
    """
    row: dict[str, object] = {}
    for decl in model.decls():
        name = decl.name()
        if not ctx.is_real_column(name):
            continue  # skip _isnull__ / _opaque__ synthetic vars
        value = model[decl]
        sort = value.sort()
        if sort == z3.IntSort():
            row[name] = value.as_long()
        elif sort == z3.StringSort():
            row[name] = value.as_string()
        elif sort == z3.BoolSort():
            row[name] = z3.is_true(value)
        elif sort == z3.RealSort():
            row[name] = float(value.as_fraction())
        # any other sort: omit (defensive)
    return row


def _row_is_sufficient_witness(
    row: dict[str, object], base_z3: Any, head_z3: Any, ctx: _Context
) -> bool:
    """True iff pinning `row`'s columns forces ``head ∧ ¬base`` for ALL
    completions of the free (synthetic / unpinned) variables.

    A Z3 model of ``head ∧ ¬base`` is a *full* assignment; the
    real-column projection ``row`` we return drops every synthetic
    (``_isnull__*`` / ``_opaque__*``) var. A projection is NOT in
    general a satisfying assignment — e.g. for ``active = true`` vs
    ``active = true OR deleted_at IS NULL`` the model is
    ``{active=False, _isnull__deleted_at=True}`` but ``{active=False}``
    alone does not leak (it needs ``deleted_at IS NULL``). Emitting
    ``{active=False}`` would be unsound.

    Soundness gate: the row is a genuine, self-sufficient witness iff
    ``(pins) ∧ ¬(head ∧ ¬base)`` is UNSAT — i.e. there is no completion
    of the unpinned variables under which the pinned row fails to leak.
    Only then does every row matching ``row`` (for any value of the
    columns/markers we did not pin) lie inside HEAD \\ BASE. We rebuild
    the pins against the SAME ``ctx`` used to build ``base_z3`` /
    ``head_z3`` so each pinned ``z3.Const(key, sort)`` is identical to
    the variable already inside the formulas.
    """
    pins = []
    for key, val in row.items():
        var = ctx.column(key, _py_value_sort(val))
        if var is None:
            # Sort clash against the bound var — cannot honestly pin
            # this value, so we cannot prove sufficiency. Bail safe.
            return False
        pins.append(var == val)
    solver = z3.Solver()
    solver.set("timeout", 1000)
    pinned = z3.And(*pins) if len(pins) >= 2 else (pins[0] if pins else z3.BoolVal(True))
    solver.add(z3.And(pinned, z3.Not(z3.And(head_z3, z3.Not(base_z3)))))
    # UNSAT ⇒ no completion escapes head ∧ ¬base ⇒ row is sufficient.
    return bool(solver.check() == z3.unsat)


def _py_value_sort(val: object) -> Any:
    """Z3 sort for a decoded Python value, mirroring ``_decode_model``.

    ``bool`` is checked BEFORE ``int`` because ``isinstance(True, int)``
    is True in Python — a Bool column value would otherwise bind to
    ``IntSort`` and clash with the real BoolSort var inside the
    formula. ``float`` (a decoded Real) → ``RealSort``.
    """
    if isinstance(val, bool):
        return z3.BoolSort()
    if isinstance(val, int):
        return z3.IntSort()
    if isinstance(val, float):
        return z3.RealSort()
    return z3.StringSort()


def counterexample(base_node: Any, head_node: Any) -> dict[str, object] | None:
    """Return a concrete leaking row for a loosened predicate change, or None.

    The returned dict maps real column keys → decoded Python values. By
    construction (see the soundness gate below) every row matching the
    returned columns is admitted by HEAD and rejected by BASE — a row
    the new policy newly leaks relative to the old one.

    Returns None when:

    * Z3 is unavailable;
    * either predicate fails to translate (unsupported node / type clash);
    * ``head ∧ ¬base`` is UNSAT — the head admits no row the base rejected
      (an equivalent or tightened change); or
    * the real-column projection of the model is not a *self-sufficient*
      witness — the leak depends on a NULL test or an opaque
      (function / GUC / COALESCE / CASE) value that the column-only row
      cannot honestly express. In that case we emit NO counterexample
      (degrade to the label-only DANGEROUS verdict) rather than a row
      that does not actually leak. Soundness over cleverness.

    Whenever ``head ∧ ¬base`` is SAT and witnessable, the returned row is a
    sound member of HEAD ∖ BASE — this also holds for the *incomparable*
    case (head and base each admit rows the other rejects), which is NOT a
    None condition. pgrls invokes this only on the ``"semantic_loosened"``
    verdict, where the change is a strict loosening, so in practice the row
    always proves a genuine widening of the admitted set.
    """
    if not Z3_AVAILABLE:
        return None
    ctx = _Context()
    base_z3 = _to_z3(base_node, ctx)
    head_z3 = _to_z3(head_node, ctx)
    if base_z3 is None or head_z3 is None:
        return None
    solver = z3.Solver()
    solver.set("timeout", 1000)
    # SAME formula as _implies(head_z3, base_z3) — we keep the model.
    solver.add(z3.And(head_z3, z3.Not(base_z3)))
    if solver.check() != z3.sat:
        return None  # soundness guard: no model ⇒ no claim
    row = _decode_model(solver.model(), ctx)
    # Soundness gate (critique #1/#2): the real-column projection must
    # be a witness on its own, independent of the dropped synthetic
    # vars. An empty row (all-opaque/all-GUC loosen) is sufficient iff
    # EVERY row leaks — which is exactly when the gate passes; for the
    # common GUC-only loosen it does not, so we return None.
    if not _row_is_sufficient_witness(row, base_z3, head_z3, ctx):
        return None
    return row


# ===========================================================================
# H2 (SEC038) — semantic anonymous-read property via Kleene three-valued
# (3VL) logic. ADDITIVE: nothing above this line is touched. Every symbol
# below is new. The 2-valued diff path (`_to_z3` / `classify_via_z3` /
# `counterexample` / `_implies`) is unchanged and its tests stay green.
#
# The property: a read-capable policy (FOR ALL / FOR SELECT) leaks to
# anonymous iff its USING predicate, evaluated under a session where every
# auth-context function (auth.uid/role/jwt, current_user, session_user,
# current_setting) returns NULL, is VALID — i.e. evaluates to *exactly
# TRUE* (Kleene) for EVERY row assignment. Under SQL 3VL a row is visible
# iff the predicate is exactly TRUE (NULL and FALSE both hide the row), so
# validity means "anonymous unconditionally reads all rows" — the
# Lovable-CVE catastrophic class.
#
# Firing criterion (zero-false-positive on the corpus): USING is anon-valid
# iff `NOT(is_true(USING_anon))` is UNSAT. A scoped predicate
# (`col = current_setting(...)`) under anon becomes `col = NULL` → Kleene U
# (not TRUE) → not valid → does NOT fire. An inverted-auth disjunct
# (`auth.uid() IS NULL OR real_check`) under anon becomes `TRUE OR …` →
# TRUE for all rows → valid → fires. A narrow public carve-out
# (`col = <const> OR …`) is TRUE only for *some* rows → not valid → does
# NOT fire. Untranslatable sub-expressions ⇒ None ⇒ cannot prove validity
# ⇒ DO NOT fire. Soundness over recall.
# ===========================================================================


@dataclass
class _TV:
    """A three-valued (Kleene) truth: a pair of Z3 Bools.

    ``is_true`` holds iff the value is exactly TRUE; ``is_null`` holds iff
    it is the Kleene unknown (U). For every *derived* node these are
    exclusive by construction (a node can't be both TRUE and U). For a
    *free leaf* lifted into a truth (a bool column / bool opaque used as a
    predicate) the exclusivity ``Or(Not(is_true), Not(is_null))`` is
    asserted explicitly at lift time — a SOUNDNESS requirement (§ amendment
    #1): omitting it can only add models to ``is_true`` and produce a
    spurious VALID verdict (a false fire).
    """

    is_true: Any   # z3.BoolRef
    is_null: Any   # z3.BoolRef


@dataclass
class _Val:
    """A non-boolean (scalar) value plus its Kleene null-flag."""

    value: Any     # z3.ExprRef
    is_null: Any   # z3.BoolRef


# Auth-context functions forced to NULL under an anonymous session. Mirrors
# SEC004's `_DEFAULT_AUTH_FUNCTIONS` and ast_utils' SQLValueFunction set so
# the two rules stay consistent and configurable.
_DEFAULT_AUTH_FUNCTIONS: frozenset[str] = frozenset({
    "auth.uid",
    "auth.role",
    "auth.jwt",
    "current_user",
    "session_user",
    "current_setting",
})

# Postgres parses `current_user`, `session_user`, etc. as SQLValueFunction
# nodes (a separate class from FuncCall). Mirror of `_SVFOP_NAMES` /
# `_SQL_VALUE_FUNCTION_NAMES`.
_ANON_SVFOP_NAMES: dict[Any, str] = {
    SQLValueFunctionOp.SVFOP_CURRENT_USER: "current_user",
    SQLValueFunctionOp.SVFOP_SESSION_USER: "session_user",
    SQLValueFunctionOp.SVFOP_USER: "user",
    SQLValueFunctionOp.SVFOP_CURRENT_ROLE: "current_role",
}


def _is_anon_null_leaf(node: Any, auth_funcs: set[str]) -> bool:
    """True iff ``node`` is an auth-context call forced to NULL under anon.

    Recognizes the same two AST shapes SEC004 / SEC037 do:
    - ``FuncCall`` whose qualified-or-bare name ∈ ``auth_funcs``
      (``auth.uid()``, ``current_setting('app.x')``, a bare ``uid()``).
    - ``SQLValueFunction`` whose mapped name ∈ ``auth_funcs``
      (``current_user`` / ``session_user`` written without parens).
    """
    if isinstance(node, FuncCall):
        qualified, bare = func_name_parts(node)
        if qualified is None:
            return False
        return qualified in auth_funcs or bare in auth_funcs
    if isinstance(node, SQLValueFunction):
        name = _ANON_SVFOP_NAMES.get(node.op)
        return name is not None and name in auth_funcs
    return False


def _unwrap_scalar_sublink(node: Any) -> Any:
    """``(SELECT <expr>)`` → ``<expr>``; anything else returned unchanged.

    Only a single-target ``EXPR_SUBLINK`` with no FROM / WHERE / set-op /
    DISTINCT / GROUP BY / HAVING is unwrapped (a genuine scalar
    projection). Everything else — ``EXISTS``, an ``IN``-subquery, a
    multi-target or FROM-bearing select — is left as-is, so the 3VL
    translator returns None on it (soundness abort). Load-bearing: every
    auth call in the corpus is ``(SELECT auth.uid())``-wrapped, so without
    this the rule never fires on the real corpus; but an EXISTS subquery
    (corpus ``sec004-is-null-in-subquery-safe``) must stay opaque so that
    case stays clean.
    """
    if not isinstance(node, SubLink):
        return node
    if node.subLinkType != SubLinkType.EXPR_SUBLINK:
        return node
    sel = node.subselect
    if not isinstance(sel, SelectStmt):
        return node
    target_list = sel.targetList
    if not target_list or len(target_list) != 1:
        return node
    # `sel.op` is a SetOperation IntEnum; SETOP_NONE == 0 is a plain
    # SELECT. Reject UNION/INTERSECT/EXCEPT and any FROM/WHERE/aggregation
    # shape — those aren't a bare scalar.
    if (
        sel.fromClause
        or sel.whereClause
        or int(sel.op) != 0
        or sel.distinctClause
        or sel.groupClause
        or sel.havingClause
    ):
        return node
    target = target_list[0]
    if not isinstance(target, ResTarget):
        return node
    return target.val


def _as_val(x: Any) -> Any:
    """Coerce a translation result into a ``_Val`` scalar operand.

    ``_TV`` (a boolean-valued node) lowers to ``_Val(value=is_true,
    is_null=is_null)`` — its truth becomes the scalar value, its null-flag
    carries through. ``_Val`` passes through. ``None`` propagates. This is
    the dual of ``_lift_to_tv``: amendments #3/#4 require boolean operands
    (a bool literal, a bool column, a ``(... IS NULL)::bool`` cast) to be
    usable wherever a scalar ``_Val`` is expected.
    """
    if x is None:
        return None
    if isinstance(x, _Val):
        return x
    if isinstance(x, _TV):
        return _Val(value=x.is_true, is_null=x.is_null)
    return None


def _lift_to_tv(x: Any, assertions: list[Any]) -> Any:
    """Coerce a translation result into a ``_TV`` truth.

    ``_TV`` passes through. A ``_Val`` whose value is Bool-sorted is a
    free bool leaf used as a predicate — lift to ``_TV`` AND append the
    exclusivity constraint ``Or(Not(value), Not(is_null))`` (amendment #1:
    soundness — a free leaf must not satisfy ``value ∧ is_null``). A
    non-bool ``_Val`` used as a truth is not a Kleene truth → None
    (abort). ``None`` propagates.
    """
    if x is None:
        return None
    if isinstance(x, _TV):
        return x
    if isinstance(x, _Val):
        if x.value.sort() == z3.BoolSort():
            assertions.append(z3.Or(z3.Not(x.value), z3.Not(x.is_null)))
            return _TV(is_true=x.value, is_null=x.is_null)
        return None
    return None


def _anon_3vl(
    node: Any, ctx: _Context, auth_funcs: set[str], assertions: list[Any]
) -> Any:
    """Translate a pglast predicate node into a Kleene ``_TV`` / ``_Val``.

    Returns ``_TV`` for a boolean-valued node (comparison, AND/OR/NOT,
    NullTest, bool column / bool literal), ``_Val`` for a scalar (column,
    auth call, literal, arithmetic, COALESCE, cast), or ``None`` when any
    sub-expression is untranslatable (soundness abort — propagated by the
    ``any(... is None)`` pattern, mirroring ``_to_z3``).

    ``assertions`` collects leaf-exclusivity constraints (§ amendment #1);
    the caller adds them to BOTH the validity and witness solvers.

    Every call unwraps a scalar SubLink first, then checks the anon-NULL
    leaf BEFORE the generic FuncCall / SQLValueFunction branches.
    """
    node = _unwrap_scalar_sublink(node)

    # --- anon-NULL leaf: auth.uid()/role()/jwt(), current_setting(...),
    # current_user, session_user — forced to NULL under an anonymous
    # session. Value is irrelevant (it's NULL); is_null is unconditionally
    # True. (Checked before the generic FuncCall branch.)
    if _is_anon_null_leaf(node, auth_funcs):
        return _Val(
            value=ctx.opaque(_canon(node), z3.StringSort()),
            is_null=z3.BoolVal(True),
        )

    # --- literals.
    if isinstance(node, A_Const):
        v = _const_to_z3(node)
        if v is None:
            return None  # literal NULL / unsupported
        # Bool literal at top level is a truth; the caller's _lift_to_tv
        # promotes a Bool-sorted _Val. Keep it a _Val here so it also
        # works as a scalar comparison operand (amendment #3).
        return _Val(value=v, is_null=z3.BoolVal(False))

    # --- bare ColumnRef. Bool sort by default (used as a predicate or a
    # bool operand); a typed comparison context rebinds it via the 3VL
    # operand resolver. The free null-flag is a Kleene U candidate.
    if isinstance(node, ColumnRef):
        key = _column_key(node)
        if not key:
            return None
        value = ctx.column(key, z3.BoolSort())
        if value is None:
            return None
        return _Val(value=value, is_null=ctx.null_flag(key))

    # --- non-auth function call: opaque value + FREE null-flag (a
    # non-auth function is NOT known-NULL under anon). Sanity-translate
    # args so an unparseable signature aborts.
    if isinstance(node, FuncCall):
        for arg in (node.args or ()):
            if _anon_3vl(arg, ctx, auth_funcs, assertions) is None:
                return None
        key = _canon(node)
        return _Val(
            value=ctx.opaque(key, z3.StringSort()),
            is_null=ctx.null_flag(key),
        )

    # --- boolean connectives (Kleene tables).
    if isinstance(node, BoolExpr):
        return _anon_boolexpr(node, ctx, auth_funcs, assertions)

    # --- comparison / arithmetic.
    if isinstance(node, A_Expr):
        if node.kind == A_Expr_Kind.AEXPR_OP:
            return _anon_binop(node, ctx, auth_funcs, assertions)
        # IN / BETWEEN / others: soundness abort in v1 (SEC004 still
        # guards the literal IS NULL shape syntactically).
        return None

    # --- NULL tests. The arg is resolved as a SCALAR (_Val) so
    # `auth.uid() IS NULL`, `(... )::cast IS NULL`, etc. all work — this
    # is the whole point vs the 2VL path (amendment #2: route through the
    # scalar resolver, not the bool-_TV path). The result is a definite
    # truth (never U): IS NULL is exactly the null-flag.
    if isinstance(node, NullTest):
        inner = _as_val(_anon_3vl(node.arg, ctx, auth_funcs, assertions))
        if inner is None:
            return None
        if node.nulltesttype == NullTestType.IS_NULL:
            return _TV(is_true=inner.is_null, is_null=z3.BoolVal(False))
        if node.nulltesttype == NullTestType.IS_NOT_NULL:
            return _TV(
                is_true=z3.Not(inner.is_null), is_null=z3.BoolVal(False)
            )
        return None

    # --- COALESCE: value is the first non-null arg; null iff all null.
    if isinstance(node, CoalesceExpr):
        vals: list[Any] = []
        for arg in (node.args or ()):
            v = _as_val(_anon_3vl(arg, ctx, auth_funcs, assertions))
            if v is None:
                return None
            vals.append(v)
        if not vals:
            return None
        try:
            value = vals[-1].value
            for v in reversed(vals[:-1]):
                value = z3.If(z3.Not(v.is_null), v.value, value)
            is_null = vals[0].is_null
            for v in vals[1:]:
                is_null = z3.And(is_null, v.is_null)
        except z3.Z3Exception:
            return None  # sort mismatch across branches
        return _Val(value=value, is_null=is_null)

    # --- CASE: v1 soundness abort (no CASE corpus negative; Oracle §3.5).
    if isinstance(node, CaseExpr):
        return None

    # --- TypeCast. Handle both a scalar (_Val) and a boolean (_TV) inner
    # (amendment #4: P4 `(... IS NULL)::bool` feeds a _TV inner). A cast
    # of NULL is NULL, so the inner null-flag always carries through.
    if isinstance(node, TypeCast):
        return _anon_typecast(node, ctx, auth_funcs, assertions)

    return None  # anything else: soundness abort


def _anon_boolexpr(
    node: BoolExpr, ctx: _Context, auth_funcs: set[str], assertions: list[Any]
) -> Any:
    """Kleene AND / OR / NOT over ``_TV`` operands.

    NOT x:  is_true = ¬x.is_true ∧ ¬x.is_null ; is_null = x.is_null
    AND:    is_true = ⋀ tᵢ ; is_null = (some nᵢ) ∧ (no falsey operand)
    OR:     is_true = ⋁ tᵢ ; is_null = (some nᵢ) ∧ (no true operand)

    These are exactly the SQL three-valued tables (`NULL OR TRUE = TRUE`,
    `NULL AND FALSE = FALSE`, `NULL OR NULL = NULL`, `U AND T = U`,
    `F AND U = F`). Each operand is lifted to a ``_TV`` (a bool column /
    literal operand becomes a truth, asserting leaf exclusivity).
    """
    raw_args = node.args or ()
    tvs: list[_TV] = []
    for arg in raw_args:
        tv = _lift_to_tv(
            _anon_3vl(arg, ctx, auth_funcs, assertions), assertions
        )
        if tv is None:
            return None
        tvs.append(tv)
    if not tvs:
        return None

    if node.boolop == BoolExprType.NOT_EXPR:
        if len(tvs) != 1:
            return None
        x = tvs[0]
        return _TV(
            is_true=z3.And(z3.Not(x.is_true), z3.Not(x.is_null)),
            is_null=x.is_null,
        )

    if node.boolop == BoolExprType.AND_EXPR:
        if len(tvs) < 2:
            return tvs[0]
        acc = tvs[0]
        for y in tvs[1:]:
            falsey_x = z3.And(z3.Not(acc.is_true), z3.Not(acc.is_null))
            falsey_y = z3.And(z3.Not(y.is_true), z3.Not(y.is_null))
            is_true = z3.And(acc.is_true, y.is_true)
            is_null = z3.Or(
                z3.And(acc.is_null, z3.Not(falsey_y)),
                z3.And(y.is_null, z3.Not(falsey_x)),
            )
            acc = _TV(is_true=is_true, is_null=is_null)
        return acc

    if node.boolop == BoolExprType.OR_EXPR:
        if len(tvs) < 2:
            return tvs[0]
        acc = tvs[0]
        for y in tvs[1:]:
            is_true = z3.Or(acc.is_true, y.is_true)
            is_null = z3.And(
                z3.Or(acc.is_null, y.is_null),
                z3.Not(acc.is_true),
                z3.Not(y.is_true),
            )
            acc = _TV(is_true=is_true, is_null=is_null)
        return acc

    return None


def _anon_binop(
    node: A_Expr, ctx: _Context, auth_funcs: set[str], assertions: list[Any]
) -> Any:
    """Kleene comparison / arithmetic over scalar ``_Val`` operands.

    Comparison (`= != <> < > <= >=`) → ``_TV``:
        is_true = ¬na ∧ ¬nb ∧ op(va, vb) ; is_null = na ∨ nb
    Arithmetic (`+ - * / %`) → ``_Val``:
        value = op(va, vb) ; is_null = na ∨ nb

    The comparison rule is the single highest-risk detail (§ amendment /
    Oracle N4): when one side is anon-NULL (`nb = True`), ``is_true``
    collapses to False and ``is_null`` to True — i.e. ``col = NULL`` is
    Kleene U, never a satisfiable 2VL Bool. That is what keeps
    ``U AND T = U`` / ``U OR U = U`` and the corpus negatives clean.
    """
    op_names = list(node.name or ())
    if len(op_names) != 1 or not isinstance(op_names[0], String):
        return None
    op = op_names[0].sval
    comparison_fn = _COMPARISON_OPS.get(op)
    arithmetic_fn = _ARITHMETIC_OPS.get(op)
    if comparison_fn is None and arithmetic_fn is None:
        return None

    left, right = _resolve_3vl_operands(
        node.lexpr, node.rexpr, ctx, auth_funcs, assertions
    )
    if left is None or right is None:
        return None

    if comparison_fn is not None:
        try:
            cmp_z3 = comparison_fn(left.value, right.value)
        except z3.Z3Exception:
            return None
        return _TV(
            is_true=z3.And(
                z3.Not(left.is_null), z3.Not(right.is_null), cmp_z3
            ),
            is_null=z3.Or(left.is_null, right.is_null),
        )

    if arithmetic_fn is not None:
        try:
            value = arithmetic_fn(left.value, right.value)
        except z3.Z3Exception:
            return None
        return _Val(value=value, is_null=z3.Or(left.is_null, right.is_null))

    return None  # unreachable (guarded above) — satisfies the type checker


def _resolve_3vl_operands(
    lexpr: Any,
    rexpr: Any,
    ctx: _Context,
    auth_funcs: set[str],
    assertions: list[Any],
) -> tuple[Any, Any]:
    """Translate both comparison operands to ``_Val`` pairs.

    Distinct from ``_resolve_binop_operands`` (the 2VL path) — that one
    returns bare Z3 exprs, not ``_Val`` null-pairs. When one side is a
    bare ColumnRef and the other resolves to a concrete-sorted ``_Val``,
    the column is bound to that sort (its null-flag is a free Kleene U
    candidate). ``col OP col`` binds both as String (mirroring the 2VL
    default). Any None → ``(None, None)``.
    """
    lexpr = _unwrap_scalar_sublink(lexpr)
    rexpr = _unwrap_scalar_sublink(rexpr)
    l_is_col = isinstance(lexpr, ColumnRef)
    r_is_col = isinstance(rexpr, ColumnRef)

    def col_val(col: ColumnRef, sort: Any) -> Any:
        key = _column_key(col)
        if not key:
            return None
        var = ctx.column(key, sort)
        if var is None:
            return None  # type conflict against a prior binding
        return _Val(value=var, is_null=ctx.null_flag(key))

    if l_is_col and not r_is_col:
        right = _as_val(_anon_3vl(rexpr, ctx, auth_funcs, assertions))
        if right is None:
            return (None, None)
        left = col_val(lexpr, right.value.sort())
        return (left, right)
    if r_is_col and not l_is_col:
        left = _as_val(_anon_3vl(lexpr, ctx, auth_funcs, assertions))
        if left is None:
            return (None, None)
        right = col_val(rexpr, left.value.sort())
        return (left, right)
    if l_is_col and r_is_col:
        return (col_val(lexpr, z3.StringSort()), col_val(rexpr, z3.StringSort()))
    left = _as_val(_anon_3vl(lexpr, ctx, auth_funcs, assertions))
    right = _as_val(_anon_3vl(rexpr, ctx, auth_funcs, assertions))
    return (left, right)


def _anon_typecast(
    node: TypeCast, ctx: _Context, auth_funcs: set[str], assertions: list[Any]
) -> Any:
    """Translate ``<expr>::<type>`` under 3VL, preserving the null-flag.

    The inner may be scalar (``_Val``) or boolean (``_TV`` — e.g. P4's
    ``(... IS NULL)::bool``, amendment #4). A cast of NULL is NULL, so the
    inner ``is_null`` always carries through. When the target sort matches
    the inner value's sort the cast is a no-op; otherwise the value is
    opaque under the target sort (an unknown target keeps a String opaque)
    but the null-flag is preserved.
    """
    inner_raw = _anon_3vl(node.arg, ctx, auth_funcs, assertions)
    if inner_raw is None:
        return None
    inner = _as_val(inner_raw)
    if inner is None:
        return None
    target_sort = _typename_segments_to_sort(node.typeName)
    if target_sort is None:
        # Unknown target type — opaque value, keep the inner null-flag.
        return _Val(
            value=ctx.opaque(_canon(node), z3.StringSort()),
            is_null=inner.is_null,
        )
    if inner.value.sort() == target_sort:
        return _Val(value=inner.value, is_null=inner.is_null)
    return _Val(
        value=ctx.opaque(_canon(node), target_sort),
        is_null=inner.is_null,
    )


def anon_read_counterexample(
    using_node: Any, auth_functions: set[str] | None = None
) -> dict[str, object] | None:
    """Prove (or refute) that ``using_node`` is anon-VALID under Kleene 3VL.

    Returns a dict when the USING predicate is provably TRUE for EVERY row
    under an anonymous session (every auth function NULL) — meaning the
    policy unconditionally leaks all rows to an unauthenticated client.
    Returns ``None`` otherwise.

    Under the validity criterion the predicate is TRUE for every row, so
    the proof artifact is "all rows": the returned dict is empty ``{}``
    (the predicate pins no specific real column — a genuine empty model is
    the honest witness, § amendment #6). A non-empty dict is possible only
    if a future "satisfiable read" criterion is added; SEC038 treats any
    non-None return as "fire".

    ``None`` when:
    - Z3 is unavailable;
    - the predicate (or any sub-expression) is untranslatable — cannot
      prove validity, so no claim;
    - ``NOT(is_true)`` is SAT — some row escapes ⇒ scoped, not a
      catastrophic leak;
    - the solver returns ``unknown`` (timeout) — no claim (mirrors
      ``_implies``).

    Soundness over recall: never claim a leak that can't be proven.
    """
    if not Z3_AVAILABLE:
        return None
    auth = (
        auth_functions
        if auth_functions is not None
        else set(_DEFAULT_AUTH_FUNCTIONS)
    )
    ctx = _Context()
    assertions: list[Any] = []
    tv = _lift_to_tv(
        _anon_3vl(using_node, ctx, auth, assertions), assertions
    )
    if tv is None:
        return None

    # Validity: NOT(is_true) UNSAT under the leaf-exclusivity constraints.
    solver = z3.Solver()
    solver.set("timeout", 1000)
    for a in assertions:
        solver.add(a)
    solver.add(z3.Not(tv.is_true))
    result = solver.check()
    if result != z3.unsat:
        return None  # sat (a row escapes) or unknown (timeout) ⇒ no fire

    # Valid ⇒ every row is read ⇒ any model of is_true is a sound witness
    # (no sufficiency gate needed — contrast counterexample()/H1, which
    # proves only a strict-superset loosening). Reuse the SAME ctx so
    # `_decode_model`'s real-column filter already knows the columns.
    witness = z3.Solver()
    witness.set("timeout", 1000)
    for a in assertions:
        witness.add(a)
    witness.add(tv.is_true)
    if witness.check() != z3.sat:  # defensive; valid ⇒ sat
        return {}
    return _decode_model(witness.model(), ctx)
