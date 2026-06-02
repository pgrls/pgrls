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
    String,
    TypeCast,
)
from pglast.enums import (
    A_Expr_Kind,
    BoolExprType,
    NullTestType,
)
from pglast.stream import RawStream


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
