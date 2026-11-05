"""SAT-based predicate implication via Z3.

Z3 (``z3-solver``) is a core dependency as of 0.16.0, so this path runs
on a plain ``pip install pgrls``. The ``Z3_AVAILABLE`` guard is retained
as a defensive fallback: if z3 somehow can't be imported it is False and
``classify_via_z3`` returns None — callers fall through to whatever
existing syntactic classifier they were using. ``compare_predicates`` (the public
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

Both predicates are translated by the Kleene three-valued encoder below
(``_anon_3vl``, shared with the SEC038 / verify provers), in a mode that
assumes nothing about the session (``_Context.any_session``): every column
and every opaque value carries a null-flag, and a predicate admits a row
only when it is exactly TRUE — NULL hides a row just as FALSE does. So
``a = 1 OR a <> 1`` → ``true`` is a loosening (it newly admits the rows
where ``a`` is NULL), and ``col IS NOT NULL AND col = x`` is equivalent to
``col = x``. A two-valued model gets both wrong: it calls the first
equivalent, and with an ``IS NULL`` disconnected from the column's value
it flags the second.

What the encoder translates: columns, literals, comparisons and arithmetic
(on the diff path not where Z3 and Postgres disagree — ``/`` and ``%``,
arithmetic on anything but integers, ordering on text, which collations
decide; a cast that may change the value, such as ``varchar(3)`` or
``float4``, or of a function's result, is an opaque value of its own), a
decimal literal only when a ``float4`` holds it exactly (otherwise a
``numeric``, ``float8`` and ``float4`` column read it differently),
AND / OR / NOT, ``IS [NOT] NULL``, ``IS [NOT] DISTINCT FROM`` and ``[NOT]
BETWEEN`` (on the diff path), ``= ANY (ARRAY[…])`` / ``IN (…)`` over
literals, casts, ``COALESCE``, and function calls (an opaque value per
distinct call, shared by base and head). On the diff path a ``CASE``, or a
``COALESCE`` it cannot model exactly, is an opaque value too. An opaque
call, CASE or COALESCE is text:
compared with something else it translates only through a cast; an opaque
cast or arithmetic result takes its own type. Anything else
returns None and the caller
falls through to ``requires_review``.

A column's type is inferred from what it is compared with: against an
integer literal it is an integer, so ``a >= 2`` and ``a > 1`` are
equivalent — wrong for a ``numeric`` column, where 1.5 passes only the
second, or a ``float4`` one, whose ``IN`` list rounds ``16777217`` to a
single; and against a text literal it is text, so ``c = 'true'`` and
``c <> 't'`` can both hold — wrong for a ``bool`` column (or ``uuid``,
where case does not matter). The diff compares policy text and does not see
column types.

Type unification per column: the first comparison fixes the type.
A subsequent reference with a conflicting type (e.g. ``col = 5``
then ``col = 'foo'``) returns None from the translator (unsound to
proceed). Real RLS predicates don't mix types on the same column,
so this is a defensive guardrail rather than a real limitation.
"""
from __future__ import annotations

import contextlib
import ctypes
import dataclasses
import fractions
import functools
import inspect
import math
import re
import struct

from collections.abc import Callable, Mapping, Sequence

from dataclasses import dataclass
from typing import Any, Literal, TypeVar, cast

try:
    import z3

    Z3_AVAILABLE = True
except ImportError:  # pragma: no cover — exercised by the no-z3 install path
    Z3_AVAILABLE = False
    z3 = None  # noqa: F811  # rebind to None when import failed

from pgrls.model import is_maybe_set

from pglast.ast import (
    A_ArrayExpr,
    A_Const,
    A_Expr,
    Boolean,
    BoolExpr,
    Node,
    CaseExpr,
    CoalesceExpr,
    ColumnRef,
    Float,
    FuncCall,
    Integer,
    MinMaxExpr,
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

from pgrls.ast_utils import (
    func_name_parts,
    has_literal_setting_arguments,
    is_never_null_current_setting,
)


# Comparison operator strings appearing in `A_Expr.name[0].sval` for
# the supported subset. Each maps to a Z3 lambda the translator
# applies to the (left, right) pair. Equality and inequality work
# across all supported types; ordered comparisons (`<`, `>`, etc.)
# work for Int and Real but not Bool — Z3 raises on two Bools, but coerces
# a Bool against a number to 0 / 1, which `_unlike_sql` catches first.
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
# Int or Real. When the operands' sorts don't support the operator
# (e.g. String `-`/`*`/`/`/`%`, which routinely happens for opaque
# values like now()/current_setting/an unknown-target cast, and for
# `col OP col` where both sides default to StringSort) the Python
# operator overload raises a plain TypeError — NOT z3.Z3Exception.
# Every call site applying one of these lambdas must therefore catch
# (z3.Z3Exception, TypeError) and degrade to None (untranslatable ->
# NO-OP), or the TypeError escapes the whole rule-dispatch loop.
# (`+` is the exception: Z3 overloads it to Concat for strings, so
# it never raises here.)
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

# Z3 decl-name prefixes for the synthetic vars the context mints:
# opaque-expression vars (`opaque`) and the Kleene null-flag (`null_flag`).
# A REAL column is bound via `column()` under its verbatim key, and Z3
# identifies a constant by name+sort — so a real column literally named
# `_nullflag__x` (legal: a double-quoted identifier may contain anything
# but NUL) would alias the null-flag minted for column `x`, making
# distinct predicates look `semantic_equivalent` (a silently-suppressed
# diff Change, and by symmetry a missed DANGEROUS loosening). Embedding a
# NUL in the prefix does NOT help — Z3 truncates decl names at NUL — so
# instead `_column_key` refuses to bind any column whose key collides
# with these prefixes (it returns "" → the predicate degrades to
# requires_review, the safe direction). Single source of truth so the
# minting sites and that guard cannot drift. (R15 #3)
_OPAQUE_PREFIX = "_opaque__"
# Built-in VOLATILE calls (PERF002's set and kin): each call returns its own
# value, so two of the same text are not one value. A user function's
# volatility is not known here: it is taken to be STABLE.
_VOLATILE_CALL = re.compile(
    r"(?<![\w.\"])(?:pg_catalog\.)?(?:random|random_normal|clock_timestamp|timeofday"
    r"|nextval|setval|currval|lastval|gen_random_uuid|uuidv4|uuidv7|pg_backend_pid"
    r"|array_shuffle|array_sample)\s*\(",
    re.IGNORECASE)
_NULLFLAG_PREFIX = "_nullflag__"
# Cross-tenant verifier (`prove_cross_tenant_isolation`) only: the free,
# NON-NULL symbol that stands for an authenticated session's own tenant
# identity (`auth.uid()` etc. under `session_mode`). Same anti-collision
# rationale as the markers above — a real column literally named
# `_session__auth.uid` must not alias the session symbol — so it joins the
# reserved set and `_column_key` refuses to bind it.
_SESSION_PREFIX = "_session__"
_RESERVED_MARKER_PREFIXES: tuple[str, ...] = (
    _OPAQUE_PREFIX,
    _NULLFLAG_PREFIX,
    _SESSION_PREFIX,
)


class _Context:
    """Shared variable + type-inference context across base and head.

    `base` and `head` predicates referring to the same column must
    map to the same Z3 free variable so the implication query is
    meaningful. `_Context` tracks the variable and its inferred
    Z3 sort, refusing to re-bind a column to a conflicting sort.
    """

    def __init__(self) -> None:
        self._vars: dict[str, Any] = {}  # column-key → z3.ExprRef
        # Integer literals and numeric columns as integers (see
        # `_const_to_z3`).
        self.integers = False
        # How deep the translation is among values Postgres gives one type
        # (see `_real_integer`).
        self.unified = 0
        # Inside a list one of whose members rounds the others (off the diff
        # path), so no comparison in it is read exactly.
        self.kin_rounded = 0
        # Diff path: per column name, whether each comparison of it with a
        # string read the string bare (False) or typed (True); see
        # `_note_string_read`.
        self.string_reads: dict[str, set[bool]] = {}
        self.string_scope = 0
        # A column's last name → how it is spelled (see `_column_key`).
        self.spellings: dict[str, tuple[str, ...]] = {}
        # Phase 3 — opaque expressions (function calls,
        # COALESCE, CASE) keyed by their canonical-string shape.
        # Same key on both sides of the diff yields the same Z3
        # variable, enabling implication checks across predicates
        # that reference identical opaque expressions.
        self._opaque_vars: dict[str, Any] = {}
        self._volatile_calls = 0
        # Kleene three-valued null-flags, keyed per column / opaque-expr.
        # Decl names are
        # prefixed `_nullflag__` and never land in `_vars`, so
        # `is_real_column` excludes them and `_decode_model` drops them
        # from the witness exactly like `_opaque__*`.
        self._nullflag_vars: dict[str, Any] = {}
        # Cross-tenant verifier only. `session_mode` flips the anon-NULL
        # leaf (every auth call NULL) to a free NON-NULL *session symbol*
        # (an authenticated session's own identity) — the ONLY behavioral
        # change vs the anon path, so with `session_mode` False this
        # context is byte-for-byte the anon/diff encoder. `_session_vars`
        # is that symbol's namespace (decl-prefixed `_session__`, kept out
        # of `_vars` so `_decode_model` drops it from the witness like the
        # other synthetic vars). `tenant_pairs` records every
        # `<column> = <session symbol>` scoping equality the encoder binds,
        # so the prover can constrain the column != the session's tenant.
        self.session_mode: bool = False
        # Anon prover only. False models a session with NO JWT (every auth
        # function NULL — a raw connection as the anon DB role). True models
        # the Supabase ANON-KEY session: PostgREST sets
        # `request.jwt.claims = {"role":"anon"}`, so `auth.role()` is the
        # string 'anon' (never NULL), `auth.jwt()` is a non-null blob, and
        # `auth.uid()` (the `sub` claim) is still NULL. `prove_anon_isolation`
        # runs BOTH and a leak under either is a leak: `USING (auth.role() =
        # 'anon')` is UNSAT under the no-JWT model (NULL = 'anon' is UNKNOWN)
        # yet reads every row for a real anon-key caller — a false PROVEN
        # until the second session was modelled.
        self.anon_jwt: bool = False
        # Anon prover only: the dotted GUCs the anonymous session inherits
        # already SET (database / role / server level — `Schema.set_gucs`,
        # `Schema.role_set_gucs`), name → configured value. A read of one is
        # that value, not the unset-GUC raise; a `None` value means the GUC
        # is set but its value was not captured, so it stays opaque.
        self.set_gucs: dict[str, str | None] = {}
        # Diff path only (`classify_via_z3` / `counterexample`). The two
        # predicates are compared over EVERY session, not an anonymous one:
        # a read of a custom GUC is a free value (any session may have set
        # it), never the unset-GUC raise the anon prover models.
        self.any_session: bool = False
        # Diff path: columns tested for NULL. One that is never compared
        # binds no value variable, yet a witness row may need it NULL.
        self.null_tested: set[str] = set()
        self._session_vars: dict[str, Any] = {}
        self.tenant_pairs: list[tuple[Any, Any]] = []
        # Session identities the predicate tests for NULL (`auth.role() IS
        # NULL`), by session-symbol decl name. Under `session_mode` every auth
        # leaf is minted NON-NULL — the mode's premise is a session
        # authenticated as some tenant, so ITS OWN identity exists. That says
        # nothing about a DIFFERENT auth call: tenancy carried by `SET
        # app.tenant` with no JWT at all is an ordinary deployment, and there
        # `auth.role()` is NULL for every session. Proving such a test FALSE
        # manufactured a PROVEN for a policy that leaks — see
        # `_session_null_tests_offaxis`.
        self.session_null_tests: set[str] = set()

    @contextlib.contextmanager
    def unifying(self, unified: bool) -> Any:
        """Translate among values Postgres gives one type, when `unified`."""
        self.unified += unified
        try:
            yield
        finally:
            self.unified -= unified

    def column(self, key: str, sort: Any) -> Any:
        """Return the Z3 variable for `key`, binding it on first use.

        On a subsequent call with a different `sort`, returns None to
        signal a type-conflict abort. A number is a real unless
        `self.integers` (see `_const_to_z3`): compared with an integer, a
        column may still be a `numeric` one.
        """
        if sort == z3.IntSort() and not self.integers:
            sort = z3.RealSort()
        elif sort == z3.RealSort() and self.integers:
            sort = z3.IntSort()  # the integer pass: an integer column
        existing = self._vars.get(key)
        if existing is None:
            var = z3.Const(key, sort)
            self._vars[key] = var
            return var
        if existing.sort() == sort:
            return existing
        return None  # type conflict — translation aborts

    def opaque(self, key: str, sort: Any) -> Any:
        """Return a Z3 free variable for an opaque expression keyed by
        its canonical shape. Bound to ``sort`` on first use; subsequent
        calls with a different sort return None (type-conflict abort).
        An expression with a volatile call gets a variable of its own.
        """
        key = self._unshared(key)
        existing = self._opaque_vars.get(key)
        if existing is None:
            var = z3.Const(f"{_OPAQUE_PREFIX}{key}", sort)
            self._opaque_vars[key] = var
            return var
        if existing.sort() == sort:
            return existing
        return None

    def null_flag(self, key: str) -> Any:
        """Free Kleene null-flag (a Z3 Bool) for the value keyed by ``key``.

        The decl name is prefixed
        ``_nullflag__`` and the var never enters ``_vars``, so
        ``is_real_column`` returns False for it and ``_decode_model``
        drops it from the witness — keeping the emitted row real-columns
        only, exactly like ``_opaque__*``.
        """
        existing = self._nullflag_vars.get(key)
        if existing is None:
            existing = z3.Bool(f"{_NULLFLAG_PREFIX}{key}")
            self._nullflag_vars[key] = existing
        return existing

    def opaque_null_flag(self, key: str) -> Any:
        """``null_flag`` of the opaque expression keyed ``key`` — under the
        reserved ``_opaque__`` prefix, so it never aliases the null-flag of a
        column whose (quoted) name happens to equal ``key``."""
        return self.null_flag(f"{_OPAQUE_PREFIX}{self._unshared(key)}")

    def _unshared(self, key: str) -> str:
        if _VOLATILE_CALL.search(key) is None:
            return key
        self._volatile_calls += 1
        return f"{key} #volatile{self._volatile_calls}"

    def is_real_column(self, name: str) -> bool:
        """True iff `name` is a real column var (not a null/opaque marker).

        `column()` binds via ``z3.Const(key, sort)`` (the var's decl name
        is exactly ``key``), whereas ``null_flag`` / ``opaque`` prefix
        their decl names with ``_nullflag__`` / ``_opaque__`` and live in
        the separate ``_nullflag_vars`` / ``_opaque_vars`` dicts. So a model
        decl whose name is a key of ``_vars`` is authoritatively a real
        column; everything else is a synthetic marker. Preferred over
        prefix-string matching, which a user column literally named
        ``_nullflag__x`` could otherwise spoof.
        """
        return name in self._vars

    def session_var(self, key: str, sort: Any) -> Any:
        """Free, NON-NULL Z3 symbol for the authenticated session's own
        tenant identity (cross-tenant verifier only).

        The dual of ``opaque``: same canonical-shape keying so every
        reference to one auth call (e.g. ``auth.uid()``) shares one symbol,
        but a SEPARATE namespace + ``_session__`` decl prefix so it never
        enters ``_vars`` — ``is_real_column`` returns False for it and
        ``_decode_model`` drops it from the witness, exactly like
        ``_opaque__*``. Bound to ``sort`` on first use; a later call with a
        different sort returns None (type-conflict abort), mirroring
        ``column`` / ``opaque``. A number is a real unless
        ``self.integers``, as for ``column``.
        """
        if sort == z3.IntSort() and not self.integers:
            sort = z3.RealSort()
        elif sort == z3.RealSort() and self.integers:
            sort = z3.IntSort()  # the integer pass, as for ``column``
        existing = self._session_vars.get(key)
        if existing is None:
            var = z3.Const(f"{_SESSION_PREFIX}{key}", sort)
            self._session_vars[key] = var
            return var
        if existing.sort() == sort:
            return existing
        return None  # type conflict — translation aborts


def _column_key(node: ColumnRef, ctx: _Context) -> str:
    """Render `ColumnRef.fields` as a `.`-joined identifier key.

    A column reference's `fields` is a tuple of `String` nodes (or
    `A_Star` for wildcards, which we don't support). Returns None
    for unsupported shapes, and for a column `ctx` has seen spelled
    otherwise (`t.a` and `m.a`, which `_bare_columns` leaves as they are):
    as two variables they gave a leaking row that cannot exist.
    """
    parts = []
    for field in node.fields or ():
        if isinstance(field, String):
            parts.append(field.sval)
        else:
            return ""  # unsupported (e.g., A_Star)
    if not parts or ctx.spellings.setdefault(parts[-1], tuple(parts)) != tuple(parts):
        return ""
    key = ".".join(parts)
    # A real column whose key collides with a synthetic marker namespace
    # would alias the marker var in the implication query (Z3 keys a
    # constant by name+sort), silently making distinct predicates look
    # equivalent. Such a column name is pathological but legal (a quoted
    # identifier may be literally `_nullflag__x`), so refuse to bind it:
    # return "" and the caller degrades the predicate to requires_review
    # (the safe direction). See `_RESERVED_MARKER_PREFIXES`.
    if key.startswith(_RESERVED_MARKER_PREFIXES):
        return ""
    return key


def _const_to_z3(node: A_Const, ctx: _Context) -> Any:
    """Translate an A_Const literal to a Z3 expression. Returns None for unsupported.

    An integer is a real unless `ctx.integers`: the column it is compared
    with may be a `numeric` or a `float8` (`score >= 1` and `score > 0`
    differ at 0.5), which the policy text does not say unless a cast does;
    read as a real it is what every numeric type agrees on (a float4 holds
    it exactly). The integer reading only refines a verdict (see
    `_integers_agree`)."""
    val = node.val
    if isinstance(val, Integer):
        return _integer(val.ival, ctx)
    if isinstance(val, String):
        return _z3_string(val.sval)
    if isinstance(val, Boolean):
        return z3.BoolVal(val.boolval)
    if isinstance(val, Float):
        # pglast keeps a Float as its text — an integer too big for an int4
        # among them, which is read exactly (through a Python float, two
        # past double precision became one value).
        text = val.fval or ""
        try:
            if re.fullmatch(r"[+-]?\d+", text):
                return _integer(int(text), ctx)
        except (ValueError, TypeError, z3.Z3Exception):
            return None
        # A decimal reads differently against a `numeric` (exactly), a
        # `float8` (rounded to a double) and, in an `IN` list, a `float4`
        # (rounded to a single), and pgrls does not see which: it is
        # translated only when all three agree.
        return _exact_real(text)
    # Anything else (NULL literal, BitString, etc.) — out of scope.
    # In particular, `col = NULL` is always-false in Postgres but
    # users express that with `IS NULL` instead; if we see a literal
    # NULL on either side of a comparison, return None and let the
    # caller fall through to requires_review.
    return None


def _is_constant(node: Any) -> bool:
    """A literal, through casts that keep its type's value (`1::real` gives
    its neighbours the float4 type)."""
    while isinstance(node, TypeCast):
        if not _exact_cast(node.typeName):
            return False
        node = node.arg
    return isinstance(node, A_Const)


def _integer(number: int, ctx: _Context) -> Any:
    """An integer literal: as a real (`_real_integer`), or in the integer
    pass as an integer."""
    return z3.IntVal(number) if ctx.integers else _real_integer(number, ctx)


def _has_lossy_cast(node: Any) -> bool:
    """Whether `node` holds a cast that may change a value anywhere in it
    (`(SELECT 0::real)`, `0::real * 1::real` give its value that type)."""
    return any(isinstance(n, TypeCast) and not _exact_cast(n.typeName)
               for n in _ast_nodes(node))


def _rounds_its_kin(node: Any, ctx: _Context) -> bool:
    """Whether `node`, beside others given its type (a `COALESCE`, an `IN`
    list, an array), may round them: a value-changing cast to a number type
    (`0::real`, `1::numeric(3,1)`). In a diff, any value-changing cast — the
    text does not say what it does to its kin; off it, a cast to `uuid`, an
    enum or `date` keeps the literal's value and its kin's (`pg_get_expr`
    writes `ARRAY['draft'::post_status, …]`)."""
    if ctx.any_session:
        return _has_lossy_cast(node)
    return any(isinstance(n, TypeCast) and not _exact_cast(n.typeName)
               and _typename_last_segment(n.typeName) in _NUMBER_TYPES
               for n in _ast_nodes(node))


def _note_string_read(ctx: Any, left: Any, rights: Sequence[Any]) -> None:
    """In a diff, note how `left` compared with each of `rights` (one, or an
    `IN` list's members, which take one type) reads each column the operands
    yield against a string: bare (`email = 'A'`, `COALESCE(x, 'a') = 'A'`),
    where the literal takes the column's type, or typed (`'A'::text`,
    `(SELECT 'A')`, `COALESCE('A', '')`, a typed list member, a function's
    result), where a `citext` or `char(n)` column compares as text. The text
    may not show the column's type, so a column read both ways decides
    nothing (`_diff_truths`)."""
    if not ctx.any_session or ctx.string_scope:
        return
    sides = [_string_operand(left), *(_string_operand(r) for r in rights)]
    if not any(kind == "bare" for _, kind in sides) and not any(
            kind == "typed" for _, kind in sides):
        return  # column against column, or no string at all
    typed = any(kind == "typed" for _, kind in sides)
    for columns, _ in sides:
        for column in columns:
            ctx.string_reads.setdefault(column, set()).add(typed)


def _string_operand(node: Any) -> tuple[frozenset[str], str]:
    """The columns `node` yields as its value and how it is typed: `column`
    (it takes a column's type), `bare` (an untyped string literal), `typed`
    (a string of a known type, or anything else: a function, a cast), or
    `other` (a number, a NULL)."""
    inner = _unwrap_scalar_sublink(node)
    if inner is not node and isinstance(inner, A_Const):
        # `(SELECT 'A')` is text, as a select list makes a bare literal.
        return frozenset(), "typed"
    node = inner
    if isinstance(node, ColumnRef):
        last = node.fields[-1] if node.fields else None
        return (frozenset({last.sval}) if isinstance(last, String) else frozenset()), "column"
    if isinstance(node, A_Const):
        return frozenset(), "bare" if isinstance(getattr(node, "val", None), String) else "other"
    arms: list[Any] | None = None
    if isinstance(node, (CoalesceExpr, MinMaxExpr)):
        arms = list(node.args or ())
    elif isinstance(node, CaseExpr):
        arms = [w.result for w in node.args or ()] + [node.defresult]
    if arms is not None:
        # Its arms take one type: a typed arm's, else a column's, else text.
        parts = [_string_operand(arm) for arm in arms if arm is not None]
        columns = frozenset().union(*(c for c, _ in parts))
        kinds = {k for _, k in parts}
        if "typed" in kinds or not columns and "bare" in kinds:
            return columns, "typed"
        return columns, "column" if columns else "other"
    columns = frozenset(n.fields[-1].sval for n in _ast_nodes(node)
                        if isinstance(n, ColumnRef) and n.fields
                        and isinstance(n.fields[-1], String))
    return columns, "typed"


def _blanks_its_kin(members: Sequence[Any], ctx: Any) -> bool:
    """Off the diff path, whether a member cast to a text type that changes a
    value (`'a'::bpchar`, `'z'::"char"`, `name`) gives that type to a bare
    string literal beside it, which then compares as that type does
    (`'b'::text = ANY(ARRAY['a'::bpchar, 'b '])` holds: `bpchar` ignores the
    trailing space). A list `pg_get_expr` writes casts every member."""
    if ctx.any_session:
        return False  # `_has_lossy_cast` already abstains there
    return any(isinstance(n, TypeCast) and not _exact_cast(n.typeName)
               and _typename_last_segment(n.typeName) in _STRING_TYPES - {"uuid"}
               for m in members for n in _ast_nodes(m)) and any(
        isinstance(m, A_Const) and isinstance(getattr(m, "val", None), String)
        for m in members)


def _floats_meet(left: Any, right: Any) -> bool:
    """Whether a value cast to a float type meets a non-constant one, which
    Postgres converts to float too, rounding it (`a = 1::float8` reads a
    `numeric` or past-2^53 `int8` column `a` through a double)."""
    return ((_floatish(left) and not _is_constant(right))
            or (_floatish(right) and not _is_constant(left)))


def _cast_value_meets_column(left: Any, right: Any) -> bool:
    """Whether a column meets a value cast to a number type that is not a
    literal (`amount = current_setting('app.v')::numeric`): Postgres converts
    the value to the column's type, a float's too, rounding it, and the text
    of an offline snapshot does not say which (a live one writes the cast)."""
    return ((_holds_column(left) and _casts_a_value(right))
            or (_holds_column(right) and _casts_a_value(left)))


def _ordered_truth(op: str, left: Any, right: Any, ctx: _Context,
                   assertions: list[Any]) -> Any:
    """`left op right` for two non-NULL values compared in a type the text
    does not show (a column meeting a cast value, in a diff): an order of
    its own over the two, the same one wherever the same two are compared,
    either way round, so a clause both sides share cancels and `=` → `>=`
    is a loosening. Exactly one of `<`, `=`, `>` holds, as in any btree
    type's order (NaN included); a type with no btree order may break it
    (`lseg`'s `=` compares endpoints, its `<` lengths), as on `main`, which
    read such a pair through Z3's own order."""
    lhs, rhs = _canon(left), _canon(right)
    if lhs > rhs:
        lhs, rhs, op = rhs, lhs, _MIRRORED.get(op, op)
    key = f"order {lhs!r} {rhs!r}"
    known = f"{key} =" in ctx._opaque_vars
    lt, eq, gt = (ctx.opaque(f"{key} {o}", z3.BoolSort()) for o in "<=>")
    if not known:
        assertions.append(z3.PbEq([(lt, 1), (eq, 1), (gt, 1)], 1))
    return {"=": eq, "<>": z3.Not(eq), "!=": z3.Not(eq), "<": lt, ">": gt,
            "<=": z3.Or(lt, eq), ">=": z3.Or(gt, eq)}[op]


_MIRRORED = {"<": ">", ">": "<", "<=": ">=", ">=": "<="}


def _holds_column(node: Any) -> bool:
    """Whether a column is anywhere in `node`: `COALESCE(amount, 0)` has
    `amount`'s type."""
    return any(isinstance(n, ColumnRef) for n in _ast_nodes(node))


def _casts_a_value(node: Any) -> bool:
    return any(isinstance(n, TypeCast) and not _is_constant(n.arg)
               and _typename_last_segment(n.typeName) in _NUMBER_TYPES
               for n in _ast_nodes(node))


_NUMBER_TYPES = frozenset({
    "int2", "int4", "int8", "int", "integer", "bigint", "smallint", "numeric", "decimal",
    "float4", "float8", "oid",
})


def _floatish(node: Any) -> bool:
    """Whether `node` holds a value of a float type: a float cast, or a
    built-in that returns one (for some argument type)."""
    return any((isinstance(n, TypeCast)
                and _typename_last_segment(n.typeName) in ("float4", "float8"))
               or (isinstance(n, FuncCall) and func_name_parts(n)[1] in _FLOAT_FUNCTIONS)
               for n in _ast_nodes(node))


# Built-ins that return a float for some argument type.
_FLOAT_FUNCTIONS = frozenset({
    "pi", "sqrt", "cbrt", "power", "pow", "exp", "ln", "log", "log10", "float4", "float8",
    "date_part", "degrees", "radians", "sin", "cos", "tan", "cot", "asin", "acos", "atan",
    "atan2", "sind", "cosd", "tand", "cotd", "asind", "acosd", "atand", "atan2d", "sinh",
    "cosh", "tanh", "asinh", "acosh", "atanh", "random", "random_normal", "erf", "erfc",
    "to_timestamp", "extract",
})


def _real_integer(number: int, ctx: _Context) -> Any:
    """An integer literal as a real: exactly, up to where a `float8` holds
    it (an `int8` compared with one is rounded past 2^53), and among values
    Postgres gives one type (`ctx.unified`: an `IN` list, a `COALESCE`, an
    array with a column in it) only where a `float4` does (measured: a
    `float4` column reads `IN (16777217, 1)` and `COALESCE(g, 16777217)`
    through a float4, `= 16777217` not)."""
    if ctx.unified:
        return _exact_real(str(number))
    return z3.RealVal(number) if abs(number) <= 2**53 else None


def _exact_real(text: str) -> Any:
    """`text`'s number as a Z3 real when it is Postgres numeric syntax and a
    `float4` holds it exactly — so a `numeric`, a `float8` and a `float4`
    read it alike — else None."""
    m = re.fullmatch(r"\s*[+-]?(\d+\.?\d*|\.\d+)(?:[eE]([+-]?\d+))?\s*", text, re.ASCII)
    # A float4 holds nothing past 1e39 or with more digits than its exact
    # subnormals have; `Fraction` would build `1e999999999` exactly first.
    if (m is None or len(m.group(1)) > 200
            or len((m.group(2) or "").lstrip("+-").lstrip("0")) > 5
            or abs(int(m.group(2) or 0)) > 200):
        return None
    exact = fractions.Fraction(text.strip())
    try:
        single = struct.unpack("f", struct.pack("f", float(exact)))[0]
    except (OverflowError, struct.error):
        return None
    if not math.isfinite(single) or fractions.Fraction(single) != exact:
        return None
    return z3.Q(exact.numerator, exact.denominator)


def _z3_string(text: str) -> Any:
    """`text` as a Z3 string constant. ``StringVal`` reads ``\\u{…}`` escapes
    in its argument (``'\\u{41}'`` would be ``'A'``), so each backslash goes
    in escaped — a policy's ``'\\u{41}'`` is those six characters. None for
    a character past U+2FFFF, where Z3's alphabet ends: it would stand for
    the text of its own escape."""
    if any(ord(c) > 0x2FFFF for c in text):
        return None
    return z3.StringVal(text.replace("\\", "\\u{5c}"))


def _z3_value(val: object) -> Any:
    """A decoded witness value as a Z3 constant to pin a column to — a
    string through `_z3_string`, which Z3's own coercion would not use."""
    return _z3_string(val) if isinstance(val, str) else val


# Cast targets that keep the value of a column, a literal or another such
# cast (an out-of-range integer raises rather than changing): a cast to one
# of these, with no type modifier, of a value Z3 already holds in that sort
# leaves it as it is; one that changes sort, like `1.5::int`, is opaque,
# except a string literal Postgres reads exactly (`'5'::int`).
# Any other —
# `varchar(3)` truncates, `char` is `char(1)`, `bpchar` ignores trailing
# spaces, `numeric(4,1)` and `float4` round, `oid` wraps a negative integer
# — makes a value of its own (an opaque one, which the same cast in both
# predicates shares).
_EXACT_CAST_TARGETS = frozenset({
    "text", "varchar", "int", "int4", "integer", "int8", "bigint", "bool",
    "boolean", "numeric", "decimal",
})


def _exact_cast(typename: Any) -> bool:
    """Whether a cast to `typename` keeps the value (see `_EXACT_CAST_TARGETS`)."""
    return (
        _typename_last_segment(typename) in _EXACT_CAST_TARGETS
        and not getattr(typename, "typmods", None)
        and not getattr(typename, "arrayBounds", None)
    )


def _bare_type(typename: Any, name: str) -> bool:
    """Whether `typename` is `name` with no type modifier or array bounds."""
    return (
        _typename_last_segment(typename) == name
        and not getattr(typename, "typmods", None)
        and not getattr(typename, "arrayBounds", None)
    )


def _keeps_its_type(node: Any) -> bool:
    """Whether `node` is a column, a literal, or a value-keeping cast of one —
    a value a further cast to an exact target reads as the diff path models
    it."""
    node = _unwrap_scalar_sublink(node)
    if isinstance(node, (ColumnRef, A_Const)):
        return True
    return (isinstance(node, TypeCast) and _exact_cast(node.typeName)
            and _keeps_its_type(node.arg))


def _typename_last_segment(typename: Any) -> str | None:
    """The bare type name of a pglast ``TypeName`` (`int4`, `numeric`), or
    None — used to range-check an integer fold against the RIGHT width."""
    segments = getattr(typename, "names", None) or ()
    last = segments[-1] if segments else None
    return last.sval.lower() if isinstance(last, String) else None


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


def _canon(node: Any) -> str:
    """Canonical RawStream rendering of an AST node."""
    rendered: str = RawStream()(node)
    return rendered


_Z3Result = Literal["semantic_equivalent", "semantic_tightened", "semantic_loosened"]


_F = TypeVar("_F", bound=Callable[..., Any])


def _bare_columns(*names: str) -> Callable[[_F], _F]:
    """Run the decorated prover with the named predicate arguments' columns
    written bare, and restore them after: `pg_get_expr` qualifies a column
    in a sub-select (`t.a`) and not outside it (`a`), one column. Outside a
    sub-select with a FROM, a qualified column can only be the policy's own
    table's (a composite's field needs `(c).f`), so the qualifiers must
    agree; if they do not, the columns stay as they are (and `_column_key`
    declines to read a column spelled two ways). In place, not a copy: a
    copy of a predicate a few hundred levels deep overflows the stack."""

    def wrap(fn: _F) -> _F:
        signature = inspect.signature(fn)

        @functools.wraps(fn)
        def run(*args: Any, **kwargs: Any) -> Any:
            bound = signature.bind_partial(*args, **kwargs).arguments
            undo = _write_bare([bound.get(name) for name in names])
            try:
                return fn(*args, **kwargs)
            finally:
                for ref, fields in undo:
                    ref.fields = fields
        return cast(_F, run)
    return wrap


def _write_bare(nodes: list[Any]) -> list[tuple[Any, Any]]:
    """Write each qualified column in `nodes` bare (see `_bare_columns`),
    returning what to restore."""
    refs: dict[int, tuple[Any, Any]] = {}
    qualifier = None
    stack: list[Any] = list(nodes)
    while stack:
        node = stack.pop()
        if isinstance(node, (list, tuple)):
            stack.extend(node)
        elif isinstance(node, SelectStmt) and node.fromClause:
            continue  # its columns can be another table's
        elif isinstance(node, ColumnRef):
            fields = tuple(node.fields or ())
            if len(fields) > 1 and all(isinstance(f, String) for f in fields):
                q = tuple(f.sval for f in fields[:-1])
                if qualifier not in (None, q):
                    return []
                qualifier = q
                refs[id(node)] = (node, node.fields)
        elif isinstance(node, Node):
            stack.extend(getattr(node, f, None) for f in node)
    for ref, fields in refs.values():
        ref.fields = tuple(fields)[-1:]
    return list(refs.values())


@_bare_columns("base_node", "head_node")
def _diff_truths(base_node: Any, head_node: Any, *, integers: bool = False
                 ) -> tuple[_Context, list[Any], _TV, _TV] | None:
    """Both predicates as Kleene truths over one context (so a column or an
    opaque expression is the same variable in both), with the assertions
    their free boolean leaves need — None when either does not translate.

    A row passes a policy only when the predicate is exactly TRUE: NULL hides
    it as FALSE does. So the predicates are compared on ``is_true``, over
    every row including ones holding NULLs, and over any session (no auth
    call or GUC is assumed NULL or unset)."""
    ctx = _Context()
    ctx.any_session = True
    ctx.integers = integers
    assertions: list[Any] = []
    base = _lift_to_tv(_anon_3vl(base_node, ctx, set(), assertions), assertions)
    head = _lift_to_tv(_anon_3vl(head_node, ctx, set(), assertions), assertions)
    if base is None or head is None or any(len(reads) > 1 for reads in ctx.string_reads.values()):
        return None
    return ctx, assertions, base, head




def _abstains_when_too_deep(result: Any) -> Callable[[_F], _F]:
    """Return `result` (the entry point's "decided nothing") instead of a
    RecursionError on a predicate nested past the stack — Postgres accepts
    hundreds of levels of COALESCE."""
    def wrap(fn: _F) -> _F:
        @functools.wraps(fn)
        def inner(*args: Any, **kwargs: Any) -> Any:
            try:
                return fn(*args, **kwargs)
            except RecursionError:
                return result
            except ctypes.ArgumentError as exc:
                # Z3's ctypes layer re-raises a RecursionError as this.
                if "RecursionError" not in str(exc):
                    raise
                return result
        return cast(_F, inner)
    return wrap


@_abstains_when_too_deep(None)
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

    Implication is over the rows each predicate admits — the ones it is
    exactly TRUE for under SQL's three-valued logic (see `_diff_truths`).
    """
    if not Z3_AVAILABLE:
        return None
    verdict = _classify(base_node, head_node, integers=False)
    if verdict in ("semantic_loosened", _UNTRANSLATED):
        # Loosened only where a column is not an integer one, which the
        # text does not say, is no verdict; one the reals cannot read (an
        # integer a float4 rounds) is loosened if an integer row leaks.
        again = _classify(base_node, head_node, integers=True)
        return "semantic_loosened" if again == "semantic_loosened" else None
    return cast("_Z3Result | None", verdict)


# `_classify`'s "the predicates do not translate".
_UNTRANSLATED = "untranslated"


def _classify(base_node: Any, head_node: Any, *, integers: bool) -> Any:
    truths = _diff_truths(base_node, head_node, integers=integers)
    if truths is None:
        return _UNTRANSLATED
    _, assertions, base, head = truths

    base_implies_head = _implies(base.is_true, head.is_true, assertions)
    head_implies_base = _implies(head.is_true, base.is_true, assertions)

    if base_implies_head and head_implies_base:
        return "semantic_equivalent"
    if head_implies_base and not base_implies_head:
        return "semantic_tightened"
    if base_implies_head and not head_implies_base:
        return "semantic_loosened"
    return None


def _implies(p: Any, q: Any, assertions: Sequence[Any] = ()) -> bool:
    """Return True iff `p → q` is valid under `assertions` (i.e.
    `assertions AND p AND NOT q` is UNSAT)."""
    solver = z3.Solver()
    # Bound the search: real-world RLS predicates resolve in
    # milliseconds, but a pathologically constructed predicate with
    # deep quantifier alternation could otherwise hang. 1 second is
    # comfortable for the supported subset.
    solver.set("timeout", 1000)
    for a in assertions:
        solver.add(a)
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
    ``_nullflag__*`` / ``_opaque__*`` / ``_session__*`` vars are dropped — and decodes
    each value by its Z3 sort, one-to-one with the constructors in
    ``_const_to_z3`` (Int → ``as_long``, String → ``as_string``,
    Bool → ``z3.is_true``, Real → ``float(as_fraction())``, left out when
    it is beyond a double's range; a witness gate declines a row whose
    float no longer witnesses the leak). Any other sort is omitted
    (defensive). ``model.decls()`` yields only the
    constants Z3 actually assigned; a don't-care column is simply
    absent and is never fabricated.
    """
    row: dict[str, object] = {}
    for decl in model.decls():
        name = decl.name()
        if not ctx.is_real_column(name):
            continue  # skip the synthetic vars
        value = model[decl]
        sort = value.sort()
        if sort == z3.IntSort():
            row[name] = value.as_long()
        elif sort == z3.StringSort():
            # `as_string` escapes every character past U+00FF, and the
            # backslash `_z3_string` escaped, as `\\u{…}`.
            row[name] = re.sub(r"\\u\{([0-9a-fA-F]+)\}",
                               lambda m: chr(int(m.group(1), 16)), value.as_string())
        elif sort == z3.BoolSort():
            row[name] = z3.is_true(value)
        elif sort == z3.RealSort():
            try:
                row[name] = float(value.as_fraction())
            except OverflowError:
                pass
        # any other sort: omit (defensive)
    return row


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


@_abstains_when_too_deep(None)
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
      witness — the leak depends on an opaque (function / GUC / COALESCE /
      CASE) value the row cannot express, or on a column being NOT NULL
      that the predicates only test for NULL (the row pins a column NULL,
      but has no value to give one that must not be). In that case we
      emit NO counterexample
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
    # An integer row leaks whatever numeric type a column is.
    truths = _diff_truths(base_node, head_node, integers=True)
    if truths is None:
        return None
    ctx, assertions, base, head = truths
    leaks = z3.And(head.is_true, z3.Not(base.is_true))
    solver = z3.Solver()
    solver.set("timeout", 1000)
    for a in assertions:
        solver.add(a)
    # SAME formula as _implies(head, base) — we keep the model.
    solver.add(leaks)
    if solver.check() != z3.sat:
        return None  # soundness guard: no model ⇒ no claim
    model = solver.model()
    row = _decode_model(model, ctx)
    # A column the model makes NULL is NULL in the row, whatever value its
    # (then irrelevant) value variable took.
    for key in {*ctx._vars, *ctx.null_tested}:
        flag = model[ctx.null_flag(key)] if key in ctx._nullflag_vars else None
        if flag is not None and z3.is_true(flag):
            row[key] = None
    # Soundness gate (critique #1/#2): the real-column projection must
    # be a witness on its own, independent of the dropped synthetic
    # vars. An empty row (all-opaque/all-GUC loosen) is sufficient iff
    # EVERY row leaks — which is exactly when the gate passes; for the
    # common GUC-only loosen it does not, so we return None.
    if not _diff_witness_is_sufficient(row, leaks, ctx, assertions):
        return None
    return row


def _diff_witness_is_sufficient(
    row: dict[str, object], leaks: Any, ctx: _Context, assertions: list[Any]
) -> bool:
    """True iff pinning `row`'s columns — each one's value and null-flag, a
    ``None`` as NULL — forces `leaks` for every completion of the rest: the
    variables it does not pin (opaque values, other columns) are free, so
    only then does every row matching `row` lie inside HEAD \\ BASE."""
    pins = []
    for key, val in row.items():
        if val is None:
            pins.append(ctx.null_flag(key))
            continue
        var = ctx.column(key, _py_value_sort(val))
        if var is None:  # pragma: no cover - _py_value_sort inverts the bound sort
            return False
        pins.extend((var == _z3_value(val), z3.Not(ctx.null_flag(key))))
    solver = z3.Solver()
    solver.set("timeout", 1000)
    for a in assertions:
        solver.add(a)
    solver.add(*pins)
    solver.add(z3.Not(leaks))
    return bool(solver.check() == z3.unsat)


# ===========================================================================
# H2 (SEC038) — semantic anonymous-read property via Kleene three-valued
# (3VL) logic. The diff path above (`classify_via_z3` / `counterexample`)
# runs on the same encoder, under `_Context.any_session`.
#
# The property: a read-capable policy (FOR ALL / FOR SELECT) leaks to
# anonymous iff its USING predicate, evaluated under a session where every
# auth-context function in the configured set (auth.uid/role/jwt,
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
    """A non-boolean (scalar) value plus its Kleene null-flag.

    ``unset`` marks a value read from a GUC that is UNSET for the session
    being modeled, so evaluating it RAISES instead of producing a value —
    the statement errors and the caller gets no rows. It is deliberately
    NOT the same thing as ``is_null``: the call never *returns* NULL (see
    ``is_never_null_current_setting``), so ``is_null`` stays False and
    ``current_setting('app.t') IS NULL OR …`` remains the dead disjunct
    R12/R13 pinned — while comparisons against the value resolve to Kleene
    U rather than a free existential. Only ever set on the anon path.
    """

    value: Any            # z3.ExprRef
    is_null: Any          # z3.BoolRef
    unset: bool = False


# Auth-context functions forced to NULL under an anonymous session.
# Mirrors SEC004 / SEC038. Only genuinely-nullable functions belong:
# current_user / session_user / current_role / user are EXCLUDED because
# they always return the session role name (never NULL — there is no
# unauthenticated backend), so treating them as anon-NULL would make an
# inverted `current_user IS NULL OR …` prove valid and false-fire. A
# caller may still pass them in an explicit `auth_funcs` set (the
# SQLValueFunction branch / _ANON_SVFOP_NAMES honors a configured name).
_DEFAULT_AUTH_FUNCTIONS: frozenset[str] = frozenset({
    "auth.uid",
    "auth.role",
    "auth.jwt",
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
        # A never-NULL builtin current_setting — the one-arg form, or the
        # two-arg current_setting(name, false) — RAISES on an unset GUC and
        # is otherwise a non-NULL string, so it is NEVER NULL. Modeling it
        # as anon-NULL would make `current_setting('x') IS NULL OR …` prove
        # valid and false-fire (mirrors SEC004 via the shared guard). Only
        # the two-arg current_setting(name, true) is NULLable under anon.
        if is_never_null_current_setting(node):
            return False
        if (func_name_parts(node)[0] in ("current_setting", "pg_catalog.current_setting")
                and not has_literal_setting_arguments(node)):
            # A name or missing_ok read from a column: neither the session's
            # identity nor NULL under anon, but whatever the row makes it.
            return False
        if qualified in auth_funcs:
            return True
        # Bare-name fallback: an UNQUALIFIED call has qualified == bare
        # and is already covered above. The fallback therefore only
        # ever fires for a *schema-qualified* call matched by its last
        # component — and a user-defined `myschema.current_setting()`
        # is a DIFFERENT function from the pg_catalog builtin, so
        # forcing it to NULL would be a SEC038 false positive. Only
        # honor the bare match for the pg_catalog builtins.
        if qualified.startswith("pg_catalog.") and bare in auth_funcs:
            return True
        return False
    if isinstance(node, SQLValueFunction):
        name = _ANON_SVFOP_NAMES.get(node.op)
        return name is not None and name in auth_funcs
    return False


def _first_string_arg(node: Any) -> str | None:
    """The first argument of a FuncCall when it is a string literal.

    `pg_get_expr` renders literals with casts (`'x'::text`), so the argument
    is usually a `TypeCast` around the `A_Const`; unwrap it — matching only a
    bare `A_Const` is a silent no-op on every catalog-read policy.
    """
    args = getattr(node, "args", None) or ()
    if not args:
        return None
    arg = args[0]
    while isinstance(arg, TypeCast):
        arg = arg.arg
    if not isinstance(arg, A_Const):
        return None
    val = getattr(arg, "val", None)
    return val.sval if isinstance(val, String) else None


def _computes_missing_ok(node: Any) -> bool:
    """`current_setting(<literal name>, <missing_ok not a literal>)`."""
    qualified, _bare = func_name_parts(node)
    args = node.args or ()
    return (qualified in ("current_setting", "pg_catalog.current_setting")
            and len(args) == 2 and _first_string_arg(node) is not None
            and not has_literal_setting_arguments(node))


def _is_builtin_current_setting_call(node: Any) -> bool:
    """A call of the built-in `current_setting` with literal arguments; one
    with a computed name or missing_ok is an opaque value."""
    qualified, bare = func_name_parts(node)
    return bare == "current_setting" and qualified in (
        "current_setting",
        "pg_catalog.current_setting",
    ) and has_literal_setting_arguments(node)


def _is_jwt_role_extraction(node: Any) -> bool:
    """`<jwt blob> ->> 'role'` where the blob is `auth.jwt()` or the claims GUC
    (through any casts) — the anon-key caller's role claim, i.e. 'anon'."""
    if not isinstance(node, A_Expr) or node.kind != A_Expr_Kind.AEXPR_OP:
        return False
    names = list(node.name or ())
    if len(names) != 1 or not isinstance(names[0], String) or names[0].sval != "->>":
        return False
    key = node.rexpr
    while isinstance(key, TypeCast):
        key = key.arg
    if not (isinstance(key, A_Const) and isinstance(getattr(key, "val", None), String) and key.val.sval == "role"):
        return False
    blob = node.lexpr
    while isinstance(blob, TypeCast):
        blob = blob.arg
    return _anon_jwt_claim(blob) == "jwt"


def _anon_jwt_claim(node: Any) -> str | None:
    """Which anon-key JWT claim `node` reads, under the anon-JWT session.

    ``"role"`` for `auth.role()` and `current_setting('request.jwt.claim.role'
    [, …])` — the claim PostgREST sets to ``'anon'`` for an anon-key caller;
    ``"jwt"`` for `auth.jwt()` and `current_setting('request.jwt.claims'[, …])`
    — the claims blob, non-null for that caller; ``None`` otherwise (`auth.uid()`
    / the `sub` claim stay NULL: an anon key carries no subject).
    """
    if not isinstance(node, FuncCall):
        return None
    qualified, bare = func_name_parts(node)
    if qualified is None:
        return None
    if qualified == "auth.role":
        return "role"
    if qualified == "auth.jwt":
        return "jwt"
    if _is_builtin_current_setting_call(node):
        # Postgres reads a setting's name ignoring case.
        name = (_first_string_arg(node) or "").lower()
        if name == "request.jwt.claim.role":
            return "role"
        if name == "request.jwt.claims":
            return "jwt"
    return None


def _reads_unset_guc_under_anon(node: Any) -> bool:
    """True iff ``node`` reads a *custom* GUC an anonymous session cannot
    have set — so evaluating it RAISES rather than yielding a value.

    A custom ("placeholder") GUC name MUST contain a dot — ``app.tenant_id``,
    ``request.jwt.claims`` — and a stock server ships none of them set
    (``SELECT count(*) FROM pg_settings WHERE name LIKE '%.%'`` is 0 on a
    fresh PG16), so a session that never ran ``SET`` errors reading one.

    A NON-dotted name is a BUILT-IN GUC: always set, and mostly ``USERSET``
    (``search_path``, ``role``, ``timezone``), i.e. genuinely caller-
    controlled — those keep a free value and go on reporting a leak. A
    computed name (``current_setting(some_col)``) is unclassifiable and is
    treated the same conservative way.

    Only meaningful for a never-NULL ``current_setting`` (the one-arg and
    two-arg ``missing_ok=false`` forms); the caller gates on that.

    The name argument is unwrapped through any ``TypeCast`` first: a policy
    read back from the catalog comes via ``pg_get_expr``, which renders the
    literal as ``current_setting('app.tenant'::text)``, so the bare-literal
    shape only ever appears in hand-written SQL.

    THREAT MODEL: this assumes the auth-context GUC is set by the
    application from a verified credential and an anonymous caller cannot
    set it — a caller with raw SQL *can* (``SET app.tenant_id = …`` needs no
    privilege). That is the same assumption that already makes
    ``auth.uid()`` and ``current_setting(name, true)`` provably isolated
    here; without it no GUC-based tenancy scheme is verifiable at all. The
    point of this helper is that all four spellings now share it.
    """
    args = getattr(node, "args", None) or ()
    if not args:
        return False
    name = args[0]
    while isinstance(name, TypeCast):
        name = name.arg
    if not isinstance(name, A_Const):
        return False
    val = getattr(name, "val", None)
    if not isinstance(val, String):
        return False
    return "." in (val.sval or "")


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
    # `(SELECT (SELECT x))` is `x` too — a loop, not a recursion, so a deep
    # nesting cannot exhaust the stack.
    while True:
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
        # SELECT. Reject UNION/INTERSECT/EXCEPT and any FROM/WHERE/
        # aggregation shape — those aren't a bare scalar — and a LIMIT /
        # OFFSET, which can make it NULL (`(SELECT x LIMIT 0)`).
        if (
            sel.fromClause
            or sel.whereClause
            or int(sel.op) != 0
            or sel.distinctClause
            or sel.groupClause
            or sel.havingClause
            or sel.limitCount is not None
            or sel.limitOffset is not None
            # A set-returning function in ORDER BY or a WINDOW makes it NULL
            # when it yields no row.
            or sel.sortClause
            or sel.windowClause
        ):
            return node
        target = target_list[0]
        if not isinstance(target, ResTarget):
            return node
        # (One in the target is `_anon_3vl`'s: see `_may_yield_no_row`.)
        node = target.val


def _ast_nodes(node: Any) -> Any:
    """`node` and every pglast node beneath it."""
    stack = [node]
    while stack:
        n = stack.pop()
        if isinstance(n, (list, tuple)):
            stack.extend(n)
        elif isinstance(n, Node):
            yield n
            stack.extend(getattr(n, f, None) for f in n)


def _may_yield_no_row(target: Any, auth_funcs: set[str]) -> bool:
    """Whether the target of a scalar sub-select calls anything that may be
    set-returning: any call but an auth function (the configured ones and
    the defaults, on the diff path too, which configures none) or the
    built-in `current_setting`; the arguments are walked too."""
    known = auth_funcs | _DEFAULT_AUTH_FUNCTIONS
    return any(
        isinstance(n, FuncCall) and not _is_anon_null_leaf(n, known)
        and func_name_parts(n)[0] not in ("current_setting", "pg_catalog.current_setting")
        for n in _ast_nodes(target))


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
        if x.unset:
            # An unset-GUC read used directly as a predicate raises → no
            # rows. U, not a free bool (same reasoning as `_anon_binop`).
            return _TV(is_true=z3.BoolVal(False), is_null=z3.BoolVal(True))
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
    ``any(... is None)`` pattern).

    ``assertions`` collects leaf-exclusivity constraints (§ amendment #1);
    the caller adds them to BOTH the validity and witness solvers.

    Every call unwraps a scalar SubLink first, then checks the anon-NULL
    leaf BEFORE the generic FuncCall / SQLValueFunction branches.
    """
    inner = _unwrap_scalar_sublink(node)
    if inner is not node and _may_yield_no_row(inner, auth_funcs):
        # A call in the target may be set-returning, which a name cannot tell
        # apart, and yield no row: the sub-select is then NULL whatever its
        # target reads (`(SELECT srf() IS NULL)` is NULL, not TRUE). The same
        # sub-select shares the one flag, in base and head alike.
        result = _anon_3vl(inner, ctx, auth_funcs, assertions)
        if result is None:
            return None
        # Keyed by the target: Postgres renders `(SELECT f() AS f)`.
        no_row = ctx.opaque(f"no_row {_canon(inner)}", z3.BoolSort())
        if no_row is None:
            return None
        if isinstance(result, _TV):
            return _TV(is_true=z3.And(result.is_true, z3.Not(no_row)),
                       is_null=z3.Or(result.is_null, no_row))
        return dataclasses.replace(result, is_null=z3.Or(result.is_null, no_row))
    node = inner

    # --- auth-context leaf: auth.uid()/role()/jwt(), current_setting(...),
    # current_user, session_user. Checked before the generic FuncCall
    # branch. Two contexts:
    #   * anon (default) — forced to NULL: value is irrelevant, is_null
    #     unconditionally True (an unauthenticated session has no identity).
    #   * session_mode (cross-tenant verifier) — a free, NON-NULL symbol
    #     standing for the authenticated session's own tenant identity, so
    #     `auth.uid() IS NULL` is definitively FALSE. The inverted-auth
    #     `... IS NULL OR ...` anon leak is a DIFFERENT threat (an
    #     authenticated attacker, not an anonymous one) caught by the anon
    #     path; here we ask only whether one tenant can read another's row.
    if ctx.anon_jwt and not ctx.session_mode:
        # `auth.jwt() ->> 'role'` / `current_setting('request.jwt.claims',
        # true)::jsonb ->> 'role'` — the JSON spelling of the role claim.
        if _is_jwt_role_extraction(node):
            return _Val(value=z3.StringVal("anon"), is_null=z3.BoolVal(False))
        claim = _anon_jwt_claim(node)
        if claim == "role":
            # The anon-key caller's role claim is the literal string 'anon'.
            return _Val(value=z3.StringVal("anon"), is_null=z3.BoolVal(False))
        if claim == "jwt":
            return _Val(
                value=ctx.opaque(_canon(node), z3.StringSort()),
                is_null=z3.BoolVal(False),
            )
    if (
        not ctx.session_mode
        and ctx.set_gucs
        and isinstance(node, FuncCall)
        and _is_builtin_current_setting_call(node)
        and is_maybe_set(ctx.set_gucs.get((_first_string_arg(node) or "").lower()))
    ):
        # Readable by the introspecting session, but not attributable to the
        # SERVER — it may be that connection's own option (`PGOPTIONS`), which
        # an anonymous caller would not have. Keep BOTH the value and the
        # null-flag free: `col = current_setting('x')` stays a leak (safe),
        # while `current_setting('x', true) IS NULL` stays undecided instead
        # of being proven dead from evidence we do not have.
        return _Val(
            value=ctx.opaque(_canon(node), z3.StringSort()),
            is_null=(
                z3.BoolVal(False)
                if is_never_null_current_setting(node)
                else ctx.opaque_null_flag(_canon(node))
            ),
        )
    if (
        not ctx.session_mode
        and ctx.set_gucs
        and isinstance(node, FuncCall)
        and _is_builtin_current_setting_call(node)
        and (_first_string_arg(node) or "").lower() in ctx.set_gucs
    ):
        # A dotted GUC the anonymous session inherits already SET (database /
        # role / server level) is a real value in EVERY spelling — one-arg,
        # `(name, false)` AND the canonical `(name, true)` that `pgrls
        # generate` emits. Gating only the raising forms left the generated
        # policy PROVEN while a fresh anon session read the shared row.
        # The CONFIGURED value when it was captured, so `current_setting(
        # 'app.flag') = 'on'` at 'off' stays PROVEN (measured: 0 rows); an
        # uncaptured value (`None`) falls back to an opaque non-null one,
        # which can only decline to prove isolation, never claim it.
        configured = ctx.set_gucs[(_first_string_arg(node) or "").lower()]
        value = _z3_string(configured) if configured is not None else None
        return _Val(
            value=(
                value if value is not None
                else ctx.opaque(_canon(node), z3.StringSort())
            ),
            is_null=z3.BoolVal(False),
        )
    if (isinstance(node, FuncCall) and _computes_missing_ok(node)
            and func_name_parts(node)[0] in auth_funcs | {"pg_catalog.current_setting"}
            and "current_setting" in auth_funcs):
        # `current_setting('app.t', <computed>)`: the setting as an auth
        # leaf reads it, or NULL where missing_ok is (it is STRICT).
        name = (_first_string_arg(node) or "").lower()
        if ctx.session_mode:
            return _Val(value=ctx.session_var(_canon(node), z3.StringSort()),
                        is_null=ctx.opaque_null_flag(_canon(node)))
        if ctx.anon_jwt and name in ("request.jwt.claim.role", "request.jwt.claims"):
            # Set for the anon-key caller: its claim, or NULL where
            # missing_ok is.
            return _Val(value=(z3.StringVal("anon") if name == "request.jwt.claim.role"
                               else ctx.opaque(_canon(node), z3.StringSort())),
                        is_null=ctx.opaque_null_flag(_canon(node)))
        if (not ctx.any_session and _reads_unset_guc_under_anon(node)
                and name not in ctx.set_gucs):
            # Unset under anon: NULL, or it raises (no rows).
            return _Val(value=ctx.opaque(_canon(node), z3.StringSort()),
                        is_null=z3.BoolVal(True))
    if _is_anon_null_leaf(node, auth_funcs):
        if ctx.session_mode:
            # `session_var` never returns None for a fresh StringSort key.
            return _Val(
                value=ctx.session_var(_canon(node), z3.StringSort()),
                is_null=z3.BoolVal(False),
            )
        if isinstance(node, FuncCall) and _is_builtin_current_setting_call(node):
            if not _reads_unset_guc_under_anon(node):
                # A BUILT-IN (non-dotted) GUC — `role`, `search_path`,
                # `TimeZone`. Always set, so `current_setting(name, true)`
                # never returns NULL, and mostly USERSET, so the value is the
                # caller's to choose. Modelling it NULL proved away a disjunct
                # that is live: measured, `... OR current_setting('role', true)
                # <> 'anon'` let a real anon session read every row (the value
                # is 'none' in a fresh session) while this mode said PROVEN.
                # The same reasoning `_DEFAULT_AUTH_FUNCTIONS` gives for
                # excluding `current_user` — only genuinely-nullable functions
                # may be pinned NULL.
                return _Val(
                    value=ctx.opaque(_canon(node), z3.StringSort()),
                    is_null=(
                        z3.BoolVal(False)
                        if _first_string_arg(node) is not None
                        # a computed name could be either: stay undecided
                        else ctx.opaque_null_flag(_canon(node))
                    ),
                )
        return _Val(
            value=ctx.opaque(_canon(node), z3.StringSort()),
            is_null=z3.BoolVal(True),
        )

    # --- literals.
    if isinstance(node, A_Const):
        v = _const_to_z3(node, ctx)
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
        key = _column_key(node, ctx)
        if not key:
            return None
        value = ctx.column(key, z3.BoolSort())
        if value is None:
            return None
        return _Val(value=value, is_null=ctx.null_flag(key))

    # --- non-auth function call: opaque value + FREE null-flag (a
    # non-auth function is NOT known-NULL under anon). Sanity-translate
    # args so an unparseable signature aborts. A bare column argument is not
    # bound: it has no sort here, and as a Bool it clashed with the same
    # column compared elsewhere (`user_id = auth.uid() AND f(user_id)`).
    if isinstance(node, FuncCall):
        for arg in (node.args or ()):
            arg = _unwrap_scalar_sublink(arg)
            if isinstance(arg, ColumnRef):
                if not _column_key(arg, ctx):
                    return None
            elif _anon_3vl(arg, ctx, auth_funcs, assertions) is None:
                return None
        key = _canon(node)
        # A never-NULL builtin current_setting (the one-arg form, or two-arg
        # current_setting(name, false)) RAISES on an unset GUC and is otherwise
        # a non-NULL string — it is NEVER NULL. Pin is_null=False so the
        # *satisfiability* path can't pick a free null-flag and manufacture a
        # `current_setting('x') IS NULL OR …` anon "leak": the disjunct is
        # genuinely dead. This is the same guard `_is_anon_null_leaf` applies
        # (it returns False for these, routing them here) and that SEC004 /
        # SEC038 already use, so `verify --mode anon` and the linter agree.
        if is_never_null_current_setting(node):
            if ctx.session_mode:
                # Cross-tenant verifier: this IS the authenticated session's
                # own identity, exactly like the nullable `auth.uid()` /
                # `current_setting(name, true)` leaves handled above. Mint the
                # SAME session symbol so `<tenant col> = current_setting('app.t')`
                # records a tenant pair and can be PROVEN, instead of degrading
                # to "no provable tenant-scoping equality" purely because the
                # policy spelled its identity read without `missing_ok`.
                return _Val(
                    value=ctx.session_var(key, z3.StringSort()),
                    is_null=z3.BoolVal(False),
                )
            if not ctx.any_session and _reads_unset_guc_under_anon(node) and (
                (_first_string_arg(node) or "").lower() not in ctx.set_gucs
            ):
                # Anon: the GUC is unset, so this RAISES — the statement
                # errors and the caller gets NO rows. Keep `is_null` False
                # (it never *returns* NULL, so the `... IS NULL OR …` dead
                # disjunct R12/R13 pinned stays dead) and mark the value
                # `unset`, which makes a comparison against it Kleene U.
                # Without this the free opaque lets Z3 existentially pick a
                # GUC value equal to a free row and report a phantom LEAK on
                # the canonical `col = current_setting('app.tenant')` policy.
                return _Val(
                    value=ctx.opaque(key, z3.StringSort()),
                    is_null=z3.BoolVal(False),
                    unset=True,
                )
            return _Val(
                value=ctx.opaque(key, z3.StringSort()),
                is_null=z3.BoolVal(False),
            )
        return _Val(
            value=ctx.opaque(key, z3.StringSort()),
            is_null=ctx.opaque_null_flag(key),
        )

    # --- boolean connectives (Kleene tables).
    if isinstance(node, BoolExpr):
        return _anon_boolexpr(node, ctx, auth_funcs, assertions)

    # --- comparison / arithmetic.
    if isinstance(node, A_Expr):
        if node.kind == A_Expr_Kind.AEXPR_OP:
            return _anon_binop(node, ctx, auth_funcs, assertions)
        if node.kind in (A_Expr_Kind.AEXPR_OP_ANY, A_Expr_Kind.AEXPR_IN):
            # `col = ANY(ARRAY[lit, ...])` membership — every introspected
            # `IN (...)` normalizes to this form — plus the hand-written
            # `IN (...)` list itself. Gated to `=` + literal elements.
            return _anon_any_array(node, ctx, auth_funcs, assertions)
        if ctx.any_session and node.kind in (
            A_Expr_Kind.AEXPR_BETWEEN, A_Expr_Kind.AEXPR_NOT_BETWEEN,
        ):
            return _anon_between(node, ctx, auth_funcs, assertions)
        if ctx.any_session and node.kind in (
            A_Expr_Kind.AEXPR_DISTINCT, A_Expr_Kind.AEXPR_NOT_DISTINCT,
        ):
            return _anon_distinct(node, ctx, auth_funcs, assertions)
        # IN / BETWEEN / ALL / others: soundness abort (SEC004 still guards
        # the literal IS NULL shape syntactically).
        return None

    # --- NULL tests. The arg is resolved as a SCALAR (_Val) so
    # `auth.uid() IS NULL`, `(... )::cast IS NULL`, etc. all work — this
    # is the point (amendment #2: route through the scalar resolver, not
    # the bool-_TV path). The result is a definite
    # truth (never U): IS NULL is exactly the null-flag.
    if isinstance(node, NullTest):
        if ctx.any_session and isinstance(node.arg, ColumnRef):
            # Only the column's null-flag is tested: binding its value would
            # give it a sort (Bool) that clashes with its comparisons.
            key = _column_key(node.arg, ctx)
            if not key:
                return None
            ctx.null_tested.add(key)
            inner = _Val(value=z3.BoolVal(False), is_null=ctx.null_flag(key))
        else:
            inner = _as_val(_anon_3vl(node.arg, ctx, auth_funcs, assertions))
        if inner is None:
            return None
        if ctx.session_mode:
            # Record every session identity the TESTED SUBTREE reads, not just
            # a bare minted symbol: a cast to a sort we do not model, or a
            # COALESCE, keeps `is_null` while replacing the value, so testing
            # `<wrapper>(auth.role()) IS NULL` would otherwise record nothing
            # and prove away. The caller decides, once the tenant axis is
            # known, whether each identity is the axis (its non-nullness is
            # the mode's premise) or a different one (unconstrained).
            ctx.session_null_tests |= _session_terms_under(node.arg, ctx)
        if node.nulltesttype == NullTestType.IS_NULL:
            return _TV(is_true=inner.is_null, is_null=z3.BoolVal(False))
        if node.nulltesttype == NullTestType.IS_NOT_NULL:
            return _TV(
                is_true=z3.Not(inner.is_null), is_null=z3.BoolVal(False)
            )
        return None

    # --- COALESCE: value is the first non-null arg; null iff all null.
    if isinstance(node, CoalesceExpr):
        args = list(node.args or ())
        # A bare column argument (`(SELECT x)` too) has no sort of its own:
        # `_anon_coalesce` gives it its siblings'. With every argument a
        # bare column there is none to give — modelled as Bools, three text
        # columns could hold only two values — so such a COALESCE is an
        # opaque value on every path, like CASE below, without binding those
        # columns; the diff path also makes one it cannot model exactly for
        # another reason opaque, shared by base and head.
        all_bare = all(isinstance(_unwrap_scalar_sublink(a), ColumnRef) for a in args)
        exact = None if all_bare else _anon_coalesce(node, ctx, auth_funcs, assertions)
        if exact is None and (ctx.any_session or all_bare):
            if any(not isinstance(_unwrap_scalar_sublink(a), ColumnRef)
                   and _anon_3vl(a, ctx, auth_funcs, assertions) is None
                   for a in args):
                return None
            key = _canon(node)
            return _Val(value=ctx.opaque(key, z3.StringSort()), is_null=ctx.opaque_null_flag(key))
        return exact

    # --- CASE: v1 soundness abort (no CASE corpus negative; Oracle §3.5).
    # The diff path keeps it as an opaque value — one free value and
    # null-flag per distinct CASE, shared by base and head, which can only
    # leave an implication unproven.
    if isinstance(node, CaseExpr):
        if not ctx.any_session:
            return None
        for part in _case_parts(node):
            if _anon_3vl(part, ctx, auth_funcs, assertions) is None:
                return None
        key = _canon(node)
        return _Val(value=ctx.opaque(key, z3.StringSort()), is_null=ctx.opaque_null_flag(key))

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
        if len(tvs) < 2:  # pragma: no cover - pglast flattens AND to >=2 args
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
        if len(tvs) < 2:  # pragma: no cover - pglast flattens OR to >=2 args
            return tvs[0]
        acc = tvs[0]
        for y in tvs[1:]:
            acc = _kleene_or(acc, y)
        return acc

    return None


def _anon_coalesce(
    node: CoalesceExpr, ctx: _Context, auth_funcs: set[str], assertions: list[Any]
) -> Any:
    """COALESCE: value is the first non-null arg; null iff all null.

    A bare column argument takes the sort its siblings share (Postgres
    gives every argument one type), rather than the Bool a bare column
    defaults to; with no sibling to give one, the caller keeps the COALESCE
    opaque."""
    args = list(node.args or ())
    if sum(_floatish(a) or _casts_a_value(a) or any(isinstance(n, ColumnRef) for n in _ast_nodes(a))
           for a in args) > 1:
        # Two columns (or a column and a float): Postgres gives the
        # COALESCE the type of either (a float column's), rounding the
        # other, which the text does not show.
        return None
    if any(_rounds_its_kin(a, ctx) for a in args) or _blanks_its_kin(args, ctx):
        # Postgres gives every argument the float type a cast gives one,
        # rounding a column's value too (`COALESCE(id, 0::real)`).
        return None
    # Its arguments take one type, a column's beside a literal.
    with ctx.unifying(not all(_is_constant(a) for a in args)):
        others = [_as_val(_anon_3vl(a, ctx, auth_funcs, assertions)) for a in args
                  if not isinstance(_unwrap_scalar_sublink(a), ColumnRef)]
    if not others or any(v is None for v in others):
        return None
    sorts = {v.value.sort() for v in others}
    if len(sorts) != 1:
        return None
    sort = sorts.pop()
    vals: list[Any] = []
    rest = iter(others)
    for arg in args:
        column = _unwrap_scalar_sublink(arg)
        if isinstance(column, ColumnRef):
            key = _column_key(column, ctx)
            var = ctx.column(key, sort) if key else None
            if var is None:
                return None
            vals.append(_Val(value=var, is_null=ctx.null_flag(key)))
        else:
            vals.append(next(rest))
    # Every COALESCE branch shares a common type in Postgres, so the
    # translated branch values must share a Z3 sort. A mismatch here
    # is an ENCODING ARTIFACT, not real SQL: a bare column argument
    # reaches the COALESCE with no comparison-sort context, so it
    # defaults to BoolSort (see the ColumnRef branch above), while a
    # sibling numeric/text literal is Int/Real/String. The `z3.If`
    # fold below SILENTLY COERCES such a Bool into {0,1} rather than
    # raising, so the `except z3.Z3Exception` never catches it — and a
    # numeric gate like `COALESCE(level, 0) < 3` would be mis-encoded
    # as unconditionally TRUE, fabricating a catastrophic SEC038
    # anonymous-read-leak verdict on a safe, auth-free predicate.
    # Abstain on any cross-branch sort mismatch: soundness (no false
    # positive) over coverage. (R18 #1)
    if len({v.value.sort() for v in vals}) > 1:
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


def _case_parts(node: CaseExpr) -> list[Any]:
    """The sub-expressions of a CASE: its operand, each WHEN / THEN, ELSE."""
    parts = [node.arg] if node.arg is not None else []
    for when in node.args or ():
        parts.extend((when.expr, when.result))
    if node.defresult is not None:
        parts.append(node.defresult)
    return parts


def _anon_between(
    node: A_Expr, ctx: _Context, auth_funcs: set[str], assertions: list[Any]
) -> Any:
    """``x [NOT] BETWEEN lo AND hi`` as ``[NOT] (lo <= x AND x <= hi)`` —
    the SQL definition, so its Kleene value is exactly that AND's.
    ``BETWEEN SYMMETRIC`` is another kind and abstains."""
    bounds = node.rexpr
    if not isinstance(bounds, (list, tuple)) or len(bounds) != 2:
        return None
    lo, hi = bounds
    body = BoolExpr(boolop=BoolExprType.AND_EXPR, args=(
        A_Expr(kind=A_Expr_Kind.AEXPR_OP, name=(String(sval="<="),),
               lexpr=lo, rexpr=node.lexpr),
        A_Expr(kind=A_Expr_Kind.AEXPR_OP, name=(String(sval="<="),),
               lexpr=node.lexpr, rexpr=hi),
    ))
    if node.kind == A_Expr_Kind.AEXPR_NOT_BETWEEN:
        body = BoolExpr(boolop=BoolExprType.NOT_EXPR, args=(body,))
    return _anon_3vl(body, ctx, auth_funcs, assertions)


def _anon_distinct(
    node: A_Expr, ctx: _Context, auth_funcs: set[str], assertions: list[Any]
) -> Any:
    """``a IS [NOT] DISTINCT FROM b``: never NULL — two NULLs are not
    distinct, a NULL and a value are, two values compare with ``<>``."""
    left, right = _resolve_3vl_operands(
        node.lexpr, node.rexpr, ctx, auth_funcs, assertions
    )
    if left is None or right is None or left.unset or right.unset:
        return None
    _note_string_read(ctx, node.lexpr, [node.rexpr])
    if _unlike_sql("=", left.value, right.value, any_session=ctx.any_session) or _floats_meet(
            node.lexpr, node.rexpr):
        return None
    if ctx.any_session and _cast_value_meets_column(node.lexpr, node.rexpr):
        # As in `_anon_binop`: the values' order is one of its own.
        values_differ = _ordered_truth("<>", node.lexpr, node.rexpr, ctx, assertions)
        differ = z3.If(z3.Or(left.is_null, right.is_null),
                       left.is_null != right.is_null, values_differ)
        if node.kind == A_Expr_Kind.AEXPR_NOT_DISTINCT:
            differ = z3.Not(differ)
        return _TV(is_true=differ, is_null=z3.BoolVal(False))
    try:
        differ = z3.Or(
            left.is_null != right.is_null,
            z3.And(z3.Not(left.is_null), z3.Not(right.is_null), left.value != right.value),
        )
    except (z3.Z3Exception, TypeError):
        return None
    if node.kind == A_Expr_Kind.AEXPR_NOT_DISTINCT:
        differ = z3.Not(differ)
    return _TV(is_true=differ, is_null=z3.BoolVal(False))


def _kleene_or(acc: _TV, y: _TV) -> _TV:
    """Pairwise Kleene (SQL three-valued) OR of two truths.

    `is_true = aᵀ ∨ yᵀ`; `is_null = (aᴺ ∨ yᴺ) ∧ ¬aᵀ ∧ ¬yᵀ` — i.e.
    `NULL OR TRUE = TRUE`, `NULL OR NULL = NULL`, `NULL OR FALSE = NULL`.
    Single source of truth for the OR table, shared by the `OR_EXPR` fold
    above and `= ANY(ARRAY[...])` membership below, so the two can never
    drift.
    """
    return _TV(
        is_true=z3.Or(acc.is_true, y.is_true),
        is_null=z3.And(
            z3.Or(acc.is_null, y.is_null),
            z3.Not(acc.is_true),
            z3.Not(y.is_true),
        ),
    )


def _anon_any_array(
    node: A_Expr, ctx: _Context, auth_funcs: set[str], assertions: list[Any]
) -> Any:
    """Kleene `lexpr = ANY(ARRAY[lit, ...])` membership.

    Modeled as the *exact* desugaring `lexpr = lit₁ OR lexpr = lit₂ OR …`,
    which is what SQL `= ANY(array)` means and what every `IN (...)` list
    normalizes to on introspection (`pg_get_expr` rewrites `IN` →
    `= ANY (ARRAY[...])`). Each element comparison is built as a synthetic
    `lexpr = elemᵢ` and routed through the existing `_anon_binop`, so column
    binding, null-flags, element casts, and the Kleene comparison rule are
    byte-for-byte identical to a hand-written `=`; the results are combined
    with `_kleene_or`. This is an exact desugaring onto trusted machinery,
    not a new approximation.

    Abstains (`None`) on anything else, because a wrong guess could flip the
    predicate and risk a false PROVEN:
    * operator other than `=` — notably `<> ALL`, the `NOT IN` normalization,
      which is the *complement* of membership;
    * RHS that is not an `A_ArrayExpr` literal (a column / function /
      subquery array needs array-containment reasoning we don't model);
    * an empty array, or any element `_anon_binop` itself can't translate.
    """
    op_names = list(node.name or ())
    if len(op_names) != 1 or not isinstance(op_names[0], String):
        return None
    if op_names[0].sval != "=":
        return None
    arr = node.rexpr
    if isinstance(arr, A_ArrayExpr):
        elements = list(arr.elements or ())
    elif node.kind == A_Expr_Kind.AEXPR_IN and isinstance(arr, (list, tuple)):
        # The hand-written `x IN (a, b)` spelling (offline `--sql-file`
        # input); the catalog never emits it — `pg_get_expr` rewrites IN to
        # `= ANY (ARRAY[...])` — but it is the same membership test.
        elements = list(arr)
    else:
        return None
    if not elements:
        return None
    if ctx.any_session and node.kind != A_Expr_Kind.AEXPR_IN and (
            _has_lossy_cast(node.lexpr) or any(
                isinstance(e, A_Const) and isinstance(getattr(e, "val", None), String)
                for e in elements)):
        # In a diff, `x = ANY(ARRAY['US '])` is no `x = 'US '`: the bare
        # literals make a `text[]`, so a `char(n)` or `citext` `x` (which the
        # text may not show) compares as text there, and as itself here.
        return None
    rounded = any(_rounds_its_kin(e, ctx) for e in elements) or (
            node.kind == A_Expr_Kind.AEXPR_IN and _rounds_its_kin(node.lexpr, ctx)) or (
            _blanks_its_kin([node.lexpr, *elements], ctx))
    if (rounded and ctx.any_session) or (
            # An array takes one type from its elements, a column's too
            # (`ARRAY[a + 0, 1]` is a float8[] for a float `a`), rounding
            # the left side; an `IN` list compares one with each.
            isinstance(arr, A_ArrayExpr)
            and any(isinstance(n, ColumnRef) for e in elements for n in _ast_nodes(e))):
        # The list takes the float type a cast gives one element (or, for
        # `IN`, its left side), rounding the others: `IN (16777217, 1::real)`
        # is a `real[]`. Off the diff path each comparison is then a truth
        # of its own (`_anon_binop`), as a float meeting a column is.
        return None
    # The list is read as a whole: a typed member types the bare ones too.
    _note_string_read(ctx, node.lexpr, elements)
    acc: _TV | None = None
    for elem in elements:
        cmp_node = A_Expr(
            kind=A_Expr_Kind.AEXPR_OP,
            name=(String(sval="="),),
            lexpr=node.lexpr,
            rexpr=elem,
        )
        # An `IN` list takes one type with its left side, and an array
        # one with a non-constant element.
        with ctx.unifying(node.kind == A_Expr_Kind.AEXPR_IN or not all(
                _is_constant(e) for e in elements)):
            ctx.kin_rounded += rounded
            ctx.string_scope += 1
            try:
                tv = _anon_binop(cmp_node, ctx, auth_funcs, assertions)
            finally:
                ctx.kin_rounded -= rounded
                ctx.string_scope -= 1
        # `=` yields a _TV; anything else (None, or a _Val) → abstain whole.
        if not isinstance(tv, _TV):
            return None
        acc = tv if acc is None else _kleene_or(acc, tv)
    return acc


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
        _note_string_read(ctx, node.lexpr, [node.rexpr])

    # Cross-tenant verifier: capture a `<column> = <session symbol>`
    # scoping equality (the tenant predicate `pgrls generate` emits) so the
    # prover can assert column != the session's own tenant. No-op on the
    # anon/diff path (session_mode False).
    if ctx.session_mode and op == "=":
        _record_tenant_pair(ctx, left, right)

    cast_meets = ctx.any_session and _cast_value_meets_column(node.lexpr, node.rexpr)
    unlike = _unlike_sql(op, left.value, right.value, any_session=ctx.any_session)
    if comparison_fn is None and not ctx.any_session and not unlike and _floats_meet(
            node.lexpr, node.rexpr):
        # Off the diff path, float arithmetic (`score * (2)::double precision`)
        # is a fresh value of its own, as other real arithmetic is below.
        floats_meet = False
    else:
        floats_meet = _floats_meet(node.lexpr, node.rexpr) or (
            comparison_fn is not None and ctx.kin_rounded > 0)
    if unlike or floats_meet or cast_meets:
        if comparison_fn is None or (ctx.any_session and (not cast_meets or ctx.unified)):
            # In an `IN` list or array the value takes the list's type, not
            # the column's: `x IN (v::int, 1)` rounds `v` to a `real` `x`'s
            # float4, while `x = v::int` compares in float8.
            return None
        if left.unset or right.unset:
            return _TV(is_true=z3.BoolVal(False), is_null=z3.BoolVal(True))
        # Off the diff path, a fresh truth of its own: free where both
        # operands are non-NULL, so a proof holds only if it holds for either
        # outcome, and a leak resting on it has no witness row.
        null = z3.Or(left.is_null, right.is_null)
        if cast_meets:
            truth = _ordered_truth(op, node.lexpr, node.rexpr, ctx, assertions)
        else:
            truth = ctx.opaque(f"comparison#{len(ctx._opaque_vars)}", z3.BoolSort())
        return _TV(is_true=z3.And(z3.Not(null), truth), is_null=null)

    if comparison_fn is not None:
        if left.unset or right.unset:
            # One side reads a GUC that is unset for an anonymous session,
            # so evaluating this comparison RAISES: the statement errors and
            # no row comes back. Kleene U models that exactly — "not TRUE",
            # and `NOT U` is still U, so an enclosing NOT cannot flip the
            # erroring branch back into a visible row. A short-circuiting
            # sibling is unaffected: `true OR U` is still TRUE, so a genuine
            # `USING (true OR …)` leak keeps reporting. Anon path only
            # (`unset` is never set under `session_mode`).
            return _TV(is_true=z3.BoolVal(False), is_null=z3.BoolVal(True))
        try:
            cmp_z3 = comparison_fn(left.value, right.value)
        except (z3.Z3Exception, TypeError):
            # TypeError: `<`/`>`/`<=`/`>=` on two Bool-sorted operands
            # (e.g. `(a IS NULL) > (b IS NULL)`) — Z3 raises a plain
            # TypeError, not Z3Exception. Untranslatable -> NO-OP.
            return None
        return _TV(
            is_true=z3.And(
                z3.Not(left.is_null), z3.Not(right.is_null), cmp_z3
            ),
            is_null=z3.Or(left.is_null, right.is_null),
        )

    if arithmetic_fn is not None and (left.unset or right.unset):
        # An unset GUC raises before its NULL could reach an `IS NULL` or a
        # COALESCE, which read only the null-flag: no reading of the result
        # (a value, or one marked unset) is right for both, so abstain.
        return None
    sorts = {left.value.sort(), right.value.sort()}
    if arithmetic_fn is not None and (sorts != {z3.IntSort()} or op in ("/", "%") or _floats_meet(
            node.lexpr, node.rexpr)):
        # Off the diff path too, a result Z3 does not compute as Postgres
        # does — on reals (no NaN / ±Infinity, no rounding), `/` and `%`
        # (Postgres truncates) — is a fresh value of its own each time (not
        # keyed by its rendering, which recursed a second time down a deep
        # chain; a fresh value only frees it further). Arithmetic on
        # anything else — text standing for a timestamp or an interval,
        # whose order is not text's — abstains, as the diff path did above.
        if not sorts <= {z3.IntSort(), z3.RealSort()}:
            return None
        floaty = z3.RealSort() in sorts or _floats_meet(node.lexpr, node.rexpr)
        sort = z3.RealSort() if floaty else z3.IntSort()
        return _Val(
            value=ctx.opaque(f"arithmetic#{len(ctx._opaque_vars)}", sort),
            is_null=z3.Or(left.is_null, right.is_null),
        )

    if arithmetic_fn is not None:
        try:
            value = arithmetic_fn(left.value, right.value)
        except (z3.Z3Exception, TypeError):
            # TypeError: String `-`/`*`/`/`/`%` (the common case is a
            # time window like `created_at > now() - interval '7 days'`,
            # where now()/interval resolve to opaque String operands).
            # Z3 raises a plain TypeError, not Z3Exception. NO-OP.
            return None
        return _Val(value=value, is_null=z3.Or(left.is_null, right.is_null))

    return None  # unreachable (guarded above) — satisfies the type checker


def _unlike_sql(op: str, left: Any, right: Any, *, any_session: bool) -> bool:
    """Whether Z3's reading of `left op right` would differ from Postgres's,
    so the comparison must not be translated (on the diff path it abstains;
    off it, it is a truth of its own, see `_anon_binop`).

    On every path:

    * a Bool against a non-Bool — an encoding artifact (a bare column
      defaults to Bool) that Z3 coerces to 0 / 1 rather than rejects — and
      text against a number (an opaque value against a literal), which Z3
      cannot compare at all;
    * ``<`` / ``>`` / ``<=`` / ``>=`` on text — Postgres orders it by
      collation, Z3 by code point (``'B' < 'b'`` is FALSE under en_US), and
      an equality elsewhere can pin either side to a literal.

    On the diff path (`any_session`), where both predicates' readings must be
    exact for an equivalence or an implication to hold, also (off it,
    arithmetic on numbers is a value of its own instead and on text still
    abstains, see `_anon_binop`):

    * arithmetic on anything but integers — Z3's ``+`` on two strings
      concatenates, and its reals have no NaN / ±Infinity and never round;
    * ``/`` and ``%`` — Postgres truncates an integer quotient toward zero
      (``-1 % 2`` is -1, Z3's is 1)."""
    sorts = (left.sort(), right.sort())
    if (sorts[0] == z3.BoolSort()) != (sorts[1] == z3.BoolSort()):
        return True
    if sorts[0] != sorts[1] and not set(sorts) <= {z3.IntSort(), z3.RealSort()}:
        return True
    if op in ("<", ">", "<=", ">=") and z3.StringSort() in sorts:
        return True
    if not any_session:
        return False
    if op in _ARITHMETIC_OPS:
        # Only integers: Z3's reals have no NaN or ±Infinity, which a
        # `numeric` / `float8` value can be (`n * 0.0 = 0.0` is not TRUE
        # for NaN), and they never round as `float8` does.
        if not all(s == z3.IntSort() for s in sorts):
            return True
        return op in ("/", "%")
    return False


def _resolve_3vl_operands(
    lexpr: Any,
    rexpr: Any,
    ctx: _Context,
    auth_funcs: set[str],
    assertions: list[Any],
) -> tuple[Any, Any]:
    """Translate both comparison operands to ``_Val`` pairs.

    When one side is a
    bare ColumnRef and the other resolves to a concrete-sorted ``_Val``,
    the column is bound to that sort (its null-flag is a free Kleene U
    candidate). ``col OP col`` binds both as String (no other side gives
    them a type). Any None → ``(None, None)``.
    """
    # A bare column is found through a sub-select; anything else is
    # translated as written, so `_anon_3vl` sees the sub-select.
    if isinstance(_unwrap_scalar_sublink(lexpr), ColumnRef):
        lexpr = _unwrap_scalar_sublink(lexpr)
    if isinstance(_unwrap_scalar_sublink(rexpr), ColumnRef):
        rexpr = _unwrap_scalar_sublink(rexpr)
    l_is_col = isinstance(lexpr, ColumnRef)
    r_is_col = isinstance(rexpr, ColumnRef)

    def col_val(col: ColumnRef, sort: Any) -> Any:
        key = _column_key(col, ctx)
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


_PG_TRUE = frozenset({"true", "t", "yes", "y", "on", "1"})
_PG_FALSE = frozenset({"false", "f", "no", "n", "off", "0"})


# The value range each integer type accepts, so a fold never invents a row
# Postgres could not hold. `'99999999999999999999'::int` RAISES — Python's
# unbounded `int()` happily produced it, and the witness named a row the
# INSERT in the emitted reproduction then rejected with "integer out of
# range": a leak the tool could not exhibit.
_INT_RANGES: dict[str, tuple[int, int]] = {
    "int2": (-(2**15), 2**15 - 1),
    "smallint": (-(2**15), 2**15 - 1),
    "int": (-(2**31), 2**31 - 1),
    "int4": (-(2**31), 2**31 - 1),
    "integer": (-(2**31), 2**31 - 1),
    "int8": (-(2**63), 2**63 - 1),
    "bigint": (-(2**63), 2**63 - 1),
    "oid": (0, 2**32 - 1),
}


def _fold_literal_cast(value: Any, target_sort: Any, type_name: str | None) -> Any:
    """`'<literal>'::<type>` as a Z3 constant of `target_sort`, else None.

    Only folds a String constant the encoder already knows exactly — a
    captured GUC value or a policy literal — and only when Postgres would
    accept it and read it alike whatever it is compared with: in range for
    the integer type, and for a real one that `_exact_real` reads (not
    `'NaN'` / `'Infinity'`, which Z3 reals do not have). The caller folds
    only for a cast that keeps the value (`_exact_cast`, and off the diff
    path an integer one). Anything else
    returns None and stays opaque: declining to decide is the
    safe direction, and modelling the raise as "isolated" is not this
    function's job.
    """
    if not z3.is_string_value(value):
        return None
    text = value.as_string()
    try:
        if target_sort == z3.IntSort():
            if not re.fullmatch(r"\s*[+-]?\d+\s*", text, re.ASCII):
                return None  # Postgres reads no other digits (`'١٢'`)
            number = int(text)
            low, high = _INT_RANGES.get(type_name or "", _INT_RANGES["int8"])
            return z3.IntVal(number) if low <= number <= high else None
        if target_sort == z3.RealSort():
            return _exact_real(text)
    except (ValueError, OverflowError, ZeroDivisionError, z3.Z3Exception):
        return None
    if target_sort == z3.BoolSort():
        low_text = text.strip().lower()
        if low_text in _PG_TRUE:
            return z3.BoolVal(True)
        if low_text in _PG_FALSE:
            return z3.BoolVal(False)
    return None


def _in_int_range(number: int, typename: Any) -> bool:
    low, high = _INT_RANGES.get(_typename_last_segment(typename) or "", _INT_RANGES["int8"])
    return low <= number <= high


def _anon_typecast(
    node: TypeCast, ctx: _Context, auth_funcs: set[str], assertions: list[Any]
) -> Any:
    """Translate ``<expr>::<type>`` under 3VL, preserving the null-flag.

    The inner is coerced to a ``_Val`` via ``_as_val``: a boolean ``_TV``
    inner (e.g. P4's ``(... IS NULL)::bool``, amendment #4) becomes a
    Bool-sorted scalar whose value carries its truth and whose null-flag
    carries through — there is no separate ``_TV`` branch here. A cast of
    NULL is NULL, so the inner ``is_null`` always propagates. When the
    target sort matches the inner value's sort the cast is a no-op only
    for a cast that keeps the value (`_exact_cast`; off the diff path also
    a `uuid` or non-`oid` integer cast) — and on the diff path only of a
    value that keeps its type (`_keeps_its_type`); otherwise the value is
    opaque under the target sort (an unknown target keeps a String opaque)
    but the null-flag is preserved.

    One exception under the cross-tenant verifier (``session_mode``): a
    sort-changing cast of the session identity stays a free, NON-NULL
    *session* symbol of the target sort rather than an opaque one — so
    ``<int column> = current_setting('app.tenant_id', true)::bigint`` (the
    integer/bigint tenant scoping ``pgrls generate`` emits — wrapped in
    ``(SELECT …)`` for index caching, which the encoder unwraps) still
    records a tenant pair and can be PROVEN isolated instead of degrading to
    UNVERIFIED. No effect on the anon/diff path (``session_mode`` False).
    """
    inner_raw = _anon_3vl(node.arg, ctx, auth_funcs, assertions)
    if inner_raw is None:
        return None
    inner = _as_val(inner_raw)
    if inner is None:
        return None
    target_sort = _typename_segments_to_sort(node.typeName)
    if (ctx.integers and target_sort == z3.RealSort() and _exact_cast(node.typeName)
            and z3.is_int_value(inner.value)):
        return inner  # the integer pass: `5::numeric` is 5
    if (target_sort == z3.IntSort() and not ctx.integers and _exact_cast(node.typeName)
            and z3.is_rational_value(inner.value) and inner.value.denominator_as_long() == 1
            and _in_int_range(inner.value.numerator_as_long(), node.typeName)):
        return inner  # `5::int` is 5 (not `(-256)::oid`, which wraps)
    if (target_sort == z3.IntSort() and not ctx.integers
            and _is_real_column_term(ctx, inner.value)):
        # Over the reals (see `_const_to_z3`) an integer cast of a column
        # that may be a `numeric` rounds it: an integer of its own.
        return _Val(
            value=ctx.opaque(_canon(node), target_sort),
            is_null=inner.is_null,
            unset=inner.unset,
        )
    lossy = target_sort is not None and not _exact_cast(node.typeName)
    if lossy and not ctx.any_session:
        # Off the diff path a `uuid` cast (the session identity's) and an
        # integer one (which raises rather than changes) keep the value as
        # before; `oid` wraps a negative integer. (A `uuid` cast does fold
        # case and braces, which the text model does not — the documented
        # uuid limit.)
        lossy = not (
            _bare_type(node.typeName, "uuid")
            or (target_sort == z3.IntSort()
                and _typename_last_segment(node.typeName) != "oid")
            # `'demo'::bpchar`, as `pg_get_expr` writes a `char(n)` literal,
            # is 'demo' (a trailing space is the documented char(n) limit).
            or (_bare_type(node.typeName, "bpchar") and isinstance(node.arg, A_Const)
                and isinstance(getattr(node.arg, "val", None), String)
                and not node.arg.val.sval.endswith(" "))
        )
    if lossy:
        # A cast that may change the value (`varchar(3)`, `float4`, `oid`,
        # `numeric(3,1)`, `citext`) is a value of its own.
        return _Val(
            value=ctx.opaque(_canon(node), target_sort),
            is_null=inner.is_null,
            unset=inner.unset,
        )
    if target_sort is None:
        # Unknown target type — opaque value, keep the inner null-flag.
        return _Val(
            value=ctx.opaque(_canon(node), z3.StringSort()),
            is_null=inner.is_null,
            unset=inner.unset,
        )
    if ctx.any_session and not _keeps_its_type(node.arg):
        # A cast of a value whose Postgres type pgrls does not know — a
        # function's result, a lossy or unknown cast — may change it even to
        # a type of the same sort (`s::float8::numeric`, `abs(n)::text`).
        return _Val(
            value=ctx.opaque(_canon(node), target_sort),
            is_null=inner.is_null,
            unset=inner.unset,
        )
    if inner.value.sort() == target_sort:
        return _Val(
            value=inner.value, is_null=inner.is_null, unset=inner.unset
        )
    if ctx.session_mode and _is_session_term(ctx, inner.value):
        # Cross-tenant recall: keep a sort-changing cast of the session
        # identity (`current_setting(...)::bigint`/`::int`) a free, non-null
        # session symbol of the target sort, keyed by the cast's canonical
        # rendering so `::bigint`/`::int`/the uncast String identity stay
        # distinct. Sound: the cast of an arbitrary OTHER tenant's identity
        # is itself an arbitrary value of the target sort, so a fresh free
        # symbol over-approximates — it can only leave the leak check SAT
        # (decline), never manufacture a false PROVEN.
        return _Val(
            value=ctx.session_var(_canon(node), target_sort),
            is_null=inner.is_null,
        )
    # On the diff path only to an integer or a boolean: a real fold is
    # what a captured GUC value needs, and only the provers capture one.
    folded = None if ctx.any_session and target_sort == z3.RealSort() else _fold_literal_cast(
        inner.value, target_sort, _typename_last_segment(node.typeName)
    )
    if folded is not None and z3.is_int_value(folded):
        # `'…'::int8` is an integer literal too (see `_integer`).
        folded = _integer(folded.as_long(), ctx)
    if folded is not None:
        # A captured GUC value cast to the column's type is exactly that
        # constant — `col = current_setting('app.n')::int` with `app.n` set to
        # '1' admits the row with id 1. Leaving it opaque cost the witness, so
        # `--emit-repro` seeded a placeholder row the policy does not admit
        # and the generated pytest failed against a real leak.
        return _Val(value=folded, is_null=inner.is_null, unset=inner.unset)
    return _Val(
        value=ctx.opaque(_canon(node), target_sort),
        is_null=inner.is_null,
        unset=inner.unset,
    )


@_abstains_when_too_deep(None)
@_bare_columns("using_node")
def anon_read_counterexample(
    using_node: Any, auth_functions: set[str] | None = None
) -> dict[str, object] | None:
    """Prove (or refute) that ``using_node`` is anon-VALID under Kleene 3VL.

    Returns a dict when the USING predicate is provably TRUE for EVERY row
    under an anonymous session (every auth function NULL) — meaning the
    policy unconditionally leaks all rows to an unauthenticated client.
    Returns ``None`` otherwise.

    Under the validity criterion the predicate is TRUE for every row, so
    the proof artifact is "all rows": the returned dict is ALWAYS empty
    ``{}``. Validity means ``is_true`` holds for every assignment of the
    real columns, so no column value characterizes the leak — a genuine
    empty model is the honest witness (§ amendment #6), and decoding an
    arbitrary satisfying model instead would yield a misleading non-empty
    dict (e.g. ``{flag: False}`` for ``flag OR NOT flag``) implying those
    columns matter when they do not. The non-empty shape is reserved for a
    future "satisfiable read" criterion. SEC038 treats any non-None return
    as "fire".

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

    # Valid ⇒ NOT(is_true) is UNSAT ⇒ is_true holds for EVERY assignment of
    # the real columns: no column value characterizes the leak — every row
    # leaks unconditionally. So the honest proof artifact is the empty
    # model ``{}`` ("all rows", § amendment #6), NOT an arbitrary
    # satisfying assignment of is_true: decoding such a model would yield a
    # non-empty dict (e.g. ``{flag: False}`` for ``flag OR NOT flag``) that
    # misleadingly implies those columns matter when they do not. SEC038
    # treats any non-None return as "fire"; the empty dict drives its
    # "every row is visible unconditionally" message.
    return {}


def _anon_witness_is_sufficient(
    row: dict[str, object], is_true: Any, ctx: _Context, assertions: list[Any]
) -> bool:
    """True iff pinning ``row``'s real columns forces ``is_true`` for ALL
    completions of the free (synthetic / unpinned) variables.

    The Kleene model of ``is_true`` (an anonymous-read witness) is a *full*
    assignment; the real-column projection ``row`` drops every synthetic
    null-flag / opaque marker. A projection is not in general self-sufficient
    — e.g. ``is_public OR tenant_id = auth.uid()`` admits a row only because
    ``is_public`` is True, whereas an unconditional ``USING (true)`` admits
    every row and no column characterizes it. Pin the row and check
    ``(assertions) ∧ (pins) ∧ ¬is_true`` UNSAT: only then does every row
    matching ``row`` lie inside the anon-visible set, so it is an honest,
    self-sufficient counterexample. Mirrors ``_diff_witness_is_sufficient``.

    Each pin fixes the column's VALUE **and** its 3VL null-flag: a real row
    holding ``tenant = 'shared'`` has a non-null ``tenant``, by construction.
    Pinning only the value left the flag free, so ``¬is_true`` stayed
    satisfiable via "the column is NULL" and the single most common policy
    shape of all — ``<column> = <constant>``, the shape an inherited
    ``current_setting`` reduces to — was downgraded to "a conditional leak,
    no single row characterizes it". That cost the honest witness twice
    over: ``--emit-repro`` seeded a placeholder row the policy does not
    admit (the generated pytest then failed against a leak that is real),
    and ``--probe`` abstained instead of confirming it. Unpinned columns
    keep BOTH their value and their flag free, so the check still demands
    the leak for every completion — the ``is_public OR deleted_at IS NULL``
    projection is rejected exactly as before.
    """
    pins = []
    for key, val in row.items():
        var = ctx.column(key, _py_value_sort(val))
        if var is None:  # pragma: no cover - _py_value_sort inverts the bound sort
            return False
        pins.append(var == _z3_value(val))
        pins.append(z3.Not(ctx.null_flag(key)))
    solver = z3.Solver()
    solver.set("timeout", 1000)
    for a in assertions:
        solver.add(a)
    pinned = z3.And(*pins) if len(pins) >= 2 else (pins[0] if pins else z3.BoolVal(True))
    solver.add(z3.And(pinned, z3.Not(is_true)))
    return bool(solver.check() == z3.unsat)


@_abstains_when_too_deep(("unverified", None))
def prove_anon_isolation(
    using_node: Any,
    auth_functions: set[str] | None = None,
    *,
    set_gucs: Mapping[str, str | None] | Sequence[Mapping[str, str | None]] = (),
) -> tuple[str, dict[str, object] | None]:
    """Prove whether an anonymous session can read any row under ``using_node``.

    Encodes the USING predicate under TWO anonymous sessions — JWT-less
    (every auth function NULL) and Supabase anon-key (`auth.role()` = 'anon',
    `auth.jwt()` non-null; see `_Context.anon_jwt`) — with the same
    Kleene-3VL translator SEC038 uses, a leak under either being a leak, and asks
    the *satisfiability* question — can ``is_true`` hold for some row? —
    rather than SEC038's validity question (does it hold for EVERY row). The
    satisfiability criterion is what tenant isolation needs: a row is exposed
    to an unauthenticated client iff the policy's USING is TRUE for it under
    anon.

    ``set_gucs`` maps the dotted GUCs the anonymous session inherits already
    set (database / server level, or role level for its login role) to their
    configured values; a read of one is that value rather than the unset-GUC
    raise — in every spelling, including the ``(name, true)`` form. Pass a
    SEQUENCE of such mappings to check one state per login path (a direct
    ``anon`` login and ``authenticator`` then ``SET ROLE anon`` inherit
    different role-level settings): every state is proven and a leak in any
    is the verdict, since every path is a session a real caller can arrive
    in.

    Returns ``(verdict, witness)``:

    - ``("isolated", None)`` — ``is_true`` is UNSAT under anon: **proven** that
      no row is visible to an anonymous session.
    - ``("leak", row)`` — ``is_true`` is SAT: an anonymous session can read a
      row. ``row`` is a self-sufficient characterizing assignment of the real
      columns (e.g. ``{"is_public": True}``); ``{}`` when the leak is
      unconditional — every row, ``USING (true)`` — (``NOT(is_true)`` is also
      UNSAT); or ``None`` when the leak is *conditional* but no real-column
      assignment characterizes it (some row escapes, yet the discriminating
      value is a synthetic null-flag), so callers must not claim "every row".
    - ``("unverified", None)`` — Z3 unavailable, the predicate (or a
      sub-expression) is untranslatable, or the solver timed out. No claim is
      made (the "verifier degrades to a linter" boundary).

    Soundness over recall: never returns ``isolated`` unless ``is_true`` is
    provably UNSAT, and never returns ``leak`` unless a model exists.
    """
    if not Z3_AVAILABLE:
        return ("unverified", None)
    auth = (
        auth_functions
        if auth_functions is not None
        else set(_DEFAULT_AUTH_FUNCTIONS)
    )
    # Two anonymous sessions, and a leak under EITHER is a leak: the no-JWT
    # session (every auth function NULL) and the Supabase anon-key session
    # (`auth.role()` = 'anon', `auth.jwt()` non-null, `auth.uid()` NULL). The
    # verdict is `isolated` only when both are UNSAT, `unverified` when either
    # cannot be decided, and the witness comes from whichever session leaked
    # (the no-JWT one first, so existing witnesses are unchanged).
    states: tuple[Mapping[str, str | None], ...] = (
        (set_gucs,) if isinstance(set_gucs, Mapping) else tuple(set_gucs) or ({},)
    )
    verdicts = [
        _prove_anon_session(using_node, auth, anon_jwt=anon_jwt, set_gucs=state)
        for state in states
        for anon_jwt in (False, True)
    ]
    for verdict, witness in verdicts:
        if verdict == "leak":
            return (verdict, witness)
    if any(v == "unverified" for v, _ in verdicts):
        return ("unverified", None)
    return ("isolated", None)


@_abstains_when_too_deep(False)
def anon_leak_is_total(
    using_node: Any,
    auth_functions: set[str] | None = None,
    *,
    set_gucs: Mapping[str, str | None] | Sequence[Mapping[str, str | None]] = (),
) -> bool:
    """Does EVERY modelled anonymous session read EVERY row?

    `prove_anon_isolation` answers the ∃ question — a leak in any session is a
    leak — and returns the FIRST leaking session's witness. That makes a `{}`
    witness mean "some session reads everything", which is not what a caller
    asking "does the direct read already expose everything a second door
    would" needs. Measured: `USING (auth.role() = 'anon')` is total for the
    Supabase anon-key caller and admits NOTHING to a JWT-less one, so a
    definer view over it handed a JWT-less anon every row while the direct
    read gave none — and the ∃ reading cleared it.
    """
    if not Z3_AVAILABLE:
        return False
    auth = (
        auth_functions
        if auth_functions is not None
        else set(_DEFAULT_AUTH_FUNCTIONS)
    )
    states: tuple[Mapping[str, str | None], ...] = (
        (set_gucs,) if isinstance(set_gucs, Mapping) else tuple(set_gucs) or ({},)
    )
    for state in states:
        for anon_jwt in (False, True):
            verdict, witness = _prove_anon_session(
                using_node, auth, anon_jwt=anon_jwt, set_gucs=state
            )
            if verdict != "leak" or witness != {}:
                return False
    return True


def _prove_anon_session(
    using_node: Any,
    auth: set[str],
    *,
    anon_jwt: bool,
    set_gucs: Mapping[str, str | None] | None = None,
) -> tuple[str, dict[str, object] | None]:
    """`prove_anon_isolation` for ONE session model (see `_Context.anon_jwt`)
    in ONE inherited-GUC state (see `_Context.set_gucs`)."""
    return _integers_agree(lambda integers: _prove_anon_session_once(
        using_node, auth, anon_jwt=anon_jwt, set_gucs=set_gucs, integers=integers))


def _integers_agree(prove: Callable[[bool], tuple[str, Any]]) -> tuple[str, Any]:
    """`prove` over the reals (see `_const_to_z3`), whose `isolated` holds
    for an integer column too; a leak stands only if an integer row leaks
    as well (else it may hold only where a column is not an integer one),
    and its witness is that row (also where the reals decide nothing)."""
    verdict = prove(False)
    if verdict[0] not in ("leak", "unverified"):
        return verdict
    # A leak the reals cannot decide (an integer a float4 rounds) is one if
    # an integer row leaks.
    again = prove(True)
    return again if again[0] == "leak" else ("unverified", None)


@_bare_columns("using_node")
def _prove_anon_session_once(
    using_node: Any,
    auth: set[str],
    *,
    anon_jwt: bool,
    set_gucs: Mapping[str, str | None] | None,
    integers: bool,
) -> tuple[str, dict[str, object] | None]:
    ctx = _Context()
    ctx.integers = integers
    ctx.anon_jwt = anon_jwt
    ctx.set_gucs = dict(set_gucs or {})
    assertions: list[Any] = []
    tv = _lift_to_tv(_anon_3vl(using_node, ctx, auth, assertions), assertions)
    if tv is None:
        return ("unverified", None)

    solver = z3.Solver()
    solver.set("timeout", 1000)
    for a in assertions:
        solver.add(a)
    solver.add(tv.is_true)
    result = solver.check()
    if result == z3.unsat:
        return ("isolated", None)
    if result != z3.sat:  # unknown / timeout — no claim
        return ("unverified", None)

    model = solver.model()
    row = _decode_model(model, ctx)
    if row and _anon_witness_is_sufficient(row, tv.is_true, ctx, assertions):
        return ("leak", row)
    # No real-column row characterizes the leak. Distinguish a genuine tautology
    # (every row leaks → the honest "all rows" artifact {}) from a conditional
    # leak we cannot pin to specific real columns (some row escapes → None), so
    # callers don't claim "every row" for a leak that only some rows exhibit.
    valid = z3.Solver()
    valid.set("timeout", 1000)
    for a in assertions:
        valid.add(a)
    valid.add(z3.Not(tv.is_true))
    return ("leak", {}) if valid.check() == z3.unsat else ("leak", None)


def _is_real_column_term(ctx: _Context, term: Any) -> bool:
    """True iff ``term`` is exactly a bound real-column Z3 const."""
    return bool(z3.is_const(term)) and term.decl().name() in ctx._vars


def _session_terms_under(node: Any, ctx: _Context) -> set[str]:
    """Decl names of every session identity the subtree `node` reads.

    Taken at the OUTERMOST node that minted one, which is what preserves the
    on-axis premise: `current_setting('app.tenant_id', true)::bigint IS NULL`
    records the symbol the sort-changing cast minted — the same one
    `_record_tenant_pair` recorded as the axis — rather than the inner String
    leaf, so a policy that NULL-tests its own axis still proves.

    Called only after `_anon_3vl` has walked the same subtree, so every session
    var it can mint already exists in `ctx`.
    """
    found: set[str] = set()

    def walk(n: Any) -> None:
        if n is None:
            return
        if isinstance(n, (list, tuple)):
            for item in n:
                walk(item)
            return
        if not isinstance(n, Node):
            return
        minted = ctx._session_vars.get(_canon(n))
        if minted is not None:
            found.add(minted.decl().name())
            return  # outermost wins: do not descend past it
        for field_name in n:
            walk(getattr(n, field_name, None))

    walk(node)
    return found


def _session_null_tests_offaxis(ctx: _Context, axis_session: Any) -> bool:
    """Did the predicate test a session identity OTHER than the tenant axis
    for NULL?

    Under ``session_mode`` every auth leaf is minted NON-NULL, so such a test
    encodes to a definite FALSE. For the AXIS identity that is the mode's own
    premise (a session authenticated as tenant A has an identity). For any
    OTHER auth call it is an unfounded assumption that a JWT is present:
    measured on PG16, with tenancy in `SET app.tenant` and no JWT, a tenant-b
    session read tenant a's row through `... OR auth.role() IS NULL` while
    both `--mode cross-tenant` and `--mode anon` reported PROVEN. Decline to
    prove instead.
    """
    axis_name = axis_session.decl().name() if z3.is_const(axis_session) else None
    return any(name != axis_name for name in ctx.session_null_tests)


def _is_session_term(ctx: _Context, term: Any) -> bool:
    """True iff ``term`` is exactly a minted session-tenant symbol.

    Identity by decl-name against the actual ``_session_vars`` the encoder
    minted — not a bare ``_session__`` prefix test — so nothing outside the
    context's own session namespace can be mistaken for the session symbol.
    """
    if not z3.is_const(term):
        return False
    name = term.decl().name()
    return name in {sv.decl().name() for sv in ctx._session_vars.values()}


def _record_tenant_pair(ctx: _Context, left: Any, right: Any) -> None:
    """Record a ``<real column> = <session tenant symbol>`` scoping equality.

    Order-insensitive; ignores every other operand shape (column = column,
    column = literal, opaque = session, …). The two terms are already
    sort-matched (``_resolve_3vl_operands`` bound the column to the session
    symbol's sort), but re-check defensively before storing ``(column,
    session)``.
    """
    for col, sess in ((left.value, right.value), (right.value, left.value)):
        if (
            _is_real_column_term(ctx, col)
            and _is_session_term(ctx, sess)
            and col.sort() == sess.sort()
        ):
            ctx.tenant_pairs.append((col, sess))
            return


def _distinct_tenant_pairs(
    pairs: list[tuple[Any, Any]],
) -> list[tuple[Any, Any]]:
    """De-duplicate recorded ``(column, session)`` pairs by decl-name.

    A policy may state the same scoping equality more than once (a repeated
    disjunct, or USING mirrored in WITH CHECK) — those collapse to one
    tenant axis. Two DIFFERENT columns, or one column vs two different
    session symbols, stay distinct; the prover declines (UNVERIFIED) on
    anything but a single axis.
    """
    seen: dict[tuple[str, str], tuple[Any, Any]] = {}
    for col, sess in pairs:
        key = (col.decl().name(), sess.decl().name())
        if key not in seen:
            seen[key] = (col, sess)
    return list(seen.values())


def _is_z3_str_placeholder(value: object) -> bool:
    """True for Z3's arbitrary string-model artifacts (``!0!``, ``!1!``, …).

    Z3 renders an unconstrained String const as a bang-delimited internal
    token. Such a value is a don't-care (any string satisfies), so it must
    never be presented as a meaningful witness literal.
    """
    return (
        isinstance(value, str)
        and len(value) >= 3
        and value[0] == "!"
        and value[-1] == "!"
        and value[1:-1].isdigit()
    )


def _cross_tenant_witness_sufficient(
    witness: dict[str, object],
    column: Any,
    session_tenant: Any,
    is_true: Any,
    ctx: _Context,
    assertions: list[Any],
) -> bool:
    """True iff pinning ``witness``'s columns forces the cross-tenant leak for
    ALL completions of the free (synthetic / unpinned) variables.

    The cross-tenant dual of ``_anon_witness_is_sufficient``: a leaking row's
    real-column projection is self-sufficient only when every other-tenant row
    matching it leaks regardless of the unmodeled opaque values — i.e.
    ``(assertions) ∧ (pins) ∧ (column != session) ∧ ¬is_true`` is UNSAT. A
    leak that additionally needs an unpinned opaque/session value (an
    ``OR (flag AND fn() = 'x')`` row condition, or an admin-role bypass that
    depends on the *session* not the row) is NOT self-sufficient → the caller
    reports a conditional leak (witness ``None``) rather than over-claim which
    rows leak.

    Each pinned column also pins its Kleene null-flag false: a witnessed
    concrete value implies the column is non-null, so the check must not
    consider the impossible ``value = 'x' ∧ x IS NULL`` state (which would
    spuriously deem a value-scoped leak, e.g. a hardcoded ``tenant = 'X'``,
    insufficient because a NULL ``tenant`` would not match).
    """
    pins = []
    for key, val in witness.items():
        var = ctx.column(key, _py_value_sort(val))
        if var is None:  # pragma: no cover - _py_value_sort inverts the bound sort
            return False
        pins.append(var == _z3_value(val))
        pins.append(z3.Not(ctx.null_flag(key)))
    solver = z3.Solver()
    solver.set("timeout", 1000)
    for a in assertions:
        solver.add(a)
    solver.add(column != session_tenant)
    if pins:
        solver.add(z3.And(*pins) if len(pins) >= 2 else pins[0])
    solver.add(z3.Not(is_true))
    return bool(solver.check() == z3.unsat)


def _cross_tenant_witness(
    model: Any,
    row: dict[str, object],
    column: Any,
    session_tenant: Any,
    is_true: Any,
    ctx: _Context,
    assertions: list[Any],
) -> dict[str, object] | None:
    """Refine a cross-tenant leak model into an honest characterizing row.

    Characterizes the leaking ROW (the session side is "some authenticated
    session of a different tenant"). The discriminator ``column`` is, by
    construction, "a tenant other than the session's" — its model value
    matters ONLY when the predicate pins the leak to that one value (a
    hardcoded ``tenant = 'X'`` bypass: ``is_true ∧ column != session ∧
    column != X`` is UNSAT). Otherwise (an ``OR is_public`` / admin bypass —
    other tenants leak too) it is a don't-care and is dropped, leaving the
    columns that actually characterize the bypass. Z3's arbitrary string
    placeholders are scrubbed from any kept value.

    The kept columns are then run through ``_cross_tenant_witness_sufficient``:
    if pinning them (with ``column != session``) does not by itself force the
    leak — the leak also needs an unpinned opaque value (``OR (flag AND fn() =
    'x')``) or a session-only condition (an admin-role bypass) — the row is NOT
    self-sufficient and ``None`` is returned (a conditional leak), mirroring
    ``prove_anon_isolation`` / ``counterexample``. Returns the (possibly empty)
    self-sufficient row — ``{}`` meaning "every other-tenant row is readable".
    """
    disc_name = column.decl().name()
    # The discriminator is "pinned" iff its model value is the ONLY other-tenant
    # value that leaks — i.e. no leaking row exists with a *different* such value
    # (`is_true ∧ column != session ∧ column != model_value` is UNSAT). `column`
    # is constrained ``!= session`` so the model always assigns it; ``eval`` with
    # completion yields that concrete value.
    probe = z3.Solver()
    probe.set("timeout", 1000)
    for a in assertions:
        probe.add(a)
    probe.add(is_true)
    probe.add(column != session_tenant)
    probe.add(column != model.eval(column, model_completion=True))
    pinned = probe.check() == z3.unsat
    witness: dict[str, object] = {}
    for key, value in row.items():
        if key == disc_name and not pinned:
            continue  # don't-care: rows of any other tenant leak
        if _is_z3_str_placeholder(value):
            continue  # arbitrary Z3 string artifact — not characterizing
        witness[key] = value
    if not _cross_tenant_witness_sufficient(
        witness, column, session_tenant, is_true, ctx, assertions
    ):
        return None  # conditional leak — no real-column row characterizes it
    return witness


@_abstains_when_too_deep(("unverified", None))
def prove_cross_tenant_isolation(
    using_node: Any,
    auth_functions: set[str] | None = None,
    *,
    identity_columns: frozenset[str] | None = None,
) -> tuple[str, dict[str, object] | None]:
    """See `_prove_cross_tenant_once`; over the reals, refined by the
    integers (see `_integers_agree`)."""
    return _integers_agree(lambda integers: _prove_cross_tenant_once(
        using_node, auth_functions, identity_columns=identity_columns, integers=integers))


@_bare_columns("using_node")
def _prove_cross_tenant_once(
    using_node: Any,
    auth_functions: set[str] | None = None,
    *,
    identity_columns: frozenset[str] | None = None,
    integers: bool = False,
) -> tuple[str, dict[str, object] | None]:
    """Prove whether one tenant's session can read another tenant's row.

    The cross-tenant dual of ``prove_anon_isolation``. Encodes the USING
    predicate under an AUTHENTICATED session — every auth function a free,
    NON-NULL symbol standing for the session's own tenant identity — with
    the same Kleene-3VL translator, then, for the single tenant-scoping
    equality ``<column> = <session identity>`` the policy declares, asks
    whether a VISIBLE row can carry ``column != the session's tenant``:

        SAT(is_true ∧ column != session_tenant)  ⇒  cross-tenant LEAK
        UNSAT                                     ⇒  ISOLATED (proven)

    **The premise, and its edge.** "A session authenticated as one tenant"
    means that tenant's identity EXISTS, so the AXIS identity is minted
    non-NULL and ``<axis> IS NULL`` proves FALSE. That is deliberate:
    ``user_id = auth.uid() OR auth.uid() IS NULL`` is PROVEN here. It is not a
    claim about a session that carries tenancy in a GUC and no JWT at all —
    such a session does not satisfy the premise, and live it reads and updates
    other tenants' rows. ``--mode anon`` reports exactly that shape as a leak,
    which is why the split is sound. Any auth value that is NOT the axis gets
    no such premise: see ``_session_null_tests_offaxis``, which declines rather
    than assume a JWT is present.

    A visible row must belong to the session's own tenant, so isolation is
    exactly the UNSAT case. SAT yields a concrete cross-tenant row when one
    characterizes the leak (an ``OR is_public`` disjunct that lets another
    tenant's row slip past the scoping equality), or a conditional leak with
    no characterizing row when the bypass depends on the *session* (an
    admin-role disjunct) rather than the row (see ``_cross_tenant_witness``).

    Returns ``(verdict, witness)``:

    - ``("isolated", None)`` — proven: no row of another tenant is visible.
    - ``("leak", row)`` — a row of another tenant is visible. ``row`` is the
      decoded counterexample (its discriminator column differs from the
      session's tenant), or ``None`` if no real-column assignment
      characterizes it.
    - ``("unverified", None)`` — Z3 unavailable; the predicate is
      untranslatable / timed out; or the policy carries no single
      tenant-scoping equality to verify against (no discriminator, multiple
      distinct discriminators, or a sort mismatch). No claim — the
      "verifier degrades to a linter" boundary. ``USING (true)`` and other
      total leaks have no scoping equality and land here; they are already
      caught as anonymous-read leaks by ``prove_anon_isolation``.

    Soundness over recall: never returns ``isolated`` unless ``is_true ∧
    column != session_tenant`` is provably UNSAT, with ``column`` and
    ``session_tenant`` the distinct, same-sorted terms the encoder actually
    bound for the policy's own scoping equality (so the inequality is freely
    satisfiable in isolation and UNSAT can only mean the predicate forces
    the row into the session's tenant).
    """
    if not Z3_AVAILABLE:
        return ("unverified", None)
    auth = (
        auth_functions
        if auth_functions is not None
        else set(_DEFAULT_AUTH_FUNCTIONS)
    )
    ctx = _Context()
    ctx.integers = integers
    ctx.session_mode = True
    assertions: list[Any] = []
    tv = _lift_to_tv(_anon_3vl(using_node, ctx, auth, assertions), assertions)
    if tv is None:
        return ("unverified", None)

    pairs = _distinct_tenant_pairs(ctx.tenant_pairs)
    if len(pairs) != 1:
        # No single tenant axis ⇒ nothing sound to prove against.
        return ("unverified", None)
    column, session_tenant = pairs[0]
    if _session_null_tests_offaxis(ctx, session_tenant):
        # The predicate turns on whether some auth call OTHER than the tenant
        # axis is NULL. `session_mode` mints those non-NULL, which is only
        # true of a JWT-bearing deployment — decline rather than prove.
        return ("unverified", None)
    # The axis must be a tenant/identity DISCRIMINATOR. Any `<column> =
    # <session value>` equality records a pair, but `status =
    # current_setting('app.status', true)` or `region = current_setting(
    # 'app.region', true)` carries no tenant scoping at all — proving
    # `status != session.status` UNSAT is vacuous and read as "no
    # cross-tenant read" was a false PROVEN. The tenant-axis set
    # (`sec021.AXIS_IDENTITY_COLUMNS`): SEC021's own flagging names plus the
    # ambiguous bare spellings that rule excludes, since `client = <session
    # value>` is a real axis even where `client = 'x'` is too noisy to flag.
    # Overridable.
    if identity_columns is None:
        from pgrls.rules.sec021 import (  # noqa: PLC0415 — avoids a rules↔diff import cycle
            AXIS_IDENTITY_COLUMNS,
        )

        identity_columns = frozenset(AXIS_IDENTITY_COLUMNS)
    axis = column.decl().name().rsplit(".", 1)[-1].lower()
    if axis not in identity_columns:
        return ("unverified", None)

    solver = z3.Solver()
    solver.set("timeout", 1000)
    for a in assertions:
        solver.add(a)
    solver.add(tv.is_true)
    try:
        solver.add(column != session_tenant)
    except z3.Z3Exception:  # pragma: no cover - sorts matched at record time
        return ("unverified", None)
    result = solver.check()
    if result == z3.unsat:
        return ("isolated", None)
    if result != z3.sat:  # unknown / timeout — no claim
        return ("unverified", None)

    model = solver.model()
    row = _decode_model(model, ctx)
    witness = _cross_tenant_witness(
        model, row, column, session_tenant, tv.is_true, ctx, assertions
    )
    return ("leak", witness)


@_abstains_when_too_deep(None)
@_bare_columns("using_node")
def cross_tenant_session_identity(
    using_node: Any, auth_functions: set[str] | None = None
) -> tuple[str, str] | None:
    """The ``(discriminator column, session-identity SQL)`` of a policy's single
    tenant-scoping equality — what `pgrls verify --mode cross-tenant
    --emit-repro` needs to set the session's tenant and insert an other-tenant
    row.

    Re-runs the same session-mode encoding as ``prove_cross_tenant_isolation``
    and reads the single recorded scoping pair, so it picks the EXACT axis the
    prover verified (a LEAK verdict guarantees exactly one pair). The session
    SQL is the canonical rendering of the auth expression the discriminator is
    compared to — recovered from the session symbol's decl name (keyed by
    ``_canon`` = the RawStream SQL) — e.g. ``auth.uid()`` or
    ``current_setting('app.tenant_id', TRUE)``.

    Returns None when Z3 is unavailable, the predicate is untranslatable, or
    there is not exactly one scoping pair (the same boundary that makes
    ``prove_cross_tenant_isolation`` decline to UNVERIFIED — so a real LEAK
    always yields a pair here).
    """
    if not Z3_AVAILABLE:
        return None
    auth = (
        auth_functions
        if auth_functions is not None
        else set(_DEFAULT_AUTH_FUNCTIONS)
    )
    for integers in (False, True):
        # A leak may come from the integer pass alone (`_integers_agree`).
        ctx = _Context()
        ctx.session_mode = True
        ctx.integers = integers
        assertions: list[Any] = []
        tv = _lift_to_tv(_anon_3vl(using_node, ctx, auth, assertions), assertions)
        if tv is not None:
            break
    else:
        return None
    pairs = _distinct_tenant_pairs(ctx.tenant_pairs)
    if len(pairs) != 1:
        return None
    column, session = pairs[0]
    return (column.decl().name(), session.decl().name()[len(_SESSION_PREFIX):])
