"""PERF004 fixer — emit `CREATE INDEX` for a function-wrapped column.

PERF004 flags an RLS policy whose `USING` / `WITH CHECK` predicate
wraps an indexed own-table column in a function call (`lower(email)`,
`date_trunc('day', created_at)`, etc.), defeating the plain
leading-column B-tree index. The mechanical fix is an *expression*
index that matches the predicate exactly:

    CREATE INDEX ON <schema>.<table> (<function-expression>);

The fixer walks the policy AST, finds each top-level `FuncCall` that
wraps a column the rule flags, and renders the call back to SQL
through `pglast.stream.RawStream`. One CREATE INDEX is emitted per
distinct (table, expression-text) pair — multiple policies hitting
the same `lower(email)` collapse to one statement.

Only the OUTERMOST `FuncCall` containing the column is emitted: for
`lower(upper(email))`, the index has to match the full expression
the planner sees in the predicate, so the fixer emits
`CREATE INDEX ON t (lower(upper(email)))`, not the inner
`upper(email)`. The walk tracks "currently inside a FuncCall" so a
nested FuncCall whose parent already wraps the column is skipped.

The statement is plain `CREATE INDEX`, not `CREATE INDEX
CONCURRENTLY` — same rationale PERF003's fixer documents: a plain
build composes with `pgrls fix --apply`'s single all-or-nothing
transaction, which `CONCURRENTLY` cannot run inside. Plain builds
hold a write lock for the duration; the description points at the
`CONCURRENTLY` alternative for production-size tables, and `pgrls
fix --output` writes the SQL to a file for the operator to adapt.

Postgres requires every function in an index expression to be
IMMUTABLE and rejects STABLE / VOLATILE ones at runtime. The fixer
therefore emits an index only when the *whole* operand is provably
immutable — built solely from a curated set of always-IMMUTABLE
builtin functions (`lower`, `upper`, `md5`, …), column refs, and
literals (`_is_immutable_index_expr`). The conditionally-STABLE time
functions (`date_trunc('day', created_at)` on a `timestamptz` is
STABLE) and anything it cannot vouch for — operators, casts,
user-defined functions — make it ABSTAIN: the rule still reports, and
the operator reshapes the predicate / adds the index by hand. This
keeps `pgrls fix --apply` (one all-or-nothing transaction) from
aborting the whole batch on a single server-rejected CREATE INDEX.

The fix is **additive**: it CREATEs an index alongside the existing
plain index that PERF004 reported as wasted. PERF004's other remedy
— rewriting the predicate to compare the bare column — needs human
intent (the function might be load-bearing for case-insensitive
matching, or might be removable) and is out of scope. The
description points at the alternative.
"""
from __future__ import annotations

import hashlib
from typing import Any

from pglast.ast import A_Const, A_Expr, BoolExpr, ColumnRef, FuncCall, Node, String
from pglast.enums import A_Expr_Kind
from pglast.stream import RawStream

from pgrls.ast_utils import extract_column_refs, func_name_parts
from pgrls.fixers import Fix
from pgrls.fixers._idents import quote_qualified
from pgrls.model import Schema, Table, policy_id
# Reuse PERF004's canonical own-column resolution and leading-column
# index check — the fixer indexes exactly the (table, column) pairs
# the rule reports as wasted, no more, no less.
from pgrls.rules._allowlist import parse_policy_id_allowlist
from pgrls.rules.perf003 import _has_leading_column_index, _own_table_column


# Comparison / pattern operators whose direct operand the planner
# evaluates as an indexable value expression. Arithmetic / concat
# operators (`+`, `||`, …) are deliberately excluded: their result, not
# the inner FuncCall, is the comparison operand.
_COMPARISON_OPS: frozenset[str] = frozenset({
    "=", "<>", "!=", "<", ">", "<=", ">=",
    "~~", "~~*", "!~~", "!~~*", "~", "~*", "!~", "!~*",
})
_COMPARISON_AEXPR_KINDS: frozenset[Any] = frozenset({
    A_Expr_Kind.AEXPR_IN,
    A_Expr_Kind.AEXPR_LIKE,
    A_Expr_Kind.AEXPR_ILIKE,
    A_Expr_Kind.AEXPR_BETWEEN,
    A_Expr_Kind.AEXPR_NOT_BETWEEN,
})


# Builtin functions that are IMMUTABLE in EVERY overload, so an
# expression built only from them (+ column refs + literals) is legal in
# a CREATE INDEX. Postgres requires every function in an index expression
# to be IMMUTABLE and rejects STABLE/VOLATILE ones at runtime ("functions
# in index expression must be marked IMMUTABLE"). Deliberately CONSERVATIVE
# and builtin-focused: the dominant PERF004 wrapper is case-normalization
# (`lower`/`upper`). Notably EXCLUDED are the conditionally-STABLE time
# functions — `date_trunc`/`date_part`/`extract`/`to_char`/`age`/… —
# whose volatility depends on the argument type (e.g. `date_trunc('day',
# ts)` is STABLE for `timestamptz` but IMMUTABLE for `timestamp`). When
# the expression is not provably immutable the fixer ABSTAINS (the rule
# still reports; the operator reshapes/indexes by hand), rather than
# emitting a CREATE INDEX that fails at apply and — under fix --apply's
# single all-or-nothing transaction — rolls back every other fix too.
_IMMUTABLE_INDEX_SAFE_FUNCS: frozenset[str] = frozenset({
    # Case / text normalization — the dominant PERF004 wrapper shape.
    "lower", "upper", "initcap",
    # Hashing.
    "md5", "sha224", "sha256", "sha384", "sha512",
    # Length.
    "length", "char_length", "character_length",
    "octet_length", "bit_length",
    # Trim / pad.
    "btrim", "ltrim", "rtrim", "trim", "lpad", "rpad",
    # Substring / slice.
    "substr", "substring", "left", "right",
    # Other pure string transforms.
    "reverse", "replace", "translate", "ascii", "chr", "to_hex",
    # Basic numeric (every overload IMMUTABLE).
    "abs", "sign", "ceil", "ceiling", "floor", "round", "trunc", "mod",
})


def _is_immutable_index_expr(node: Any) -> bool:
    """True iff `node` is safe to splice into a ``CREATE INDEX`` — i.e. the
    whole expression is built only from known-IMMUTABLE builtin functions,
    column refs, and literal constants.

    Conservative by design: any node it cannot vouch for as IMMUTABLE —
    a non-allowlisted or schema-qualified (possibly user-defined, possibly
    VOLATILE) function, an operator (``A_Expr``), a ``TypeCast``,
    ``CaseExpr``/``CoalesceExpr``, a sub-select, … — makes it return False,
    so the fixer abstains rather than emit an index Postgres would reject.
    """
    if node is None:
        return True
    if isinstance(node, (list, tuple)):
        return all(_is_immutable_index_expr(item) for item in node)
    if isinstance(node, FuncCall):
        qualified, bare = func_name_parts(node)
        if bare is None or bare not in _IMMUTABLE_INDEX_SAFE_FUNCS:
            return False
        # Builtin only: a user-defined `myschema.lower(...)` is a DIFFERENT
        # function that may be VOLATILE, so only the unqualified or
        # pg_catalog-qualified builtin counts (mirrors
        # ast_utils.is_builtin_current_setting). Its args must in turn be
        # immutable — a nested STABLE call (`lower(date_trunc(...))`) or a
        # value wrapper would equally make the index illegal.
        if qualified != bare and qualified != f"pg_catalog.{bare}":
            return False
        return _is_immutable_index_expr(node.args)
    if isinstance(node, (ColumnRef, A_Const)):
        return True
    # Any other node type cannot be vouched for — abstain.
    return False


def _has_comparison_op_name(node: A_Expr) -> bool:
    """True if `node`'s operator name is a sargable comparison (`=`, `<`,
    `~`, …) rather than arithmetic/concat (`+`, `||`)."""
    names = [s.sval for s in (node.name or ()) if isinstance(s, String)]
    return bool(names) and names[-1] in _COMPARISON_OPS


def _is_scalar_comparison(node: A_Expr) -> bool:
    """True if `node` is a plain binary scalar comparison (AEXPR_OP `=`,
    `<`, `~`, …) — both operands are indexable value expressions (the
    planner may use an index on either side)."""
    return node.kind == A_Expr_Kind.AEXPR_OP and _has_comparison_op_name(node)


# Indexability context threaded through the walk:
#   _PRED    — a boolean/predicate position (top, or under AND/OR/NOT).
#              A comparison here is a real predicate comparison.
#   _OPERAND — the direct operand of a predicate-level comparison. A
#              FuncCall wrapping a flagged column here IS the expression
#              the planner indexes.
#   _VALUE   — inside a value-producing wrapper (CASE / COALESCE /
#              arithmetic / concat / a FuncCall's args / the value side of
#              IN·BETWEEN·LIKE). A FuncCall here is a strict
#              sub-expression, never the indexable operand.
_PRED = "predicate"
_OPERAND = "operand"
_VALUE = "value"


def _top_funccalls_wrapping(
    node: Any, table: Table, flagged_columns: set[str]
) -> list[FuncCall]:
    """FuncCalls in `node` that wrap a flagged own-table column AND are the
    DIRECT operand of a predicate-level comparison — the exact expression
    the planner would index.

    For `lower(upper(email))` (email flagged) returns `[lower(upper(email))]`
    once — the index must match the full predicate operand, not the inner
    `upper`. A flagged column reached only as a STRICT SUB-EXPRESSION of the
    real operand is NOT returned, because the planner's operand is the
    enclosing value expression and an index on the inner piece is dead:

    * the value side of `IN` / `BETWEEN` / `LIKE` (`col IN (lower(x), …)`,
      `col BETWEEN date_trunc(a) AND date_trunc(b)`) — only the lexpr is
      indexable, the rexpr is the value list / bounds / pattern;
    * a `COALESCE` / `CASE` / concat / arithmetic wrapper; and
    * a comparison nested INSIDE such a value wrapper
      (`CASE WHEN lower(email) = … THEN …`) — its result feeds the
      wrapper, so its operands are not predicate operands.

    The fixer defers those to the human, exactly as the rule message
    suggests. Sub-select column refs are excluded by `extract_column_refs(
    exclude_sublinks=True)`.
    """
    out: list[FuncCall] = []

    def wraps_flagged(fc: FuncCall) -> bool:
        for ref in extract_column_refs(fc, exclude_sublinks=True):
            col = _own_table_column(ref, table)
            if col is not None and col in flagged_columns:
                return True
        return False

    def walk(n: Any, ctx: str) -> None:
        if n is None:
            return
        if isinstance(n, (list, tuple)):
            for item in n:
                walk(item, ctx)
            return
        if isinstance(n, FuncCall):
            if ctx == _OPERAND and wraps_flagged(n):
                # Only emit when the WHOLE operand is provably IMMUTABLE —
                # Postgres rejects STABLE/VOLATILE functions in an index
                # expression, and the common Supabase shape
                # `date_trunc('day', created_at)` on a timestamptz column
                # is STABLE. Abstaining (the rule still reports) is the
                # safe degradation; emitting an index that fails at apply
                # would roll back the whole all-or-nothing fix batch.
                if _is_immutable_index_expr(n):
                    out.append(n)
                # Covered either way — a nested FuncCall is part of this
                # operand, never a separate index. (When not immutable we
                # deliberately do NOT descend looking for an inner index:
                # the planner's operand is the whole expression.)
                return
            # Args are sub-expressions, never a predicate operand.
            for field_name in n:
                walk(getattr(n, field_name, None), _VALUE)
            return
        if isinstance(n, BoolExpr):
            # AND / OR / NOT preserve the boolean/predicate position.
            for field_name in n:
                walk(getattr(n, field_name, None), _PRED)
            return
        if isinstance(n, A_Expr):
            if ctx == _PRED and _is_scalar_comparison(n):
                # Plain scalar comparison: an index on either operand helps.
                walk(n.lexpr, _OPERAND)
                walk(n.rexpr, _OPERAND)
                walk(n.name, _VALUE)
                return
            if ctx == _PRED and n.kind in _COMPARISON_AEXPR_KINDS:
                # IN / LIKE / ILIKE / BETWEEN / NOT BETWEEN: only the lexpr
                # is indexable; the rexpr is the value list / bounds /
                # pattern the planner never indexes.
                walk(n.lexpr, _OPERAND)
                walk(n.rexpr, _VALUE)
                walk(n.name, _VALUE)
                return
            if (
                ctx == _PRED
                and n.kind in (
                    A_Expr_Kind.AEXPR_OP_ANY,
                    A_Expr_Kind.AEXPR_OP_ALL,
                )
                and _has_comparison_op_name(n)
            ):
                # `func(col) = ANY(array)` / `= ALL(array)`: `x = ANY(arr)`
                # is sargable, so the lexpr IS the indexable operand (the
                # planner can use an expression index on it); the rexpr is
                # the array/value side. The PERF004 rule flags these, so
                # the fixer must emit the index too. Gate on a comparison
                # operator name so a non-sargable `func(col) <op> ANY(...)`
                # still defers to the human.
                walk(n.lexpr, _OPERAND)
                walk(n.rexpr, _VALUE)
                walk(n.name, _VALUE)
                return
            # A non-comparison operator (`||`, arithmetic), or a comparison
            # NOT in predicate position (nested in a value wrapper): its
            # operands feed a value, so they are not predicate operands.
            for field_name in n:
                walk(getattr(n, field_name, None), _VALUE)
            return
        if isinstance(n, Node):
            # Any other node — CaseExpr / CoalesceExpr / TypeCast / SubLink
            # / … — is a value wrapper; a FuncCall reached through it is a
            # strict sub-expression, not a direct comparison operand.
            for field_name in n:
                walk(getattr(n, field_name, None), _VALUE)

    walk(node, _PRED)
    return out


class PERF004Fixer:
    rule_id: str = "PERF004"

    def fix(
        self, schema: Schema, options: dict[str, Any]
    ) -> list[Fix]:
        # Strict allowlist parsing (the same parser PERF004 uses):
        # a malformed allowlist raises, surfaced by the `fix` CLI.
        allowlist = parse_policy_id_allowlist("PERF004", options)
        out: list[Fix] = []
        for table in schema.tables:
            # Mirror PERF004: only RLS-enabled tables filter through
            # policies, so only they have an index-coverage concern.
            if not table.rls_enabled:
                continue
            live_columns = set(table.columns)
            # Dedup expressions per table — two policies on the
            # same table that both wrap `lower(email)` need ONE
            # CREATE INDEX, not two duplicate statements.
            seen_expressions: set[str] = set()
            for policy in table.policies:
                pid = policy_id(table, policy)
                if pid in allowlist:
                    continue
                # Resolve which columns of this policy PERF004 would
                # actually flag (wrapped + indexed + live). Mirrors
                # the rule's per-policy detection.
                from pgrls.rules.perf004 import (
                    _function_wrapped_own_columns,
                )
                wrapped: set[str] = set()
                for ast in (policy.using_ast, policy.with_check_ast):
                    if ast is not None:
                        wrapped |= _function_wrapped_own_columns(ast, table)
                flagged = {
                    col
                    for col in wrapped
                    if (not live_columns or col in live_columns)
                    and _has_leading_column_index(table, col)
                }
                if not flagged:
                    continue
                # For each AST source, collect the outermost FuncCalls
                # wrapping any flagged column and emit one index per
                # distinct rendered expression.
                for ast in (policy.using_ast, policy.with_check_ast):
                    if ast is None:
                        continue
                    for fc in _top_funccalls_wrapping(ast, table, flagged):
                        expr_sql = RawStream()(fc)
                        if expr_sql in seen_expressions:
                            continue
                        seen_expressions.add(expr_sql)
                        out.append(
                            self._fix(
                                table.schema,
                                table.name,
                                policy.name,
                                expr_sql,
                            )
                        )
        return out

    @staticmethod
    def _fix(
        schema: str, table: str, policy_name: str, expr_sql: str
    ) -> Fix:
        qtable = quote_qualified(schema, table)
        # Deterministic, idempotent index name. The PERF004 RULE keys off
        # the BARE column having a plain index and cannot decode an
        # expression index, so it keeps firing after the fix lands; an
        # unnamed `CREATE INDEX` would then be regenerated byte-identical
        # on the next `pgrls fix` run and Postgres would auto-name a
        # DUPLICATE. A name derived from (schema, table, expression) plus
        # `IF NOT EXISTS` makes a second run a no-op and the --output
        # migration safely re-runnable. The digest keeps the name a valid,
        # collision-resistant identifier well under Postgres's 63-char cap.
        digest = hashlib.sha1(
            f"{schema}.{table}.{expr_sql}".encode()
        ).hexdigest()[:16]
        index_name = f"pgrls_idx_{digest}"
        return Fix(
            rule_id="PERF004",
            # One Fix per (table, expression) — the location names
            # the table and the expression text so multiple fixes on
            # one table sort deterministically and pin which
            # predicate they match.
            location=f"{schema}.{table}::{expr_sql}",
            sql=f"CREATE INDEX IF NOT EXISTS {index_name} ON {qtable} "
            f"({expr_sql});",
            description=(
                f"Create an expression index on {schema}.{table} "
                f"matching the policy predicate `{expr_sql}` so the "
                "planner can use it instead of sequential-scanning. "
                "The existing plain index on the bare column stays "
                "in place (it serves other queries); this adds a "
                "parallel index for the function-wrapped form. For a "
                "large, busy table, switch to `CREATE INDEX "
                "CONCURRENTLY` (write to a migration via `pgrls fix "
                "--output` and adjust) — the plain build here holds a "
                "write lock for the duration. PERF004's other remedy "
                "— rewriting the predicate to compare the bare column "
                "— needs human intent and is out of scope."
            ),
        )
