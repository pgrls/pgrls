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

The fix is **additive**: it CREATEs an index alongside the existing
plain index that PERF004 reported as wasted. PERF004's other remedy
— rewriting the predicate to compare the bare column — needs human
intent (the function might be load-bearing for case-insensitive
matching, or might be removable) and is out of scope. The
description points at the alternative.
"""
from __future__ import annotations

from typing import Any

from pglast.ast import FuncCall, Node
from pglast.stream import RawStream

from pgrls.ast_utils import extract_column_refs
from pgrls.fixers import Fix
from pgrls.fixers._idents import quote_qualified
from pgrls.model import Schema, Table
# Reuse PERF004's canonical own-column resolution and leading-column
# index check — the fixer indexes exactly the (table, column) pairs
# the rule reports as wasted, no more, no less.
from pgrls.rules._allowlist import parse_policy_id_allowlist
from pgrls.rules.perf003 import _has_leading_column_index, _own_table_column


def _top_funccalls_wrapping(
    node: Any, table: Table, flagged_columns: set[str]
) -> list[FuncCall]:
    """Return the OUTERMOST FuncCalls in `node` that wrap a flagged
    own-table column.

    "Outermost" means: the FuncCall contains (recursively) a flagged
    column, and is NOT itself a descendant of another FuncCall that
    also wraps the column. For `lower(upper(email))` with `email`
    flagged, returns `[FuncCall("lower", …)]` once — the index has
    to match the full predicate expression, not the inner `upper`.

    Sub-select column refs are excluded by `extract_column_refs(
    exclude_sublinks=True)` — those belong to other tables and PERF004
    itself skips them.
    """
    out: list[FuncCall] = []

    def wraps_flagged(fc: FuncCall) -> bool:
        for ref in extract_column_refs(fc, exclude_sublinks=True):
            col = _own_table_column(ref, table)
            if col is not None and col in flagged_columns:
                return True
        return False

    def walk(n: Any, inside_funccall: bool) -> None:
        if n is None:
            return
        if isinstance(n, (list, tuple)):
            for item in n:
                walk(item, inside_funccall)
            return
        if isinstance(n, FuncCall):
            if not inside_funccall and wraps_flagged(n):
                out.append(n)
                # Don't recurse — any nested FuncCall inside `n` is
                # already covered by the outer index expression.
                return
            # Either we're already inside a wrapping FuncCall (the
            # outer one covered us) or this FuncCall doesn't wrap a
            # flagged column. Recurse with the inside flag set so a
            # sibling FuncCall under a non-wrapping parent (rare)
            # still gets considered.
            for field_name in n:
                walk(getattr(n, field_name, None), True)
            return
        if isinstance(n, Node):
            for field_name in n:
                walk(getattr(n, field_name, None), inside_funccall)

    walk(node, False)
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
                policy_id = f"{table.schema}.{table.name}.{policy.name}"
                if policy_id in allowlist:
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
        return Fix(
            rule_id="PERF004",
            # One Fix per (table, expression) — the location names
            # the table and the expression text so multiple fixes on
            # one table sort deterministically and pin which
            # predicate they match.
            location=f"{schema}.{table}::{expr_sql}",
            sql=f"CREATE INDEX ON {qtable} ({expr_sql});",
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
