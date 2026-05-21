"""PERF004 — Policy filters on a function-wrapped column, defeating a plain index.

A B-tree index on a column serves predicates on that **bare** column
(`tenant_id = …`). It does **not** serve a predicate that wraps the
column in a function: Postgres can only use an index whose indexed
expression matches the query expression. So a policy like

```sql
CREATE POLICY p ON users
    USING (lower(email) = current_setting('app.email'));
```

with an ordinary `CREATE INDEX ON users (email)` will **sequential
scan** — the `lower(...)` wrapper makes the plain index unusable. The
fix is an *expression* index matching the predicate:
`CREATE INDEX ON users (lower(email))`.

PERF004 is the precise complement of **PERF003** (policy predicate
column without a leading-column index). The two are disjoint by the
index condition, so a column trips at most one:

* If the wrapped column has **no** plain index, PERF003 already fires
  (the column is un-indexed) — PERF004 stays silent.
* If the wrapped column **does** have a plain leading-column index,
  PERF003 is satisfied and stays silent (it sees the index and can't
  tell the wrapper defeats it) — that false-negative is exactly what
  PERF004 catches: the plain index exists but the `func(col)` predicate
  can't use it.

Detection is structural: a policy's `USING` / `WITH CHECK` AST is
walked for `FuncCall` nodes, and any own-table column appearing inside
one is "function-wrapped". A wrapped column is flagged only when the
table has a plain leading-column index on it (the index being wasted).
Sub-select columns are excluded (they live on other tables). The
column-on-the-value-side case (`tenant_id = lower(current_setting(…))`)
does not fire — `tenant_id` is a bare operand and its index is usable;
the function wraps the *value*, not the column.

Scope is **`FuncCall` wrapping only** — the textbook functional-index
case (`lower(col)`, `upper(col)`, `date_trunc(…, col)`, custom
functions). Other expression forms that also defeat a plain index —
`COALESCE`/`CASE` (their own AST node types, not `FuncCall`), operator
expressions (`col || …`), and casts (`col::text`) — are out of scope:
catching every wrapper shape is a rabbit hole, and the function-call
form is the common, high-signal one. A column wrapped only in those
other forms is not flagged.

Known limitation (shared with PERF003): pgrls does not decode
expression indexes (`pg_index.indexprs`), so it cannot confirm a
matching expression index already exists. In the rare case a table has
*both* a plain `(email)` index and the correct `(lower(email))`
expression index, PERF004 will fire a false positive — allowlist the
policy ID.

Severity: warning. The fix is an expression index matching the
predicate, or rewriting the policy to compare the bare column.
Allowlist by qualified policy ID.
"""
from __future__ import annotations

from typing import Any

from pglast.ast import FuncCall, Node

from pgrls.ast_utils import extract_column_refs
from pgrls.model import Schema, Table
# Reuse PERF003's canonical own-column resolution and leading-column
# index check — PERF004 flags a subset of the same column/index space,
# so sharing the helpers keeps the two rules' notions of "own column"
# and "indexed" identical.
from pgrls.rules._allowlist import parse_policy_id_allowlist
from pgrls.rules.perf003 import _has_leading_column_index, _own_table_column
from pgrls.violations import Severity, Violation


def _function_wrapped_own_columns(node: Any, table: Table) -> set[str]:
    """Own-table columns that appear inside a `FuncCall` in `node`.

    A column under any function call (`lower(email)`, `coalesce(tenant_id,
    0)`, nested `lower(upper(x))`) is function-wrapped — a plain index on
    the bare column cannot serve a predicate using it. `current_setting`
    and other auth functions take string/literal arguments, not columns,
    so they contribute nothing here. Sub-select columns are excluded
    (`exclude_sublinks=True`) — they belong to other tables.
    """
    found: set[str] = set()

    def walk(n: Any) -> None:
        if n is None:
            return
        if isinstance(n, (list, tuple)):
            for item in n:
                walk(item)
            return
        if isinstance(n, FuncCall):
            for ref in extract_column_refs(n, exclude_sublinks=True):
                col = _own_table_column(ref, table)
                if col is not None:
                    found.add(col)
            # fall through: nested FuncCalls are already covered by the
            # extract above, but a sibling FuncCall elsewhere in the
            # tree still needs walking.
        if isinstance(n, Node):
            for field_name in n:
                walk(getattr(n, field_name, None))

    walk(node)
    return found


class PERF004:
    id: str = "PERF004"
    severity: Severity = "warning"
    title: str = "Policy filters on a function-wrapped column, defeating a plain index"

    def check(
        self, schema: Schema, options: dict[str, Any]
    ) -> list[Violation]:
        allowlist = parse_policy_id_allowlist("PERF004", options)
        out: list[Violation] = []
        for table in schema.tables:
            if not table.rls_enabled:
                continue
            live_columns = set(table.columns)
            for policy in table.policies:
                policy_id = f"{table.schema}.{table.name}.{policy.name}"
                if policy_id in allowlist:
                    continue
                wrapped: set[str] = set()
                for ast in (policy.using_ast, policy.with_check_ast):
                    if ast is not None:
                        wrapped |= _function_wrapped_own_columns(ast, table)
                flagged = sorted(
                    col
                    for col in wrapped
                    if (not live_columns or col in live_columns)
                    and _has_leading_column_index(table, col)
                )
                if not flagged:
                    continue
                out.append(self._violation(table, policy, policy_id, flagged))
        return out

    def _violation(
        self,
        table: Table,
        policy: Any,
        policy_id: str,
        columns: list[str],
    ) -> Violation:
        cols = ", ".join(repr(c) for c in columns)
        plural = "column" if len(columns) == 1 else "columns"
        return Violation(
            rule_id=self.id,
            severity=self.severity,
            title=self.title,
            message=(
                f"Policy {policy.name!r} on {table.qualified_name} wraps "
                f"the indexed {plural} {cols} in a function (e.g. "
                "`lower(col)`), so the plain index on it cannot serve the "
                "predicate — Postgres falls back to a sequential scan. "
                "Add an expression index matching the predicate (e.g. "
                f"`CREATE INDEX ON {table.qualified_name} (lower(col))`), "
                "compare the bare column instead, or allowlist this "
                f"policy as {policy_id!r} in [lint.rules.PERF004] (for "
                "example when a matching expression index already exists "
                "— pgrls cannot detect those)."
            ),
            location=policy_id,
        )
