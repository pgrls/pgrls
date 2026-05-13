"""PERF003 — Policy predicate column without a leading-column index.

A typical multi-tenant RLS policy looks like
``USING (tenant_id = current_setting('app.tenant_id'))``. Postgres
evaluates the predicate for every candidate row. Without an index
whose leading column is ``tenant_id``, the planner sequential-
scans the table — fine for a few thousand rows, catastrophic on a
multi-tenant table with millions.

Detection is structural:

1. Walk every RLS-enabled table.
2. For each policy on the table, collect column references in
   ``using_ast`` and ``with_check_ast`` via
   ``extract_column_refs(exclude_sublinks=True)`` — the sublink
   exclusion drops refs that come from inner subqueries (those
   columns live on other tables and a missing index there is a
   different concern).
3. Drop refs that don't point at the policy's own table:
   * Unqualified refs (``("tenant_id",)``) are assumed to be
     own-table; Postgres resolves them against the policy's
     relation at CREATE POLICY time.
   * Qualified refs (``("u", "tenant_id")``, ``("public", "users",
     "tenant_id")``) are kept only when the qualifier matches the
     table's bare name. Cross-table refs (e.g. via a JOIN inside
     ``USING``) live on a different table and indexing them is
     out of scope for this rule.
4. For each remaining column, look up ``Table.indexes`` for any
   index whose leading column matches. If none, emit a warning.

The rule treats *any* access method as "indexed" — btree, hash,
gin, gist, brin. The operator chose the index type and pgrls
doesn't second-guess the choice. A leading-column match is the
relevant signal: a B-tree on ``(tenant_id, created_at)`` helps
``WHERE tenant_id = X``, but a B-tree on ``(created_at, tenant_id)``
does not. Partial indexes also count — the operator is responsible
for ensuring the partial predicate is satisfied by the policy
predicate (pgrls can't statically prove that compatibility).

**Known limitations** (intentional in v0.5.10):

* Expression indexes (``CREATE INDEX ON tbl (lower(email))``) are
  not matched. The expression list lives in ``pg_index.indexprs``
  which v0.5.10's introspection doesn't decode. PERF003 will
  flag the column as un-indexed even when a matching expression
  index exists. Allowlist the policy ID when this surfaces a
  false positive.
* Composite-key policies (``USING (tenant_id = X AND owner = Y)``)
  fire PERF003 for each referenced column independently. An
  operator who has a composite index ``(tenant_id, owner)`` gets
  one violation for ``tenant_id`` (the leading column matches —
  no fire) and one for ``owner`` (no leading-column match). The
  ``owner`` fire is a false positive in this case; allowlist or
  add a second index ``(owner)`` if the lookup direction matters.
* Tables without RLS are skipped entirely. PERF003's concern is
  policy-driven filtering performance; tables without policies
  don't filter via RLS.

Severity: warning. Allowlist by qualified policy ID
(``schema.table.policy_name``).
"""
from __future__ import annotations

from typing import Any

from pgrls.ast_utils import extract_column_refs
from pgrls.model import Index, Schema, Table
from pgrls.rules._allowlist import parse_policy_id_allowlist
from pgrls.violations import Severity, Violation


def _parse_allowlist(options: dict[str, Any]) -> set[str]:
    return parse_policy_id_allowlist("PERF003", options)


def _own_table_column(
    ref: tuple[str, ...], table: Table
) -> str | None:
    """Return the column name iff `ref` resolves to a column on `table`.

    Refs come from `extract_column_refs` as tuples of name parts:

    * ``("col",)`` — unqualified, treated as own-table.
    * ``("alias", "col")`` — qualified; accepted if alias matches
      the table's bare name (Postgres allows the table name as an
      alias in the policy's USING clause).
    * ``("schema", "table", "col")`` — fully qualified; accepted
      if `schema.table` matches the policy's relation.
    * Other shapes — skipped (likely cross-table refs from a JOIN
      or unusual qualifier patterns we can't statically resolve).
    """
    if len(ref) == 1:
        return ref[0]
    if len(ref) == 2:
        qualifier, col = ref
        if qualifier == table.name:
            return col
        return None
    if len(ref) == 3:
        schema, name, col = ref
        if schema == table.schema and name == table.name:
            return col
        return None
    return None


def _has_leading_column_index(
    table: Table, column: str
) -> bool:
    """True if any index on `table` has `column` as its leading column.

    Treats every access method as indexed (btree/hash/gin/gist/brin).
    Partial indexes count — pgrls can't statically verify the
    partial predicate matches the policy predicate, so we trust the
    operator's intent. Expression positions (where the captured
    column name is empty) never match by definition; an expression
    index on ``(lower(email))`` has ``columns = ("",)`` after
    introspection.
    """
    for idx in table.indexes:
        if not idx.columns:
            continue
        if idx.columns[0] == column:
            return True
    return False


class PERF003:
    id: str = "PERF003"
    severity: Severity = "warning"
    title: str = "Policy predicate column without leading-column index"

    def check(
        self, schema: Schema, options: dict[str, Any]
    ) -> list[Violation]:
        allowlist = _parse_allowlist(options)
        out: list[Violation] = []
        for table in schema.tables:
            if not table.rls_enabled:
                # PERF003's concern is policy-driven filtering;
                # tables without RLS don't filter via RLS so
                # missing indexes there are a different perf
                # question. SEC001 already flags rls_enabled=False
                # tables when they have policies.
                continue
            for policy in table.policies:
                policy_id = (
                    f"{table.schema}.{table.name}.{policy.name}"
                )
                if policy_id in allowlist:
                    continue
                unindexed = self._unindexed_columns(table, policy)
                if not unindexed:
                    continue
                out.append(self._violation(
                    table, policy_id, policy.name, unindexed
                ))
        return out

    def _unindexed_columns(
        self, table: Table, policy: Any
    ) -> list[str]:
        """Collect own-table columns referenced by the policy that
        lack a leading-column index.

        Walks both `using_ast` and `with_check_ast` because either
        side can drive a sequential scan: USING filters reads,
        WITH CHECK filters writes — both run the predicate per row.
        Refs from sublinks are skipped via `exclude_sublinks=True`;
        a `EXISTS (SELECT 1 FROM other_table WHERE ...)` references
        another table and its index health is out of scope.

        Returns a sorted list so the violation message is
        deterministic across runs.
        """
        refs: set[tuple[str, ...]] = set()
        if policy.using_ast is not None:
            refs |= extract_column_refs(
                policy.using_ast, exclude_sublinks=True
            )
        if policy.with_check_ast is not None:
            refs |= extract_column_refs(
                policy.with_check_ast, exclude_sublinks=True
            )

        # `Table.columns` lists the live columns (dropped columns
        # are filtered at introspection time). A policy that
        # references a column NOT in this set is broken — HYG001
        # flags it for the missing column directly. PERF003 has
        # nothing useful to say about an unindexed reference to a
        # column that doesn't exist, so skip those refs. Pg's
        # `pg_get_expr` renders dropped column refs as the literal
        # `?dropped?column?` token; that token won't match any
        # `Table.columns` entry either, so the same check covers it.
        #
        # The check is gated on `Table.columns` being non-empty:
        # unit-test fixtures that construct `Table(...)` without
        # populating `columns` (default `()`) shouldn't be punished
        # for omitting the field, and v3-baseline snapshots that
        # legitimately have empty columns shouldn't lose all
        # PERF003 coverage. Real introspection (v5+) always
        # populates `columns`, so the filter activates in production.
        live_columns = set(table.columns)
        unindexed: set[str] = set()
        for ref in refs:
            col = _own_table_column(ref, table)
            if col is None:
                continue
            if live_columns and col not in live_columns:
                continue
            if _has_leading_column_index(table, col):
                continue
            unindexed.add(col)
        return sorted(unindexed)

    def _violation(
        self,
        table: Table,
        policy_id: str,
        policy_name: str,
        unindexed: list[str],
    ) -> Violation:
        cols_text = ", ".join(repr(c) for c in unindexed)
        plural_col = "column" if len(unindexed) == 1 else "columns"
        plural_has = "has" if len(unindexed) == 1 else "have"
        return Violation(
            rule_id=self.id,
            severity=self.severity,
            title=self.title,
            message=(
                f"Policy {policy_name!r} on {table.qualified_name} "
                f"references {plural_col} {cols_text} which "
                f"{plural_has} no leading-column index. Postgres "
                "evaluates the policy predicate per row, so without "
                "an index on the filtering column the planner does a "
                "sequential scan — fine for small tables, "
                "catastrophic on multi-tenant tables with millions "
                "of rows. Add a B-tree index whose leading column "
                f"matches (e.g. `CREATE INDEX ON {table.qualified_name} "
                "(tenant_id)` for a tenant_id-filtered policy), or "
                f"allowlist this policy as {policy_id!r} in "
                "[lint.rules.PERF003] if a matching expression "
                "index exists (expression indexes aren't matched in "
                "v0.5.10) or if sequential scan is acceptable for "
                "the table's size."
            ),
            location=policy_id,
        )
