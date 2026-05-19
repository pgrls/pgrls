"""PERF003 fixer — emit `CREATE INDEX` for an unindexed policy column.

PERF003 flags an RLS policy whose `USING` / `WITH CHECK` predicate
filters on an own-table column with no leading-column index — the
planner sequential-scans the table on every policy-filtered query.
The mechanical fix is one B-tree index per offending column:

    CREATE INDEX ON <schema>.<table> (<column>);

The fixer reuses PERF003's own detection (`PERF003._unindexed_columns`)
so it indexes exactly the columns the rule flags. One index can
clear several PERF003 violations: if two policies on a table both
filter on the same unindexed column the rule fires twice, but the
fixer emits a single `CREATE INDEX` — fixes are deduplicated per
table + column.

The statement is a plain `CREATE INDEX`, not `CREATE INDEX
CONCURRENTLY`: a plain build composes with `pgrls fix --apply`'s
single all-or-nothing transaction, which `CONCURRENTLY` cannot run
inside. A plain build holds a lock that blocks writes to the table
for its duration — quick on a small table, disruptive on a large,
busy one. Each Fix's description says so and points at `CREATE
INDEX CONCURRENTLY` as the production-safe alternative; `pgrls fix
--output` writes the SQL to a file to adapt.
"""
from __future__ import annotations

from typing import Any

from pgrls.fixers import Fix
from pgrls.fixers._idents import quote_ident, quote_qualified
from pgrls.model import Schema
from pgrls.rules._allowlist import parse_policy_id_allowlist
# Reuse the rule's detection so the fixer indexes exactly the
# columns PERF003 reports — single source of truth.
from pgrls.rules.perf003 import PERF003


class PERF003Fixer:
    rule_id: str = "PERF003"

    def fix(
        self, schema: Schema, options: dict[str, Any]
    ) -> list[Fix]:
        # Strict allowlist parsing (the same parser PERF003 uses):
        # a malformed allowlist raises, surfaced by the `fix` CLI.
        allowlist = parse_policy_id_allowlist("PERF003", options)
        out: list[Fix] = []
        for table in schema.tables:
            # Mirror PERF003: only RLS-enabled tables filter through
            # policies, so only they have an index-coverage concern.
            if not table.rls_enabled:
                continue
            # Union the unindexed columns across every policy the
            # rule would flag (allowlisted policies excluded). One
            # index per column resolves it for all of them, so the
            # fixer keys on (table, column), not (policy, column).
            columns: set[str] = set()
            for policy in table.policies:
                policy_id = (
                    f"{table.schema}.{table.name}.{policy.name}"
                )
                if policy_id in allowlist:
                    continue
                columns.update(
                    PERF003._unindexed_columns(table, policy)
                )
            for column in sorted(columns):
                out.append(
                    self._fix(table.schema, table.name, column)
                )
        return out

    @staticmethod
    def _fix(schema: str, table: str, column: str) -> Fix:
        qtable = quote_qualified(schema, table)
        return Fix(
            rule_id="PERF003",
            location=f"{schema}.{table} ({column})",
            sql=f"CREATE INDEX ON {qtable} ({quote_ident(column)});",
            description=(
                f"Add a B-tree index on the {column!r} column of "
                f"{schema}.{table} — an RLS policy filters on it "
                "with no leading-column index, so the planner "
                "sequential-scans the table on every "
                "policy-filtered query. This is a plain CREATE "
                "INDEX: it holds a lock that blocks writes to the "
                "table while the index builds — quick on a small "
                "table, disruptive on a large, busy one. For those, "
                "use CREATE INDEX CONCURRENTLY instead (it does not "
                "block writes but cannot run inside a transaction); "
                "`pgrls fix --output` writes the SQL to a file you "
                "can adapt."
            ),
        )
