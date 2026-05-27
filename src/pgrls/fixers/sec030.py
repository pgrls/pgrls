"""SEC030 fixer — emit `ALTER TABLE ... ALTER COLUMN ... SET NOT NULL`.

SEC030 flags a row-scoping policy keyed off a NULLABLE discriminator
column. Two failure modes (rule docstring): under plain `=`, a NULL
row is silently invisible to every tenant; the moment any policy on
the table adopts a NULL-tolerant form (``IS NOT DISTINCT FROM``,
``OR col IS NULL``, ``COALESCE``), every NULL row becomes visible to
every tenant. Adding `NOT NULL` to the discriminator forecloses both.

The mechanical fix is one statement per flagged column:

    ALTER TABLE <schema>.<table> ALTER COLUMN <column> SET NOT NULL;

**Critical caveat — `--apply` will fail if NULLs already exist.**
Postgres scans the column at the ALTER and rejects the statement
with `ERROR: column "x" contains null values` if any row has NULL.
The fix description names this explicitly so the operator either
(a) backfills existing NULLs first (UPDATE with the intended
default, then re-run the fix), (b) adds a DEFAULT and a backfill
in a migration, or (c) decides the NULLs are intentional and
allowlists the table. There is no "auto-backfill" — the right
non-null sentinel for a tenant discriminator (the actual tenant
id, a backstop tenant, an opaque marker) is application logic
that pgrls cannot infer.

One Fix per flagged column (mirrors SEC030's per-table-per-column
report shape). A table flagged for two nullable scoping columns
gets two Fix entries — each ALTER COLUMN is independent and may
succeed independently. Allowlist semantics mirror the rule:
`[lint.rules.SEC030].allowlist` keyed on table name (qualified or
bare); an entry skips the whole table.

The rule's other remedy (a DEFAULT + trigger to populate the
column) is operator-specific and out of scope for the mechanical
fixer; the description points at it.
"""
from __future__ import annotations

from typing import Any

from pgrls.fixers import Fix
from pgrls.fixers._idents import quote_ident, quote_qualified
from pgrls.model import Schema, Table
from pgrls.rules._allowlist import parse_table_ref_allowlist
from pgrls.rules.sec030 import (
    _parse_auth_functions,
    _scoping_columns,
    _table_allowlisted,
)


class SEC030Fixer:
    rule_id: str = "SEC030"

    def fix(
        self, schema: Schema, options: dict[str, Any]
    ) -> list[Fix]:
        # Strict allowlist parsing — same parser SEC030 uses; a
        # malformed allowlist raises TypeError, surfaced by `pgrls
        # fix` as a tool error.
        allowlist = parse_table_ref_allowlist("SEC030", options)
        auth_functions = _parse_auth_functions(options)
        out: list[Fix] = []
        for table in schema.tables:
            # Mirror SEC030's detection precisely.
            if not table.rls_enabled:
                continue
            if not table.policies:
                continue
            # Without column nullability (pre-v5 snapshot), the rule
            # itself can't tell nullable from NOT NULL; the fixer
            # mirrors the no-Fix behaviour.
            if not table.column_details:
                continue
            if _table_allowlisted(table, allowlist):
                continue

            scoping: set[str] = set()
            for policy in table.policies:
                for ast in (policy.using_ast, policy.with_check_ast):
                    if ast is not None:
                        scoping |= _scoping_columns(
                            ast, table, auth_functions
                        )
            if not scoping:
                continue

            nullable_cols = {
                c.name for c in table.column_details if c.is_nullable
            }
            for column in sorted(scoping & nullable_cols):
                out.append(self._fix(table, column))
        return out

    @staticmethod
    def _fix(table: Table, column: str) -> Fix:
        qtable = quote_qualified(table.schema, table.name)
        qcol = quote_ident(column)
        return Fix(
            rule_id="SEC030",
            location=f"{table.schema}.{table.name}.{column}",
            sql=(
                f"ALTER TABLE {qtable} "
                f"ALTER COLUMN {qcol} SET NOT NULL;"
            ),
            description=(
                f"Set {column} NOT NULL on {table.schema}.{table.name} "
                "so a NULL discriminator can't make rows invisible to "
                "every tenant under `=`, or visible to every tenant "
                "the moment any policy adopts a NULL-tolerant form. "
                "**BACKFILL ANY EXISTING NULLs FIRST.** Postgres "
                "scans the column at ALTER time and rejects this "
                "statement with `ERROR: column contains null values` "
                "if even one row has NULL — pgrls cannot infer the "
                "right tenant-id / sentinel to backfill with, so "
                "that's your decision. Common shape: `UPDATE "
                f"{table.schema}.{table.name} SET {column} = <value> "
                f"WHERE {column} IS NULL;` BEFORE running this fix. "
                "If the NULLs are an intentional sentinel, allowlist "
                f"`{table.schema}.{table.name}` under "
                "[lint.rules.SEC030].allowlist instead."
            ),
        )
