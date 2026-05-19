"""SEC020 fixer — replace a constant-true WITH CHECK with USING.

SEC020 fires on a write-side policy that pairs a real `USING`
predicate with an explicit `WITH CHECK (true)`: the read side is
scoped but the write side accepts every row, so a caller can
write rows it could never read back. The canonical remediation —
and what SEC020's own message recommends — is to mirror the
`USING` predicate into `WITH CHECK` so writes are constrained the
same way reads are. The fixer emits:

    ALTER POLICY <name> ON <schema>.<table>
        WITH CHECK (<the USING predicate>);

`ALTER POLICY … WITH CHECK (…)` replaces the existing
constant-true clause, so the single statement is the whole fix.

Unlike the SEC006 fixer, this one fixes restrictive policies too.
A SEC020 finding always has an explicit `WITH CHECK (true)` and a
real `USING`, so mirroring `USING` is a meaningful, correct
tightening either way: for a permissive policy the wide-open
write side becomes scoped; for a restrictive one its no-op write
check (`restrictive AND true`) becomes a real constraint. There
is no missing-clause / dead-policy ambiguity — that is the
SEC006 fixer's concern, and SEC006 and SEC020 never fire on the
same policy (one needs `WITH CHECK` absent, the other needs it
present and constant-true).

Detection reuses the rule's own `_is_open_write_asymmetry` so the
fixer flags exactly what SEC020 reports — a single definition of
the finding. The `USING` predicate is round-tripped through
`pglast.stream.RawStream` rather than echoed verbatim — symmetric
with the SEC006 and PERF001 fixers, so pglast's escaping is
applied consistently regardless of where the SQL originated.
"""
from __future__ import annotations

from typing import Any

from pglast.stream import RawStream

from pgrls.fixers import Fix
from pgrls.fixers._idents import quote_ident, quote_qualified
from pgrls.model import Schema
from pgrls.rules._allowlist import parse_policy_id_allowlist
# Reuse the rule's detection so the fixer fixes exactly the
# policies SEC020 reports — single source of truth.
from pgrls.rules.sec020 import _is_open_write_asymmetry


class SEC020Fixer:
    rule_id: str = "SEC020"

    def fix(
        self, schema: Schema, options: dict[str, Any]
    ) -> list[Fix]:
        # Strict allowlist parsing (the same parser SEC020 uses):
        # a malformed allowlist raises, surfaced by the `fix` CLI.
        skip = parse_policy_id_allowlist("SEC020", options)
        out: list[Fix] = []
        for table in schema.tables:
            for policy in table.policies:
                if not _is_open_write_asymmetry(policy):
                    continue
                policy_id = (
                    f"{table.schema}.{table.name}.{policy.name}"
                )
                if policy_id in skip:
                    continue
                using_sql = RawStream()(policy.using_ast)
                sql = (
                    f"ALTER POLICY {quote_ident(policy.name)} "
                    f"ON {quote_qualified(table.schema, table.name)}\n"
                    f"    WITH CHECK ({using_sql});"
                )
                out.append(
                    Fix(
                        rule_id="SEC020",
                        location=policy_id,
                        sql=sql,
                        description=(
                            f"Replace the constant-true WITH CHECK "
                            f"on policy {policy.name!r} on "
                            f"{table.qualified_name} with its USING "
                            "predicate, so writes are constrained "
                            "the same way reads are."
                        ),
                    )
                )
        return out
