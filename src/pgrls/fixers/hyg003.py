"""HYG003 fixer — emit `DROP POLICY` for a redundant duplicate policy.

HYG003 flags a policy that is an exact duplicate of another policy
on the same table — identical command, role set, permissive /
restrictive kind, and `USING` / `WITH CHECK` predicates. Because
the two are identical, dropping one leaves the table's effective
RLS unchanged: permissive policies are OR-combined (`p OR p` is
`p`), restrictive ones AND-combined (`p AND p` is `p`).

The fixer mirrors HYG003's detection — it groups a table's
policies by the same signature the rule uses (imported from the
rule, single source of truth) — and for each duplicate group
keeps the name-sorted-first policy as the "original", emitting for
each of the rest:

    DROP POLICY <redundant> ON <schema>.<table>;

This is the only `pgrls fix` statement that DROPs an object rather
than adding or altering one. It is safe — the dropped policy has
an exact twin that remains — but, like every fixer, it is dry-run
by default; review the SQL before `--apply`.
"""
from __future__ import annotations

from typing import Any

from pgrls.fixers import Fix
from pgrls.fixers._idents import quote_ident, quote_qualified
from pgrls.model import Policy, Schema
from pgrls.rules._allowlist import parse_policy_id_allowlist
# Reuse the rule's signature so the fixer groups duplicates exactly
# as HYG003 reports them — single source of truth.
from pgrls.rules.hyg003 import _Signature, _signature


class HYG003Fixer:
    rule_id: str = "HYG003"

    def fix(
        self, schema: Schema, options: dict[str, Any]
    ) -> list[Fix]:
        # Strict allowlist parsing (the same parser HYG003 uses):
        # a malformed allowlist raises, surfaced by the `fix` CLI.
        skip = parse_policy_id_allowlist("HYG003", options)
        out: list[Fix] = []
        for table in schema.tables:
            groups: dict[_Signature, list[Policy]] = {}
            for policy in table.policies:
                groups.setdefault(_signature(policy), []).append(policy)
            for group in groups.values():
                if len(group) < 2:
                    continue
                # Keep the name-sorted-first policy; the rest are
                # the redundant duplicates HYG003 flags.
                ordered = sorted(group, key=lambda p: p.name)
                original = ordered[0]
                for dup in ordered[1:]:
                    policy_id = (
                        f"{table.schema}.{table.name}.{dup.name}"
                    )
                    if policy_id in skip:
                        continue
                    out.append(
                        self._fix(table.schema, table.name, dup, original)
                    )
        return out

    @staticmethod
    def _fix(
        schema: str, table: str, dup: Policy, original: Policy
    ) -> Fix:
        qtable = quote_qualified(schema, table)
        return Fix(
            rule_id="HYG003",
            location=f"{schema}.{table}.{dup.name}",
            sql=f"DROP POLICY {quote_ident(dup.name)} ON {qtable};",
            description=(
                f"Drop policy {dup.name!r} on {schema}.{table} — an "
                f"exact duplicate of policy {original.name!r}. The "
                "two are identical, so removing one leaves the "
                "table's RLS behavior unchanged."
            ),
        )
