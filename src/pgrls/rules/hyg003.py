"""HYG003 — Policy duplicates another policy on the same table.

Two policies on one table that are identical in everything but
their name — same command, same role list, same permissive /
restrictive kind, same `USING` and `WITH CHECK` predicates — are
redundant. A permissive duplicate adds nothing: permissive
policies are OR-combined, and `p OR p` is `p`. A restrictive
duplicate adds nothing either: restrictive policies are
AND-combined, and `p AND p` is `p`. The extra policy is dead
weight — almost always a copy-paste leftover (`policy_v1` /
`policy_v2`) or a migration that re-created a policy it never
dropped.

Beyond the clutter, a duplicate is a latent maintenance hazard:
an operator who edits "the" policy may edit only one of the pair
and leave the other stale, so the table's effective rule silently
stops matching the policy the operator believes is authoritative.

Detection is an EXACT match. HYG003 groups a table's policies by
`(command, role set, permissive flag, USING text, WITH CHECK
text)`. The `USING` / `WITH CHECK` strings are Postgres's own
canonical `pg_get_expr` rendering, so two genuinely-identical
predicates compare equal. Semantic equivalence is NOT in scope:
`USING (a = 1)` and `USING (1 = a)` are different texts and are
not flagged — a real equivalence checker is significant
infrastructure for marginal value. The role list is compared as a
set, so `TO a, b` and `TO b, a` count as the same.

For each group of duplicates HYG003 keeps the name-sorted-first
policy as the "original" and flags the rest. Severity: info — a
duplicate is redundant, not unsafe. Allowlist the redundant
policy's qualified ID if keeping both is genuinely intended.
"""
from __future__ import annotations

from typing import Any

from pgrls.model import Policy, Schema, Table, policy_id
from pgrls.rules._allowlist import parse_policy_id_allowlist
from pgrls.violations import Severity, Violation

# The policy identity HYG003 compares on — everything that defines a
# policy except its name. Two policies with the same signature are
# exact duplicates of each other.
_Signature = tuple[str, frozenset[str], bool, str | None, str | None]


def _signature(policy: Policy) -> _Signature:
    return (
        policy.command,
        frozenset(policy.roles),
        policy.permissive,
        policy.using_sql,
        policy.with_check_sql,
    )


class HYG003:
    id: str = "HYG003"
    severity: Severity = "info"
    title: str = "Policy duplicates another policy on the same table"

    def check(
        self, schema: Schema, options: dict[str, Any]
    ) -> list[Violation]:
        allowlist = parse_policy_id_allowlist("HYG003", options)
        out: list[Violation] = []
        for table in schema.tables:
            # Group the table's policies by their full definition
            # minus the name; any group of 2+ is a duplicate set.
            groups: dict[_Signature, list[Policy]] = {}
            for policy in table.policies:
                groups.setdefault(_signature(policy), []).append(policy)
            for group in groups.values():
                if len(group) < 2:
                    continue
                # Keep the name-sorted-first policy as the canonical
                # "original"; flag the rest as redundant duplicates.
                # Sorting by name makes the choice deterministic so
                # the same Schema always produces the same output.
                ordered = sorted(group, key=lambda p: p.name)
                original = ordered[0]
                for dup in ordered[1:]:
                    pid = policy_id(table, dup)
                    if pid in allowlist:
                        continue
                    out.append(
                        self._violation(table, dup, original, pid)
                    )
        return out

    def _violation(
        self,
        table: Table,
        dup: Policy,
        original: Policy,
        pid: str,
    ) -> Violation:
        return Violation(
            rule_id=self.id,
            severity=self.severity,
            title=self.title,
            message=(
                f"Policy {dup.name!r} on {table.qualified_name} is "
                f"an exact duplicate of policy {original.name!r} on "
                "the same table — same command, role list, and "
                "USING / WITH CHECK predicates. The duplicate is "
                "redundant: permissive policies are OR-combined and "
                "restrictive ones AND-combined, so a second "
                "identical policy changes nothing. It is almost "
                "always a copy-paste or migration leftover — drop "
                "one of the pair. If keeping both is intended, "
                f"allowlist {pid!r} in [lint.rules.HYG003]."
            ),
            location=pid,
        )
