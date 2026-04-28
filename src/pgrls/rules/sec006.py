"""SEC006 — INSERT/UPDATE/ALL policy missing WITH CHECK.

USING filters reads. WITH CHECK validates writes against the policy
predicate. A write-side policy without WITH CHECK lets clients write rows
that the same policy's USING would forbid them from reading.
"""
from __future__ import annotations

from typing import Any

from pgrls.model import Schema
from pgrls.violations import Violation


_WRITE_COMMANDS = {"INSERT", "UPDATE", "ALL"}


def _parse_allowlist(options: dict[str, Any]) -> set[str]:
    raw = options.get("allowlist", [])
    if not isinstance(raw, list) or not all(isinstance(s, str) for s in raw):
        raise TypeError(
            "[lint.rules.SEC006].allowlist must be a list of policy IDs "
            "of the form 'schema.table.policy_name'"
        )
    return set(raw)


class SEC006:
    id = "SEC006"
    severity = "error"
    title = "Write-side policy missing WITH CHECK"

    def check(
        self, schema: Schema, options: dict[str, Any]
    ) -> list[Violation]:
        allowlist = _parse_allowlist(options)
        out: list[Violation] = []
        for table in schema.tables:
            for policy in table.policies:
                if policy.command not in _WRITE_COMMANDS:
                    continue
                # Truthy check (not just `is not None`) so a hand-
                # built or snapshot-loaded Policy with
                # `with_check_sql=""` doesn't silently slip past.
                # Postgres's `pg_get_expr` never returns "" for a
                # real WITH CHECK clause, but defensive check costs
                # nothing.
                if policy.with_check_sql:
                    continue
                policy_id = (
                    f"{table.schema}.{table.name}.{policy.name}"
                )
                if policy_id in allowlist:
                    continue
                out.append(
                    Violation(
                        rule_id="SEC006",
                        severity="error",
                        title=self.title,
                        message=(
                            f"Policy {policy.name!r} on "
                            f"{table.qualified_name} covers "
                            f"{policy.command} but has no WITH CHECK "
                            "clause. Without one, writes that violate "
                            "the policy's intent are accepted. Add "
                            "WITH CHECK matching USING (or a write-"
                            "specific predicate)."
                        ),
                        location=policy_id,
                    )
                )
        return out
