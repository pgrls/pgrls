"""SEC003 — Permissive policy grants access to PUBLIC.

A permissive policy with PUBLIC in its role list applies to every
connection, including unauthenticated ones. This is rarely intentional
in multi-tenant apps: the policy's USING clause carries the whole
boundary for every role, and any flaw exposes data broadly. A
RESTRICTIVE policy on the table can still narrow it — restrictives
AND-combine, for the roles in their own TO list — so PUBLIC here is not
automatically the last line of defense, just the widest one.
"""
from __future__ import annotations

from typing import Any

from pgrls.model import Schema, policy_id
from pgrls.rules._allowlist import parse_policy_id_allowlist
from pgrls.violations import Severity, Violation


def _parse_allowlist(options: dict[str, Any]) -> set[str]:
    return parse_policy_id_allowlist('SEC003', options)


class SEC003:
    id: str = "SEC003"
    severity: Severity = "error"
    title: str = "Permissive policy grants access to PUBLIC"

    def check(
        self, schema: Schema, options: dict[str, Any]
    ) -> list[Violation]:
        allowlist = _parse_allowlist(options)
        out: list[Violation] = []
        for table in schema.tables:
            for policy in table.policies:
                if not policy.permissive:
                    continue
                if "PUBLIC" not in policy.roles:
                    continue
                pid = policy_id(table, policy)
                if pid in allowlist:
                    continue
                out.append(
                    Violation(
                        rule_id="SEC003",
                        severity="error",
                        title=self.title,
                        message=(
                            f"Permissive policy {policy.name!r} on "
                            f"{table.qualified_name} grants access to "
                            "PUBLIC, so anonymous connections are "
                            "governed by this policy's own clause — its "
                            "USING for reads, its WITH CHECK for writes "
                            "(a FOR INSERT policy has no USING at all). "
                            "Restrict to a specific role (e.g. "
                            "TO authenticated)."
                        ),
                        location=pid,
                    )
                )
        return out
