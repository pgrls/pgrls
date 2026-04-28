"""SEC003 — Permissive policy grants access to PUBLIC.

A permissive policy with PUBLIC in its role list applies to every
connection, including unauthenticated ones. This is rarely intentional
in multi-tenant apps; the policy's USING clause becomes the only line of
defense and any flaw exposes data broadly.
"""
from __future__ import annotations

from typing import Any

from pgrls.model import Schema
from pgrls.violations import Severity, Violation


def _parse_allowlist(options: dict[str, Any]) -> set[str]:
    raw = options.get("allowlist", [])
    if not isinstance(raw, list) or not all(isinstance(s, str) for s in raw):
        raise TypeError(
            "[lint.rules.SEC003].allowlist must be a list of policy IDs "
            "of the form 'schema.table.policy_name'"
        )
    return set(raw)


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
                policy_id = (
                    f"{table.schema}.{table.name}.{policy.name}"
                )
                if policy_id in allowlist:
                    continue
                out.append(
                    Violation(
                        rule_id="SEC003",
                        severity="error",
                        title=self.title,
                        message=(
                            f"Permissive policy {policy.name!r} on "
                            f"{table.qualified_name} grants access to "
                            "PUBLIC. Anonymous connections will be "
                            "subject to this policy's USING clause. "
                            "Restrict to a specific role (e.g. "
                            "TO authenticated)."
                        ),
                        location=policy_id,
                    )
                )
        return out
