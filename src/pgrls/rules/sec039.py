"""SEC039 — Permissive write policy grants the anonymous role write access.

Supabase (and any PostgREST deployment) exposes the database through two
built-in roles: ``anon`` for requests carrying no JWT and ``authenticated``
for signed-in users. A permissive policy whose role list includes ``anon``
for a write command (INSERT, UPDATE, DELETE, or ALL) lets an
*unauthenticated* client modify rows — anonymous data tampering, insertion,
or deletion, gated by that policy's clause AND by the table grant —
measured, without `GRANT INSERT` the write is `permission denied`, which
is why the remedy revokes it. ``anon`` *read* (SELECT)
policies are a deliberate public-data pattern and are NOT flagged; only the
write side is. This is the write-side analog of SEC003 for the named
``anon`` role, which SEC003's PUBLIC-pseudo-role check does not catch (the
Supabase ``anon`` role is a real role, not the ``PUBLIC`` pseudo-role).

Configure the anonymous-role set with ``[lint.rules.SEC039].anon_roles``
(default ``["anon"]``) for deployments that rename or add unauthenticated
roles. Remediate by restricting the policy ``TO authenticated`` (or a
privileged role) and revoking the role's table-level write grant.
"""
from __future__ import annotations

from typing import Any

from pgrls.model import Schema, policy_id
from pgrls.rules._allowlist import parse_policy_id_allowlist
from pgrls.violations import Severity, Violation

# DELETE is included (unlike SEC006's WITH-CHECK set): an anonymous client
# deleting rows is as much a write as an insert/update. SELECT is excluded —
# anonymous public-read is a legitimate, common pattern.
_WRITE_COMMANDS = {"ALL", "INSERT", "UPDATE", "DELETE"}
_DEFAULT_ANON_ROLES = ("anon",)


def _parse_allowlist(options: dict[str, Any]) -> set[str]:
    return parse_policy_id_allowlist('SEC039', options)


def _parse_anon_roles(options: dict[str, Any]) -> set[str]:
    raw = options.get("anon_roles")
    if raw is None:
        return set(_DEFAULT_ANON_ROLES)
    if not isinstance(raw, list) or not all(isinstance(s, str) for s in raw):
        raise TypeError(
            "[lint.rules.SEC039].anon_roles must be a list of role-name "
            "strings (e.g. ['anon'])."
        )
    return set(raw)


class SEC039:
    id: str = "SEC039"
    severity: Severity = "error"
    title: str = "Permissive write policy grants access to the anonymous role"

    def check(
        self, schema: Schema, options: dict[str, Any]
    ) -> list[Violation]:
        allowlist = _parse_allowlist(options)
        anon_roles = _parse_anon_roles(options)
        out: list[Violation] = []
        for table in schema.tables:
            for policy in table.policies:
                if not policy.permissive:
                    continue
                if policy.command not in _WRITE_COMMANDS:
                    continue
                granted = sorted(anon_roles.intersection(policy.roles))
                if not granted:
                    continue
                pid = policy_id(table, policy)
                if pid in allowlist:
                    continue
                role = granted[0]
                verb = "modify" if policy.command == "ALL" else policy.command.lower()
                out.append(
                    Violation(
                        rule_id="SEC039",
                        severity="error",
                        title=self.title,
                        message=(
                            f"Permissive {policy.command} policy "
                            f"{policy.name!r} on {table.qualified_name} lets "
                            f"the unauthenticated {role!r} role {verb} rows, "
                            "gated only by this policy's clause. Restrict it "
                            "TO authenticated (or a privileged role) and "
                            f"revoke {role}'s write grant on the table."
                        ),
                        location=pid,
                    )
                )
        return out
