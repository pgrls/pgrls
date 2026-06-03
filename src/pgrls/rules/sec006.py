"""SEC006 — INSERT/UPDATE/ALL policy missing WITH CHECK.

USING filters reads. WITH CHECK validates writes against the policy
predicate. The failure mode and the remediation framing depend on
whether the policy is permissive or restrictive:

  * Permissive write policy with no WITH CHECK *and nothing for
    Postgres to reuse as one*: lets clients write rows the policy
    would otherwise forbid. Concrete security hole — but only for
    INSERT (which carries no USING) or an UPDATE/ALL whose USING is
    absent or constant-true. For an UPDATE/ALL with a real USING,
    Postgres reuses the USING expression as the implicit WITH CHECK,
    so the written row must still satisfy it; that shape is closed
    and is intentionally NOT flagged (see `_permissive_write_is_open`).

  * Restrictive write policy with no WITH CHECK: Postgres defaults
    the missing WITH CHECK to `true`, AND-combined into the
    restrictive group. The policy imposes no constraint on the
    new row — it is a dead policy. Not a security hole on its
    own (the table's other restrictives still apply), but a bug:
    the author wrote the policy intending to forbid something and
    is forbidding nothing.

Both cases need the same fix — add a WITH CHECK clause — but the
message branches on `permissive` so the diagnosis matches the
actual problem.
"""
from __future__ import annotations

from typing import Any

from pgrls.ast_utils import is_literal_true
from pgrls.model import Policy, Schema, Table, policy_id
from pgrls.rules._allowlist import parse_policy_id_allowlist
from pgrls.violations import Severity, Violation


_WRITE_COMMANDS = {"INSERT", "UPDATE", "ALL"}


def _parse_allowlist(options: dict[str, Any]) -> set[str]:
    return parse_policy_id_allowlist('SEC006', options)


def _permissive_write_is_open(policy: Policy) -> bool:
    """Does a permissive write policy with no WITH CHECK actually accept
    arbitrary writes?

    Postgres reuses a policy's USING expression as the implicit WITH CHECK
    whenever WITH CHECK is omitted on an UPDATE/ALL policy. So a permissive
    ``FOR UPDATE USING (tenant_id = …)`` with no WITH CHECK still forces the
    *written* row to satisfy ``tenant_id = …`` — the write side is closed,
    not open. The only genuinely open shapes are:

      * INSERT — carries no USING for Postgres to reuse, so a missing
        WITH CHECK admits every inserted row; and
      * UPDATE/ALL whose USING is absent or constant-true — there is no
        meaningful predicate to reuse, so writes are unconstrained.

    Returns True only for those open shapes; the common multi-tenant
    ``FOR UPDATE/ALL USING (tenant = …)`` shape returns False (no finding).
    """
    if policy.command == "INSERT":
        return True
    if not policy.using_sql:
        return True
    return policy.using_ast is not None and is_literal_true(policy.using_ast)


class SEC006:
    id: str = "SEC006"
    severity: Severity = "error"
    title: str = "Write-side policy missing WITH CHECK"

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
                # Permissive UPDATE/ALL with a non-trivial USING is not an
                # open write: Postgres reuses the USING expression as the
                # implicit WITH CHECK when WITH CHECK is omitted, so the
                # written row must still satisfy the USING predicate. Only
                # INSERT (no USING to reuse) or an UPDATE/ALL whose USING is
                # absent/constant-true leaves writes genuinely unconstrained.
                # The restrictive path is unaffected: a missing WITH CHECK on
                # a restrictive policy still defaults to `true` (dead policy).
                if policy.permissive and not _permissive_write_is_open(policy):
                    continue
                pid = policy_id(table, policy)
                if pid in allowlist:
                    continue
                out.append(
                    Violation(
                        rule_id="SEC006",
                        severity="error",
                        title=self.title,
                        message=self._message(table, policy),
                        location=pid,
                    )
                )
        return out

    @staticmethod
    def _message(table: Table, policy: Policy) -> str:
        if policy.permissive:
            return (
                f"Policy {policy.name!r} on "
                f"{table.qualified_name} covers "
                f"{policy.command} but has no WITH CHECK "
                "clause. Without one, writes that violate "
                "the policy's intent are accepted. Add "
                "WITH CHECK matching USING (or a write-"
                "specific predicate)."
            )
        # Restrictive: Postgres defaults missing WITH CHECK to
        # `true`, so the policy is a no-op for the write-side
        # combination. Frame the diagnosis as "dead policy" so
        # the operator looks for the missing constraint rather
        # than misinterpreting it as a security hole.
        return (
            f"Restrictive policy {policy.name!r} on "
            f"{table.qualified_name} covers {policy.command} but "
            "has no WITH CHECK clause. Postgres defaults the "
            "missing clause to `true`, so the policy imposes no "
            "constraint on new rows — it is a dead policy. Add "
            "WITH CHECK expressing the predicate the policy is "
            "meant to enforce, or remove the policy."
        )
