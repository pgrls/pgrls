"""SEC006 — INSERT/UPDATE/ALL policy missing WITH CHECK.

USING filters reads. WITH CHECK validates writes against the policy
predicate. A missing WITH CHECK is only a problem when Postgres has
nothing to reuse as one:

  * For an UPDATE/ALL policy with a real USING, Postgres reuses the
    USING expression as the implicit WITH CHECK — for BOTH permissive
    and restrictive policies — so the written row must still satisfy it.
    That shape is closed and is intentionally NOT flagged (see
    `_write_is_open`). Flagging it was a false positive whose restrictive
    "dead policy / remove it" remediation would have deleted a real
    write-side constraint.

  * The genuinely open shapes are INSERT (which carries no USING) and an
    UPDATE/ALL whose USING is absent or constant-true (nothing meaningful
    to reuse). The diagnosis then branches on `permissive`:

      - Permissive + open: a concrete security hole — the policy admits
        writes that violate the read-side predicate.
      - Restrictive + open: the un-reusable missing WITH CHECK defaults
        to `true`, AND-combined into the restrictive group, so the policy
        imposes no constraint on new rows — a dead policy. Not a hole on
        its own (other restrictives still apply) but a bug: the author
        meant to forbid something and forbids nothing.

Both flagged shapes need the same fix — add a WITH CHECK clause — but the
message branches on `permissive` so the diagnosis matches the problem.
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


def _write_is_open(policy: Policy) -> bool:
    """Does a write policy with no WITH CHECK actually leave writes
    unconstrained?

    Applies to permissive AND restrictive policies alike: Postgres reuses a
    policy's USING expression as the implicit WITH CHECK whenever WITH CHECK
    is omitted on an UPDATE/ALL policy, regardless of permissivity. So a
    ``FOR UPDATE USING (tenant_id = …)`` with no WITH CHECK still forces the
    *written* row to satisfy ``tenant_id = …`` — the write side is closed,
    not open. The only genuinely open shapes are:

      * UPDATE/ALL whose USING is constant-true — the reused predicate
        constrains nothing, so every written row is accepted.

    The other shape is the opposite of open, and worth saying plainly: a
    permissive policy with NO usable predicate grants no write AT ALL. A
    missing WITH CHECK does not default to ``true`` — measured on PG16, a
    clause-less ``FOR INSERT`` policy rejected the insert with "new row
    violates row-level security policy", and a clause-less ``FOR UPDATE``
    reported ``UPDATE 0``. The finding is still worth making (the policy
    is dead, not protective), but the diagnosis is "grants nothing", not
    "accepts everything".

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
                # An UPDATE/ALL with a non-trivial USING is not an open
                # write: Postgres reuses the USING expression as the
                # implicit WITH CHECK when WITH CHECK is omitted, so the
                # written row must still satisfy the USING predicate. This
                # holds for permissive AND restrictive policies — so a
                # restrictive `FOR UPDATE USING (tenant = …)` is NOT a dead
                # policy (flagging it was a false positive whose "remove the
                # policy" advice would delete a real write-side constraint).
                # Only INSERT (no USING to reuse) or an UPDATE/ALL whose
                # USING is absent/constant-true leaves writes unconstrained.
                if not _write_is_open(policy):
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
                "clause. If its USING is constant-true, every "
                "written row is accepted; with no usable predicate "
                "at all the policy grants no write whatsoever (a "
                "missing WITH CHECK does NOT default to true — an "
                "INSERT raises, an UPDATE reports 0 rows). Either "
                "way it is not doing what it looks like it is "
                "doing: add WITH CHECK matching USING (or a "
                "write-specific predicate)."
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
