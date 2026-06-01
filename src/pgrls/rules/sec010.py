"""SEC010 — Policy clause is constant false.

`USING (false)` denies every row from the policy. As the only policy
on a table it produces deny-all (the same effect as SEC009 — RLS
enabled, no policies — just achieved through a more misleading
mechanism). As one of several policies it's a no-op for permissive
combinations and forces deny-all for restrictive ones.

`WITH CHECK (false)` is the same anti-pattern in the write-side
form: every INSERT/UPDATE through this policy fails. The intent —
"nobody can write this table through this role" — belongs at the
GRANT layer (`REVOKE INSERT, UPDATE ON x FROM role`), not as a
policy that makes the table look RLS-protected when it's really
just blocked.

Either way, it's the wrong primitive: the right way to deny access
is at the GRANT layer. Writing the denial as a policy makes the
table look "RLS protected" when it's actually just disabled.

Detection mirrors SEC008's `USING (true)`: only literal `false`
matches. Semantic equivalents like `NOT true` or `1 = 0` are out of
scope — a real tautology checker is significant infrastructure for
marginal value, and the disguised cases are usually SEC005 findings
anyway (no own-column reference).

Severity: warning. Allowlist by qualified policy ID when you really
do want to express "deny" via policy form (uncommon but legal).
"""
from __future__ import annotations

from typing import Any

from pgrls.ast_utils import is_literal_false
from pgrls.model import Policy, Schema, Table, policy_id
from pgrls.rules._allowlist import parse_policy_id_allowlist
from pgrls.violations import Severity, Violation


def _parse_allowlist(options: dict[str, Any]) -> set[str]:
    return parse_policy_id_allowlist('SEC010', options)


class SEC010:
    id: str = "SEC010"
    severity: Severity = "warning"
    title: str = "Policy clause is constant false"

    def check(
        self, schema: Schema, options: dict[str, Any]
    ) -> list[Violation]:
        allowlist = _parse_allowlist(options)
        out: list[Violation] = []
        for table in schema.tables:
            for policy in table.policies:
                pid = policy_id(table, policy)
                if pid in allowlist:
                    continue
                clause = self._which_clause_is_false(policy)
                if clause is None:
                    continue
                out.append(
                    Violation(
                        rule_id="SEC010",
                        severity="warning",
                        title=self.title,
                        message=self._message(table, policy, clause),
                        location=pid,
                    )
                )
        return out

    @staticmethod
    def _which_clause_is_false(policy: Policy) -> str | None:
        # Symmetric with SEC011: walk both clauses. Prefer USING in
        # the "both clauses are false" case (rare but legal —
        # `USING (false) WITH CHECK (false)` — the USING phrasing
        # is the older / more familiar one and the message is
        # marginally clearer that way).
        if policy.using_ast is not None and is_literal_false(
            policy.using_ast
        ):
            return "USING"
        if policy.with_check_ast is not None and is_literal_false(
            policy.with_check_ast
        ):
            return "WITH CHECK"
        return None

    @staticmethod
    def _message(table: Table, policy: Policy, clause: str) -> str:
        # USING (false) denies reads/visibility; WITH CHECK (false)
        # denies writes. Same remediation (REVOKE at the GRANT
        # layer), different framing of what's broken, so the
        # message branches.
        if clause == "USING":
            denial = "denies every row"
            grant_hint = (
                f"`REVOKE ALL ON TABLE {table.qualified_name} "
                "FROM <role>`"
            )
        else:  # WITH CHECK
            denial = "rejects every write"
            grant_hint = (
                f"`REVOKE INSERT, UPDATE ON TABLE "
                f"{table.qualified_name} FROM <role>`"
            )
        return (
            f"Policy {policy.name!r} on {table.qualified_name} has "
            f"{clause} (false), which {denial}. Express denial at "
            f"the GRANT layer instead — {grant_hint} is clearer "
            "than a deny-all policy that makes the table look "
            "RLS-protected when it's actually just disabled."
        )
