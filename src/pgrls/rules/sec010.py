"""SEC010 — Policy USING clause is constant false.

`USING (false)` denies every row from the policy. As the only policy
on a table it produces deny-all (the same effect as SEC009 — RLS
enabled, no policies — just achieved through a more misleading
mechanism). As one of several policies it's a no-op for permissive
combinations and forces deny-all for restrictive ones.

Either way, it's the wrong primitive: the right way to deny access
is `REVOKE ALL ON TABLE x FROM role` at the GRANT layer. Writing the
denial as a policy makes the table look "RLS protected" when it's
actually just disabled.

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

from pglast.ast import A_Const, Boolean

from pgrls.model import Schema
from pgrls.violations import Violation


def _parse_allowlist(options: dict[str, Any]) -> set[str]:
    raw = options.get("allowlist", [])
    if not isinstance(raw, list) or not all(isinstance(s, str) for s in raw):
        raise TypeError(
            "[lint.rules.SEC010].allowlist must be a list of policy IDs "
            "of the form 'schema.table.policy_name'"
        )
    return set(raw)


def _is_literal_false(node: Any) -> bool:
    return (
        isinstance(node, A_Const)
        and isinstance(node.val, Boolean)
        and node.val.boolval is False
    )


class SEC010:
    id = "SEC010"
    severity = "warning"
    title = "Policy USING clause is constant false"

    def check(
        self, schema: Schema, options: dict[str, Any]
    ) -> list[Violation]:
        allowlist = _parse_allowlist(options)
        out: list[Violation] = []
        for table in schema.tables:
            for policy in table.policies:
                if policy.using_ast is None:
                    continue
                if not _is_literal_false(policy.using_ast):
                    continue
                policy_id = (
                    f"{table.schema}.{table.name}.{policy.name}"
                )
                if policy_id in allowlist:
                    continue
                out.append(
                    Violation(
                        rule_id="SEC010",
                        severity="warning",
                        title=self.title,
                        message=(
                            f"Policy {policy.name!r} on "
                            f"{table.qualified_name} has USING (false), "
                            "which denies every row. Express denial at "
                            "the GRANT layer instead — `REVOKE ALL ON "
                            f"TABLE {table.qualified_name} FROM "
                            "<role>` is clearer than a deny-all policy "
                            "that makes the table look RLS-protected "
                            "when it's actually just disabled."
                        ),
                        location=policy_id,
                    )
                )
        return out
