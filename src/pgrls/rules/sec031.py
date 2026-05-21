"""SEC031 — RESTRICTIVE policy whose USING is constant true (no-op floor).

A `RESTRICTIVE` policy is meant to be a *hard floor*: rows are visible
only if they pass **every** restrictive policy (the restrictive
clauses AND-combine) on top of passing at least one permissive
policy. So a restrictive policy is how you add a tenant boundary that
no permissive `OR` branch can widen.

A restrictive policy whose `USING` is the literal `true` adds
`AND true` to that conjunction — which restricts **nothing**:

```sql
CREATE POLICY tenant_floor ON documents
    AS RESTRICTIVE FOR SELECT TO PUBLIC
    USING (true);          -- looks like a floor, enforces nothing
```

The policy looks like a security floor — someone added it intending
to tighten access — but it is inert. Any row a permissive policy
admits sails straight through. The danger is the *false sense of
security*: a reviewer sees a restrictive policy named `tenant_floor`
and assumes the table has a hard boundary it does not have.

SEC031 fires for a **restrictive** policy whose `USING` is constant
`true`. It is the restrictive counterpart of **SEC008**, which flags a
**permissive** `USING (true)` (there the constant-true *admits* every
row — the opposite failure). The two are disjoint by policy kind:
SEC008 handles permissive, SEC031 restrictive, so a given policy trips
at most one. The `WITH CHECK` side of the constant-true space is
SEC020's (asymmetric write) and SEC028's (open write) territory.

Detection mirrors SEC008: only the literal `true` matches (a real
tautology checker — `1 = 1`, `x OR NOT x` — is out of scope; those
surface as SEC005, no own-column reference). A restrictive policy
with a `WITH CHECK (true)` but a real `USING` is not flagged here —
a restrictive `WITH CHECK (true)` is a dead clause that restricts no
write (SEC006's framing), not a missing read floor.

Severity: warning. The fix is to give the restrictive policy a real
predicate (the tenant / ownership key it was meant to enforce) or to
drop it if it was never needed. Allowlist by qualified policy ID when
a constant-true restrictive policy is deliberate scaffolding.
"""
from __future__ import annotations

from typing import Any

from pgrls.ast_utils import is_literal_true
from pgrls.model import Schema
from pgrls.rules._allowlist import parse_policy_id_allowlist
from pgrls.violations import Severity, Violation


class SEC031:
    id: str = "SEC031"
    severity: Severity = "warning"
    title: str = "Restrictive policy USING clause is constant true"

    def check(
        self, schema: Schema, options: dict[str, Any]
    ) -> list[Violation]:
        allowlist = parse_policy_id_allowlist("SEC031", options)
        out: list[Violation] = []
        for table in schema.tables:
            for policy in table.policies:
                if policy.permissive:
                    continue  # permissive USING (true) is SEC008's
                if policy.using_ast is None:
                    continue
                if not is_literal_true(policy.using_ast):
                    continue
                policy_id = f"{table.schema}.{table.name}.{policy.name}"
                if policy_id in allowlist:
                    continue
                out.append(
                    Violation(
                        rule_id="SEC031",
                        severity=self.severity,
                        title=self.title,
                        message=(
                            f"Restrictive policy {policy.name!r} on "
                            f"{table.qualified_name} has USING (true). "
                            "Restrictive policies AND-combine, so a "
                            "constant-true USING restricts nothing — the "
                            "policy looks like a security floor but "
                            "enforces none. Give it the real predicate it "
                            "was meant to enforce (the tenant / ownership "
                            "key), or drop it if unneeded. Allowlist the "
                            "qualified policy ID in [lint.rules.SEC031] if "
                            "the constant-true restrictive policy is "
                            "intentional scaffolding."
                        ),
                        location=policy_id,
                    )
                )
        return out
