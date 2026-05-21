"""SEC028 — write-side policy whose WITH CHECK is constant true.

A **permissive** policy that governs writes (`FOR INSERT`,
`FOR UPDATE`, or `FOR ALL`) with a `WITH CHECK` clause of literal
`true` accepts every write the command covers: any row the caller
submits passes the check. The `TO` clause gates *who* may write,
never *what* they may write, so

    CREATE POLICY ins ON documents
        FOR INSERT TO authenticated
        WITH CHECK (true);

lets any authenticated caller insert a row stamped with any tenant
id, any owner, any value — the write side is wide open.

This is the open-write footgun the existing rules miss:

* **SEC006** fires when `WITH CHECK` is *absent* on a write policy;
  here it is present (and wide open).
* **SEC008** flags a constant-true `USING`; a `FOR INSERT` policy
  has no `USING` at all, and SEC008 says nothing about the write
  side regardless.
* **SEC020** flags the *asymmetry* — `WITH CHECK (true)` alongside a
  real, restrictive `USING` ("reads scoped, writes open"). SEC028
  covers the complement: there is no restrictive `USING` to
  contrast with (it is absent, as on `FOR INSERT`, or itself
  constant-true), so the policy is open on the write side outright.

SEC028 fires when a permissive policy whose command is `INSERT`,
`UPDATE`, or `ALL` has a `WITH CHECK` that is the literal `true`,
**and** its `USING` is absent or itself constant-true (so SEC020's
asymmetry case is explicitly ceded to SEC020).

**Restrictive policies are out of scope.** A restrictive
`WITH CHECK (true)` imposes no constraint, but restrictive policies
AND-combine, so on its own it opens nothing — it is a dead clause
(SEC006's restrictive framing), not an open-write hole.

The fix is to replace `WITH CHECK (true)` with a predicate that
validates the written row — typically the same tenant / ownership
key the read side uses, e.g. `WITH CHECK (tenant_id =
current_setting('app.tenant_id')::int)`. Allowlist by qualified
policy ID when an open write side is the design: an append-only
audit or event table any client may write to but only an admin
policy reads.

Scope (intentional):

* **Literal `true` only.** Detection matches the literal boolean
  `true`, exactly as SEC008 / SEC020 do — `1 = 1` and other
  semantic tautologies are out of scope.
* **Permissive only.** See above; restrictive WITH-CHECK-true is a
  dead clause, not an exposure.

Severity: warning. No auto-fix — the correct write predicate is the
application's tenant / ownership key, which pgrls cannot infer.
"""
from __future__ import annotations

from typing import Any

from pgrls.ast_utils import is_literal_true
from pgrls.model import Policy, Schema
from pgrls.rules._allowlist import parse_policy_id_allowlist
from pgrls.violations import Severity, Violation

_WRITE_COMMANDS: frozenset[str] = frozenset({"INSERT", "UPDATE", "ALL"})


def _is_open_write_check(policy: Policy) -> bool:
    """True if `policy` is a permissive write policy whose WITH
    CHECK is constant-true with no restrictive USING to contrast.

    Cedes the "restrictive USING + open WITH CHECK" asymmetry to
    SEC020: if USING is a real predicate, this is SEC020's finding,
    not SEC028's.
    """
    if not policy.permissive:
        return False
    if policy.command not in _WRITE_COMMANDS:
        return False
    if policy.with_check_ast is None or not is_literal_true(
        policy.with_check_ast
    ):
        return False
    # USING absent (FOR INSERT) or itself constant-true → no read
    # restriction to contrast, so SEC020 does not own this case.
    if policy.using_ast is not None and not is_literal_true(
        policy.using_ast
    ):
        return False
    return True


class SEC028:
    id: str = "SEC028"
    severity: Severity = "warning"
    title: str = "Write-side policy WITH CHECK is constant true (open write)"

    def check(
        self, schema: Schema, options: dict[str, Any]
    ) -> list[Violation]:
        allowlist = parse_policy_id_allowlist("SEC028", options)
        out: list[Violation] = []
        for table in schema.tables:
            for policy in table.policies:
                if not _is_open_write_check(policy):
                    continue
                policy_id = f"{table.schema}.{table.name}.{policy.name}"
                if policy_id in allowlist:
                    continue
                out.append(
                    Violation(
                        rule_id="SEC028",
                        severity=self.severity,
                        title=self.title,
                        message=(
                            f"Policy {policy.name!r} on "
                            f"{table.qualified_name} covers "
                            f"{policy.command} with WITH CHECK (true), so "
                            "it accepts every write the command allows — "
                            "any caller the policy applies to can write a "
                            "row with any tenant id, owner, or value. The "
                            "TO clause limits who may write, not what. "
                            "Replace WITH CHECK (true) with a predicate "
                            "that validates the written row (e.g. the "
                            "tenant/ownership key), or allowlist the "
                            "policy in [lint.rules.SEC028] if an open "
                            "write side is intentional (an append-only "
                            "audit or event table)."
                        ),
                        location=policy_id,
                    )
                )
        return out
