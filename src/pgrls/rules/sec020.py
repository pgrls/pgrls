"""SEC020 — policy WITH CHECK clause is constant true but USING is not.

A row-level security policy that governs writes — a `FOR ALL` or
`FOR UPDATE` policy — carries two predicates:

* `USING` filters the rows the caller may *see* (and, for UPDATE, the
  existing rows it may target).
* `WITH CHECK` validates the rows the caller may *write* — the new row
  an INSERT produces, or the post-image of an UPDATE.

When `WITH CHECK` is omitted Postgres reuses `USING` for it, so the
two sides stay in lock-step by default. The footgun appears when a
policy sets an explicit `WITH CHECK (true)` alongside a restrictive
`USING`:

    CREATE POLICY p ON documents
        FOR ALL TO app
        USING (tenant_id = current_setting('app.tenant_id')::int)
        WITH CHECK (true);

The caller can only *read* its own tenant's rows, but it may *write*
any row at all — it can INSERT a row stamped with another tenant's
id, or UPDATE one of its own rows to reassign it. The read-side
isolation looks airtight while the write side is wide open.

SEC020 fires when a policy has BOTH clauses present, its `USING`
clause is a real predicate, and its `WITH CHECK` clause is the
literal `true`. The fix is almost always to mirror the `USING`
predicate into `WITH CHECK` — or simply delete the `WITH CHECK`
clause, which makes Postgres reuse `USING` automatically.

Severity: warning. Allowlist by qualified policy ID
(`schema.table.policy_name`) — allowlist a policy when an
intentionally open write side is the design (e.g. an append-only
audit table any tenant may write but only an admin policy reads).

Scope (intentional):

* **Literal `true` only.** Detection matches the literal boolean
  `true`, exactly as SEC008 ("USING clause is constant true") does.
  Semantic tautologies — `1 = 1`, `'x' = 'x'`, `col IS NULL OR col
  IS NOT NULL` — are out of scope: a real tautology checker is
  significant infrastructure for marginal real-world value, and
  `WITH CHECK (true)` is the form that actually occurs.
* **The asymmetry, not the absence.** A policy with no `WITH CHECK`
  at all is SEC006's concern (write-side policy missing WITH CHECK);
  SEC020 fires only when `WITH CHECK` is present and constant-true.
  A `USING` that is itself constant-true is SEC008's concern — SEC020
  needs a *real* USING predicate for the asymmetry to exist.
* **No predicate comparison.** SEC020 does not try to prove a
  non-trivial `WITH CHECK` is weaker than `USING`; it flags only the
  unambiguous constant-true case. A subtler gap — `WITH CHECK`
  dropping a conjunct that `USING` has — is left to the operator.
"""
from __future__ import annotations

from typing import Any

from pgrls.ast_utils import is_literal_true
from pgrls.model import Policy, Schema, Table, policy_id
from pgrls.rules._allowlist import parse_policy_id_allowlist
from pgrls.violations import Severity, Violation


def _is_open_write_asymmetry(policy: Policy) -> bool:
    """True if `policy` is the asymmetry SEC020 flags.

    Both clauses must be present — a policy with no USING (a
    `FOR INSERT` policy) has no read side to be more restrictive
    than, and a policy with no explicit WITH CHECK reuses USING,
    so the two sides cannot diverge. The footgun is the
    *asymmetry*: USING must be a real predicate (a USING that is
    itself constant-true is a fully-open policy — SEC008's
    concern), while WITH CHECK is the literal `true`.

    Shared with the SEC020 fixer so the rule and the fix agree on
    a single definition of the finding.
    """
    if policy.using_ast is None or policy.with_check_ast is None:
        return False
    if is_literal_true(policy.using_ast):
        return False
    return is_literal_true(policy.with_check_ast)


class SEC020:
    id: str = "SEC020"
    severity: Severity = "warning"
    title: str = "Policy WITH CHECK is constant true but USING is not"

    def check(
        self, schema: Schema, options: dict[str, Any]
    ) -> list[Violation]:
        allowlist = parse_policy_id_allowlist("SEC020", options)
        out: list[Violation] = []
        for table in schema.tables:
            for policy in table.policies:
                if not _is_open_write_asymmetry(policy):
                    continue
                pid = policy_id(table, policy)
                if pid in allowlist:
                    continue
                out.append(self._violation(table, policy, pid))
        return out

    def _violation(
        self, table: Table, policy: Policy, pid: str
    ) -> Violation:
        return Violation(
            rule_id=self.id,
            severity=self.severity,
            title=self.title,
            message=(
                f"Policy {policy.name!r} on {table.qualified_name} "
                "pairs a restrictive USING clause with WITH CHECK "
                "(true). The USING clause limits which rows the "
                "caller can read, but WITH CHECK (true) accepts "
                "every row it writes — so the caller can write rows "
                "into another tenant's space (rows its USING clause "
                "would never surface) even though it can only read "
                "its own. Mirror the USING predicate in WITH CHECK "
                "(ALTER POLICY has no clause-removal syntax, so "
                "'dropping' the check means DROP POLICY + CREATE "
                "POLICY). If an intentionally open write side "
                "is the design, allowlist this policy as "
                f"{pid!r} in [lint.rules.SEC020]."
            ),
            location=pid,
        )
