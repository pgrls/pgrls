"""SEC023 — policy applies to a role that bypasses RLS.

A `CREATE POLICY` whose `TO` clause names a specific role expresses
an intent: *this* policy governs *that* role. SEC023 fires when one
of those named roles carries the `BYPASSRLS` attribute — because a
`BYPASSRLS` role skips **every** row-level security policy on every
table. The `TO` clause is inert for it:

    CREATE ROLE etl_worker BYPASSRLS;

    CREATE POLICY tenant_scope ON documents
        FOR SELECT TO etl_worker
        USING (tenant_id = current_setting('app.tenant_id'));

`etl_worker` reads every row of `documents` regardless of
`tenant_scope`'s `USING` predicate. The policy looks like it
constrains `etl_worker` to one tenant; it does not constrain it at
all.

The danger is a **false sense of security**. The author named the
role deliberately — they were thinking about that role's access —
and wrote a predicate to scope it. Nothing in the policy reveals
that the role ignores the predicate; the bypass lives in a role
attribute SEC023's siblings (SEC001–SEC015) never inspect. The
policy passes review, and the role silently sees every tenant's
rows. The other reading is milder — the author *wanted* the role
unconstrained and the `TO` clause is simply redundant noise — but
pgrls cannot tell the two apart, and both are worth surfacing.

Detection is a cross-reference, not an AST walk: SEC023 intersects
each policy's `roles` (the `TO` list) with the set of roles the
schema reports as carrying `BYPASSRLS`. No predicate analysis is
involved — the policy's `USING` / `WITH CHECK` is irrelevant, since
a `BYPASSRLS` role never evaluates it.

What SEC023 flags — and what it deliberately does not:

* **Flagged:** a policy that names a non-superuser `BYPASSRLS` role
  in its `TO` clause. Whether the policy is permissive or
  restrictive, and whatever its predicate, the clause does nothing
  for that role.
* **Not flagged — `TO PUBLIC`.** `PUBLIC` is not a role that
  bypasses RLS; it is the pseudo-role meaning "every role", and RLS
  still applies to every non-bypassing role under it. A `BYPASSRLS`
  role is of course *covered* by a `TO PUBLIC` policy and bypasses
  it like any other — but that is SEC016's finding (the role
  bypasses everything), not a property of this policy. Firing on
  every `TO PUBLIC` policy in any schema that happens to contain a
  `BYPASSRLS` role would be noise; SEC023 fires only when a policy
  *names* the bypassing role, the deliberate and surprising case.
* **Not flagged — superuser roles.** A superuser bypasses RLS via
  `rolsuper`, independently of `BYPASSRLS`. SEC023 skips superusers
  exactly as SEC016 does: a policy targeting a superuser restates
  "this role is a superuser", a far larger and separate finding.

`BYPASSRLS` itself is not always wrong — a backup, logical-
replication, or ETL role legitimately needs it — which is why
SEC016 (the role-level finding) is `warning` and allowlistable.
SEC023 inherits that judgement: it is also `warning`, and a policy
that names a bypassing role on purpose (defensive documentation, a
role that is *meant* to see everything) is allowlisted by qualified
policy ID (`schema.table.policy_name`).

Severity: warning. No auto-fix — the remedy is either to remove
`BYPASSRLS` from the role (`ALTER ROLE <name> NOBYPASSRLS`, if the
policy's constraint is the real intent) or to drop the dead `TO`
clause; pgrls cannot tell which the author wants.

Relationship to SEC016: SEC016 flags the *role* — "this role
carries `BYPASSRLS`". SEC023 flags the *policy* — "this policy
tries to govern a role that the attribute exempts". A schema can
trip SEC016 on a role and SEC023 on every policy that names it;
the two findings are complementary, and a reader who has only seen
SEC016 may not realise a specific, predicate-bearing policy is
among the things that role's attribute silently defeats.

Out of scope (intentional):

* **Role membership / `SET ROLE` reachability.** SEC023 flags a
  policy that names a `BYPASSRLS` role directly. It does not walk
  the role-membership graph to flag a policy targeting a role whose
  members can `SET ROLE` to a bypassing role — `BYPASSRLS` is a
  role attribute, not an inheritable privilege, so the named role
  is the precise audit target. Mirrors SEC016's stance.
* **Plain superusers.** A role that bypasses RLS purely through
  `rolsuper`, with no explicit `BYPASSRLS` attribute, is not in the
  schema's reported `BYPASSRLS` set and so is not matched. A policy
  targeting a superuser is a non-finding by the same reasoning
  SEC023 skips superusers that *do* carry `BYPASSRLS`.
"""
from __future__ import annotations

from typing import Any

from pgrls.model import Policy, Schema, Table
from pgrls.rules._allowlist import parse_policy_id_allowlist
from pgrls.violations import Severity, Violation


class SEC023:
    id: str = "SEC023"
    severity: Severity = "warning"
    title: str = "Policy applies to a role that bypasses RLS"

    def check(
        self, schema: Schema, options: dict[str, Any]
    ) -> list[Violation]:
        allowlist = parse_policy_id_allowlist("SEC023", options)
        # Roles that bypass RLS via the BYPASSRLS attribute, minus
        # superusers: a superuser bypasses RLS through `rolsuper`
        # regardless, so SEC016 skips it as a redundant finding and
        # SEC023 mirrors that — a policy targeting a superuser would
        # only restate "this role is a superuser".
        bypassing = {
            role.name
            for role in schema.bypassrls_roles
            if not role.superuser
        }
        if not bypassing:
            return []
        out: list[Violation] = []
        for table in schema.tables:
            for policy in table.policies:
                # `policy.roles` carries the `TO` list; a `TO PUBLIC`
                # policy reports the pseudo-role 'PUBLIC', which is
                # never a real `rolname` and so never intersects the
                # bypassing set. Only a policy that names the role
                # outright is flagged.
                targeted = sorted(
                    name for name in policy.roles if name in bypassing
                )
                if not targeted:
                    continue
                policy_id = f"{table.schema}.{table.name}.{policy.name}"
                if policy_id in allowlist:
                    continue
                out.append(
                    self._violation(table, policy, policy_id, targeted)
                )
        return out

    def _violation(
        self,
        table: Table,
        policy: Policy,
        policy_id: str,
        targeted: list[str],
    ) -> Violation:
        if len(targeted) == 1:
            roles_phrase = f"role {targeted[0]}, which carries"
        else:
            roles_phrase = f"roles {', '.join(targeted)}, which carry"
        return Violation(
            rule_id=self.id,
            severity=self.severity,
            title=self.title,
            message=(
                f"Policy {policy.name!r} on {table.qualified_name} "
                f"applies (via its TO clause) to {roles_phrase} the "
                "BYPASSRLS attribute. A BYPASSRLS role skips every "
                "row-level security policy on every table, so this "
                "policy's predicate is never evaluated for it — the "
                "role reads and writes every row regardless of the "
                "USING / WITH CHECK clause. If the policy was meant "
                "to constrain that role, it does not: the role sees "
                "every tenant's rows. If the role is meant to be "
                "unconstrained, naming it in the TO clause is "
                "redundant. Either remove BYPASSRLS from the role "
                "(`ALTER ROLE <name> NOBYPASSRLS`) so the policy "
                "takes effect, or drop the dead TO reference. See "
                "also SEC016, which flags the role itself. If a "
                "policy that names a bypassing role is intentional, "
                f"allowlist it as {policy_id!r} in [lint.rules.SEC023]."
            ),
            location=policy_id,
        )
