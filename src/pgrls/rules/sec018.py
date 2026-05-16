"""SEC018 — policy expression uses current_user / session_user.

A policy whose `USING` or `WITH CHECK` expression keys off
`current_user` (or its aliases `current_role` and `user`) or
`session_user` is asserting that *the Postgres role the session is
running as* identifies the tenant. That only isolates tenants when
every tenant connects as — or `SET ROLE`s to — a **distinct**
Postgres role.

Application architectures almost never do that. A connection pool
authenticates as one shared database role and serves every tenant's
requests over it; `current_user` is then identical for tenant A and
tenant B, and a policy like

    CREATE POLICY p ON documents
        USING (owner_role = current_user);

provides **no** isolation — every pooled request sees every row.
The policy *looks* like access control and passes every other
pgrls check, but the discriminator is a constant.

`session_user` (the original login role, unchanged by `SET ROLE`)
has the same problem, and is strictly worse for the `SET ROLE`
pattern: even a deployment that does `SET ROLE tenant_x` per request
leaves `session_user` pinned to the pool's login role.

SEC018 flags every policy whose `USING` or `WITH CHECK` expression
references any of `current_user`, `current_role`, `user`, or
`session_user`. Detection is structural — the rule walks the parsed
policy AST (`find_func_calls` matches the `SQLValueFunction` nodes
Postgres emits for these grammar-special identifiers), including
references nested inside sub-selects.

The correct discriminator for pooled application code is a
*session-scoped* value the application sets per request: a GUC read
with `current_setting('app.tenant_id')`, or a JWT claim. Those
change per request over a shared connection; the role identity does
not.

`current_user`-based policies are **not** universally wrong. The
"role-per-tenant" RLS pattern — one Postgres role per tenant, the
application `SET ROLE`s to the tenant's role per request — is a
legitimate, documented design, and there `current_user` is exactly
the right discriminator. pgrls cannot tell which deployment model
is in use, so SEC018 is severity `warning` and allowlistable: a
role-per-tenant project allowlists the affected policies (or
disables the rule) after confirming the model.

Allowlist by qualified policy ID (`schema.table.policy_name`).

Severity: warning. No auto-fix — replacing `current_user` with a
session-GUC predicate needs the application's tenant-key name and
is an architectural decision, not a mechanical rewrite.

Out of scope (intentional):

* **Deployment-model detection.** SEC018 cannot know whether the
  project uses a shared pool role or role-per-tenant — that is
  application/infrastructure context absent from the database. It
  flags the structural use of `current_user` and lets the operator
  resolve it with knowledge pgrls does not have.
* **`current_user` outside policies.** A `current_user` reference
  in a view body, a function, or a `DEFAULT` expression is not in
  scope — SEC018 inspects policy `USING` / `WITH CHECK` clauses
  only, the place where the role identity becomes an access-control
  decision.
"""
from __future__ import annotations

from typing import Any

from pgrls.ast_utils import find_func_calls
from pgrls.model import Policy, Schema, Table
from pgrls.rules._allowlist import parse_policy_id_allowlist
from pgrls.violations import Severity, Violation

# `current_user`, `current_role`, and `user` are three spellings of
# the same value (the current execution role); `session_user` is the
# login role. Postgres parses all four as `SQLValueFunction` nodes,
# which `find_func_calls` matches by these names.
_ROLE_IDENTITY_FUNCTIONS: frozenset[str] = frozenset(
    {"current_user", "current_role", "user", "session_user"}
)


class SEC018:
    id: str = "SEC018"
    severity: Severity = "warning"
    title: str = "Policy expression uses current_user / session_user"

    def check(
        self, schema: Schema, options: dict[str, Any]
    ) -> list[Violation]:
        allowlist = parse_policy_id_allowlist("SEC018", options)
        names = set(_ROLE_IDENTITY_FUNCTIONS)
        out: list[Violation] = []
        for table in schema.tables:
            for policy in table.policies:
                hits: list[Any] = []
                if policy.using_ast is not None:
                    hits.extend(find_func_calls(policy.using_ast, names))
                if policy.with_check_ast is not None:
                    hits.extend(
                        find_func_calls(policy.with_check_ast, names)
                    )
                if not hits:
                    continue
                policy_id = f"{table.schema}.{table.name}.{policy.name}"
                if policy_id in allowlist:
                    continue
                out.append(self._violation(table, policy, policy_id))
        return out

    def _violation(
        self, table: Table, policy: Policy, policy_id: str
    ) -> Violation:
        return Violation(
            rule_id=self.id,
            severity=self.severity,
            title=self.title,
            message=(
                f"Policy {policy.name!r} on {table.qualified_name} "
                "keys its predicate off current_user / session_user "
                "(or the current_role / user aliases). These identify "
                "the Postgres role the session runs as — they isolate "
                "tenants only when each tenant connects as a distinct "
                "role. Application code almost always serves every "
                "tenant over one shared pool role, and then "
                "current_user is a constant: the policy provides no "
                "per-tenant isolation while still looking like access "
                "control. For pooled application code, key the policy "
                "off a per-request session value instead — a GUC read "
                "with current_setting('app.tenant_id'), or a JWT "
                "claim. If this project genuinely uses the "
                "role-per-tenant pattern (one Postgres role per "
                "tenant, SET ROLE per request), current_user is "
                "correct here — allowlist this policy as "
                f"{policy_id!r} in [lint.rules.SEC018]."
            ),
            location=policy_id,
        )
