"""SEC018 — policy compares a column against current_user / session_user.

A policy whose `USING` or `WITH CHECK` expression compares a table
**column** against `current_user` (or its aliases `current_role` and
`user`) or `session_user` is using *the Postgres role the session
runs as* as the row-matching key — `owner_role = current_user`,
`current_user = ANY(allowed_roles)`, and so on. That isolates
tenants only when every tenant connects as — or `SET ROLE`s to — a
**distinct** Postgres role.

Application architectures almost never do that. A connection pool
authenticates as one shared database role and serves every tenant's
requests over it; `current_user` is then identical for tenant A and
tenant B, so a policy like

    CREATE POLICY p ON documents
        USING (owner_role = current_user);

matches the same way for every tenant and provides **no**
isolation. The policy looks like access control and passes every
other pgrls check, but the discriminator is a constant.

`session_user` (the original login role, unchanged by `SET ROLE`)
has the same problem, and is strictly worse for the `SET ROLE`
pattern: even a deployment that does `SET ROLE tenant_x` per request
leaves `session_user` pinned to the pool's login role.

The correct discriminator for pooled application code is a
*session-scoped* value the application sets per request: a GUC read
with `current_setting('app.tenant_id')`, or a JWT claim. Those
change per request over a shared connection; the role identity does
not.

What SEC018 flags — and what it deliberately does not:

* **Flagged:** a role-identity function on one side of a comparison
  with a column reference on the other — `owner = current_user`,
  `current_user = tenant_owner`, `current_user = ANY(member_roles)`.
  The column makes it a *data-matching* predicate: the policy is
  keying row visibility off the role identity.
* **Not flagged — `current_user` passed to a function.**
  `pg_has_role(current_user, 'pg_read_all_data', 'MEMBER')`,
  `has_table_privilege(current_user, 't', 'SELECT')` — here
  `current_user` feeds a *role/privilege check*, the standard
  "admin escape" branch of a policy. That is a correct, common
  use; it is not a tenant key.
* **Not flagged — `current_user` compared only to a literal.**
  `current_user = 'postgres'` is a check for one specific role
  (a superuser/admin escape), not a per-row data match. Under a
  shared pool role it is simply false and the rest of the policy
  governs — no isolation is lost.

Detection is structural: the rule walks the parsed policy AST and
looks for an `A_Expr` (comparison) node with a role-identity
`SQLValueFunction` on one operand and a `ColumnRef` on the other,
anywhere in the tree (including inside sub-selects, e.g.
`… IN (SELECT id FROM acl WHERE member = current_user)`).

`current_user`-based policies are **not** universally wrong. The
"role-per-tenant" RLS pattern — one Postgres role per tenant, the
application `SET ROLE`s to the tenant's role per request — is a
legitimate, documented design, and there `current_user` is exactly
the right discriminator. pgrls cannot tell which deployment model
is in use, so SEC018 is severity `warning` and allowlistable: a
role-per-tenant project allowlists the affected policies (or
disables the rule) after confirming the model.

Allowlist by qualified policy ID (`schema.table.policy_name`).

Severity: warning. No auto-fix — replacing the `current_user`
comparison with a session-GUC predicate needs the application's
tenant-key name and is an architectural decision, not a mechanical
rewrite.

Out of scope (intentional):

* **Deployment-model detection.** SEC018 cannot know whether the
  project uses a shared pool role or role-per-tenant — that is
  application/infrastructure context absent from the database. It
  flags the structural pattern and lets the operator resolve it.
* **`current_user IN (SELECT …)` membership.** When `current_user`
  is the test expression of an `IN`/`= ANY` *sub-select* — rather
  than an operand of a direct column comparison — SEC018 does not
  flag it. The dominant anti-pattern is the direct comparison; the
  membership-subquery variant is a known false negative (the
  sub-select's own `member = current_user` comparison, if present,
  is still caught). A direct `current_user = ANY(<array column>)`
  *is* flagged — that is a column comparison.
* **`current_user` outside policies.** A reference in a view body,
  a function, or a `DEFAULT` expression is not in scope — SEC018
  inspects policy `USING` / `WITH CHECK` clauses only.
"""
from __future__ import annotations

from typing import Any

from pglast.ast import A_Expr, Node

from pgrls.ast_utils import extract_column_refs, find_func_calls
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


def _side_has_role_identity(side: Any) -> bool:
    return bool(find_func_calls(side, set(_ROLE_IDENTITY_FUNCTIONS)))


def _side_has_column(side: Any) -> bool:
    return bool(extract_column_refs(side))


def _compares_role_identity_to_column(node: Any) -> bool:
    """True if the tree compares a role-identity function with a column.

    Walks every `A_Expr` (comparison) node and fires when one
    operand subtree carries a role-identity `SQLValueFunction` and
    the *other* carries a `ColumnRef`. Requiring the two on opposite
    operands is what distinguishes a data-matching predicate
    (`owner = current_user`) from an admin/role check
    (`current_user = 'postgres'`, `pg_has_role(current_user, …)`),
    which SEC018 deliberately leaves alone.
    """

    def walk(n: Any) -> bool:
        if n is None:
            return False
        if isinstance(n, (list, tuple)):
            return any(walk(item) for item in n)
        if isinstance(n, A_Expr):
            lhs, rhs = n.lexpr, n.rexpr
            if (
                _side_has_role_identity(lhs) and _side_has_column(rhs)
            ) or (
                _side_has_role_identity(rhs) and _side_has_column(lhs)
            ):
                return True
            # fall through — A_Expr is a Node; keep walking its
            # operands for nested comparisons.
        if isinstance(n, Node):
            for field_name in n:
                if walk(getattr(n, field_name, None)):
                    return True
        return False

    return walk(node)


class SEC018:
    id: str = "SEC018"
    severity: Severity = "warning"
    title: str = "Policy compares a column against current_user / session_user"

    def check(
        self, schema: Schema, options: dict[str, Any]
    ) -> list[Violation]:
        allowlist = parse_policy_id_allowlist("SEC018", options)
        out: list[Violation] = []
        for table in schema.tables:
            for policy in table.policies:
                fires = False
                for ast in (policy.using_ast, policy.with_check_ast):
                    if ast is not None and _compares_role_identity_to_column(
                        ast
                    ):
                        fires = True
                        break
                if not fires:
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
                "compares a table column directly against current_user "
                "/ session_user (or the current_role / user aliases). "
                "That uses the session's Postgres role identity as the "
                "row-matching key — it isolates tenants only when each "
                "tenant connects as a distinct role. Application code "
                "almost always serves every tenant over one shared "
                "connection-pool role, and then current_user is a "
                "constant: the comparison matches the same way for "
                "every tenant and the policy provides no per-tenant "
                "isolation. Key the policy off a per-request session "
                "value instead — a GUC read with "
                "current_setting('app.tenant_id'), or a JWT claim. If "
                "this project genuinely uses the role-per-tenant "
                "pattern (one Postgres role per tenant, SET ROLE per "
                "request), current_user is the right key here — "
                f"allowlist this policy as {policy_id!r} in "
                "[lint.rules.SEC018]."
            ),
            location=policy_id,
        )
