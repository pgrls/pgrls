"""SEC018 — policy compares an own column against current_user / session_user.

A policy whose `USING` or `WITH CHECK` expression compares one of
its **own table's columns** against `current_user` (or its aliases
`current_role` and `user`) or `session_user` is using *the Postgres
role the session runs as* as the row-matching key —
`owner_role = current_user`, `current_user = ANY(member_roles)`, and
so on. That isolates tenants only when every tenant connects as — or
`SET ROLE`s to — a **distinct** Postgres role.

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

* **Flagged:** a role-identity function compared (in an `A_Expr`)
  against a column of the **policy's own table** —
  `owner = current_user`, `current_user = tenant_owner`,
  `current_user = ANY(member_roles)`. The own-table column makes it
  a *data-matching* predicate: the policy keys row visibility off
  the role identity.
* **Not flagged — `current_user` passed to a function.**
  `pg_has_role(current_user, 'pg_read_all_data', 'MEMBER')`,
  `has_table_privilege(current_user, 't', 'SELECT')` — here
  `current_user` is a function argument, not an operand of a
  comparison. It feeds a *role/privilege check*, the standard
  "admin escape" branch of a policy. Correct and common; not a
  tenant key.
* **Not flagged — `current_user` compared only to a literal.**
  `current_user = 'postgres'` is a check for one specific role
  (a superuser/admin escape), not a per-row data match. There is
  no column operand.
* **Not flagged — `current_user` compared to a non-own-table
  column.** A catalog lookup such as
  `EXISTS (SELECT 1 FROM pg_roles WHERE rolname = current_user AND
  rolsuper)` is *also* an admin/superuser escape — `pg_roles.rolname`
  is a catalog column, not a tenant key. Restricting the column
  operand to the policy's own table excludes this family (catalog
  lookups, joins to unrelated tables) without a brittle per-table
  semantic analysis — with one imprecision, the bare-name collision
  noted under "Out of scope" below.

Detection is structural: the rule walks the parsed policy AST and
looks for an `A_Expr` (operator) node with a role-identity
`SQLValueFunction` on one operand and a reference to a column of
the policy's own table on the other — including a column reached
through correlation from inside a sub-select. (`A_Expr` is the
generic operator node; in practice the operator pairing a role
identity with a column is `=` or another comparison.)

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
* **Comparisons against non-own-table columns.** Only the policy's
  own table columns count (the same own-column scoping SEC005
  uses). A `current_user` comparison against a column of another
  table — `… IN (SELECT id FROM acl WHERE acl.member =
  current_user)`, a `pg_roles` lookup — is not flagged. This
  excludes the catalog-lookup admin escape (a true non-finding) at
  the cost of missing the membership-table variant of the
  anti-pattern (a known false negative); the dominant shape, a
  direct own-column comparison, is caught.
* **Bare-name collisions.** Own-table membership is resolved by
  column *name* — `extract_column_refs` cannot tell an unqualified
  column inside a sub-select from a same-named column of the
  policy's own table. So a catalog/membership lookup
  `… WHERE col = current_user` where `col` is unqualified *and* the
  policy's own table also has a column named `col` is
  (mis-)flagged. This is the same bare-name imprecision SEC005
  documents — there a false negative, here a false positive.
  Qualifying the sub-select column avoids it; an operator who hits
  it allowlists the policy.
* **Tables with no captured column list.** `Table.columns` is
  populated by introspection for every real table; when it is
  empty — a hand-built `Table` constructed without a column list —
  SEC018 cannot resolve own-table columns and skips the table, the
  same degradation as SEC005.
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


def _is_own_column_ref(ref: tuple[str, ...], table: Table) -> bool:
    """True if a ColumnRef name tuple names a column of `table`.

    Mirrors `SEC005._is_own_column_ref` — bare (`col`),
    table-qualified (`table.col`), and schema-qualified
    (`schema.table.col`) forms all resolve against `table.columns`.
    """
    if len(ref) == 1:
        return ref[0] in table.columns
    if len(ref) == 2:
        return ref[0] == table.name and ref[1] in table.columns
    if len(ref) == 3:
        return (
            ref[0] == table.schema
            and ref[1] == table.name
            and ref[2] in table.columns
        )
    return False


# The per-operand checks use `exclude_sublinks=True`: a
# `current_user` or column buried inside a sub-select is not an
# operand *value* of the enclosing A_Expr (it belongs to the
# sub-select's own predicate). `owner = (SELECT r FROM other WHERE
# m = current_user)` must not pair `owner` with that nested
# `current_user`. The tree walk below still recurses into
# sub-selects separately, so an A_Expr *inside* a sub-select —
# e.g. a correlated `t.owner = current_user` — is still examined
# on its own.
def _side_has_role_identity(side: Any) -> bool:
    return bool(
        find_func_calls(
            side, set(_ROLE_IDENTITY_FUNCTIONS), exclude_sublinks=True
        )
    )


def _side_has_own_column(side: Any, table: Table) -> bool:
    return any(
        _is_own_column_ref(ref, table)
        for ref in extract_column_refs(side, exclude_sublinks=True)
    )


def _compares_role_identity_to_own_column(node: Any, table: Table) -> bool:
    """True if the tree compares a role-identity function with an own column.

    Walks every `A_Expr` (operator) node and fires when one
    operand carries a role-identity `SQLValueFunction` and the
    *other* carries a column of `table`. Requiring the two on
    opposite operands distinguishes a data-matching predicate
    (`owner = current_user`) from an admin/role check
    (`current_user = 'postgres'`, `pg_has_role(current_user, …)`).
    Requiring the column to belong to `table` excludes catalog
    lookups (`pg_roles.rolname = current_user`) and joins to
    unrelated tables — both admin escapes, not tenant keys.
    """

    def walk(n: Any) -> bool:
        if n is None:
            return False
        if isinstance(n, (list, tuple)):
            return any(walk(item) for item in n)
        if isinstance(n, A_Expr):
            lhs, rhs = n.lexpr, n.rexpr
            if (
                _side_has_role_identity(lhs)
                and _side_has_own_column(rhs, table)
            ) or (
                _side_has_role_identity(rhs)
                and _side_has_own_column(lhs, table)
            ):
                return True
            # fall through — A_Expr is a Node; keep walking its
            # operands for nested A_Expr nodes (and sub-selects).
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
            # Own-column resolution needs the captured column list.
            # Introspection populates it for every real table; an
            # empty list means a hand-built `Table` fixture — skip
            # it, mirroring SEC005.
            if not table.columns:
                continue
            for policy in table.policies:
                fires = False
                for ast in (policy.using_ast, policy.with_check_ast):
                    if (
                        ast is not None
                        and _compares_role_identity_to_own_column(ast, table)
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
                "compares one of the table's own columns against "
                "current_user / session_user (or the "
                "current_role / user aliases). That uses the "
                "session's Postgres role identity as the row-matching "
                "key — it isolates tenants only when each tenant "
                "connects as a distinct role. Application code almost "
                "always serves every tenant over one shared "
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
