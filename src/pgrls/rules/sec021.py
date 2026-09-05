"""SEC021 — policy compares an identity column against a hardcoded literal.

A row-level security policy isolates tenants by keying row
visibility off a *per-request* value — the tenant id, the owning
account, the workspace — read from session context the application
sets on every connection (`current_setting('app.tenant_id')`, a JWT
claim). The footgun SEC021 flags is a policy that instead compares
that identity column against a **literal constant**:

    CREATE POLICY p ON documents
        USING (tenant_id = 1);

A literal pins the policy to one specific tenant. Every session —
tenant A, tenant B, an anonymous request — is handed the *same*
fixed slice of rows; the policy does no per-tenant scoping at all.
It is almost always a scaffolding value (`tenant_id = 1` while
developing against a seed tenant) that was never swapped for the
real session lookup before the policy shipped.

Detection is a **name heuristic**. SEC021 walks the parsed policy
AST for an `=` comparison (`A_Expr`, plain binary operator) where
one operand is a column whose name is in a configurable
identity-column set — `tenant_id`, `org_id`, `account_id`,
`user_id`, `owner`, … — and the other operand is a literal
(`A_Const`, optionally wrapped in a cast: `'…'::uuid`). The literal
constant is the signal; the identity-ish column *name* is what
separates the anti-pattern from a legitimate `column = literal`
policy such as `USING (is_public = true)` or `USING (status =
'published')`, which compare an *attribute* column to a constant on
purpose.

Because the discriminator is a name heuristic — it cannot know a
project's column conventions, and it deliberately does not analyse
intent — SEC021 is **info** severity: a review nudge, not a hard
finding. Override the column set per project with
`[lint.rules.SEC021].identity_columns` (the list replaces the
default set). Allowlist by qualified policy ID
(`schema.table.policy_name`) when comparing the column to a fixed
value is intentional — a global table pinned to one tenant, an
admin-only policy.

Out of scope (intentional):

* **No own-table scoping.** Unlike SEC018, SEC021 does not require
  the column to belong to the policy's own table. The identity
  name is distinctive enough that a hardcoded `tenant_id = 1`
  inside a sub-select membership check is still worth surfacing,
  and Postgres catalogs carry no identity-named columns, so the
  catalog-lookup false positives SEC018 must exclude do not arise.
* **Equality only.** `tenant_id = 1` is the shape that occurs;
  `tenant_id IN (1, 2)`, `tenant_id <> 1`, and `IS DISTINCT FROM`
  are not flagged.
* **No literal-value analysis.** SEC021 does not judge whether the
  literal "looks like" a real id — any `A_Const` on the other
  operand fires. The fix is the same regardless: key the policy
  off session context.
"""
from __future__ import annotations

from typing import Any

from pglast.ast import A_Const, A_Expr, ColumnRef, Node, String, TypeCast
from pglast.enums import A_Expr_Kind

from pgrls.model import Policy, Schema, Table, policy_id
from pgrls.rules._allowlist import parse_policy_id_allowlist
from pgrls.violations import Severity, Violation

# Column names that, by convention, carry the per-tenant / per-owner
# discriminator a policy should scope rows by. Comparing one of
# these to a literal pins the policy to a single tenant. Override
# per project with `[lint.rules.SEC021].identity_columns` (the
# configured list replaces this set).
_DEFAULT_IDENTITY_COLUMNS: frozenset[str] = frozenset({
    "account",
    "account_id",
    "client_id",
    "company_id",
    "customer_id",
    "group_id",
    "member_id",
    "org",
    "org_id",
    "organisation_id",
    "organization_id",
    "owner",
    "owner_id",
    "project_id",
    "site_id",
    "team_id",
    "tenant",
    "tenant_id",
    "user_id",
    "workspace_id",
})

# The tenant-axis set the cross-tenant / write provers accept (see
# `_z3_compare.prove_cross_tenant_isolation`). A superset of SEC021's flagging
# set: the bare spellings (`client`, `project`, `team`, …) are real tenant keys
# in `col = <session value>` policies, but as SEC021 *sentinels* (`project =
# 'default'` beside a real `user_id = auth.uid()` scope) they fired info noise
# on realistic schemas, so SEC021 keeps only the unambiguous forms.
AXIS_IDENTITY_COLUMNS: frozenset[str] = _DEFAULT_IDENTITY_COLUMNS | frozenset({
    "client", "customer", "company", "workspace", "team", "project",
    "organization", "organisation",
})


def _parse_identity_columns(options: dict[str, Any]) -> set[str]:
    raw = options.get("identity_columns")
    if raw is None:
        return set(_DEFAULT_IDENTITY_COLUMNS)
    if not isinstance(raw, list) or not all(
        isinstance(s, str) for s in raw
    ):
        raise TypeError(
            "[lint.rules.SEC021].identity_columns must be a list of "
            'column names, e.g. ["tenant_id", "org_id"]'
        )
    # Case-fold: Postgres lowercases unquoted identifiers, and the
    # column-name comparison below lowercases the operand too.
    return {s.lower() for s in raw}


def _is_equality(node: A_Expr) -> bool:
    """True if `node` is a plain binary `=` operator expression.

    `A_Expr.kind` must be `AEXPR_OP` — that excludes `IS DISTINCT
    FROM` / `IS NOT DISTINCT FROM`, which also carry an `=` operator
    name but are a different comparison.
    """
    name = node.name
    return (
        node.kind == A_Expr_Kind.AEXPR_OP
        and name is not None
        and len(name) == 1
        and isinstance(name[0], String)
        and name[0].sval == "="
    )


def _is_literal_operand(node: Any) -> bool:
    """True if `node` is a literal constant.

    An `A_Const` (`5`, `'acme'`, `true`), optionally wrapped in one
    or more `TypeCast`s — `'a0b1…'::uuid`, `5::bigint` — which is how
    a literal of a non-default type is spelled.
    """
    if isinstance(node, A_Const):
        return True
    if isinstance(node, TypeCast):
        return _is_literal_operand(node.arg)
    return False


def _operand_is_identity_column(
    side: Any, identity_columns: set[str]
) -> bool:
    """True if `side` IS an identity-named column as the DIRECT operand.

    The operand node must itself be a `ColumnRef` (optionally wrapped in
    one or more `TypeCast`s — `tenant_id::text`) whose last name
    component is in the identity set, so `tenant_id`, `t.tenant_id`, and
    `public.t.tenant_id` all resolve to `tenant_id`. Requiring the
    DIRECT operand — not merely the column appearing somewhere in the
    side's subtree — keeps the rule on the documented `tenant_id = 1`
    shape and excludes derived expressions that do NOT pin the policy to
    a single tenant: `substring(tenant_id, 1, 2) = 'ab'`,
    `tenant_id + 1 = 5`, `tenant_id || 'x' = 'foo'`.
    """
    while isinstance(side, TypeCast):
        side = side.arg
    if not isinstance(side, ColumnRef):
        return False
    names = [f.sval for f in (side.fields or ()) if isinstance(f, String)]
    return bool(names) and names[-1].lower() in identity_columns


def _compares_identity_column_to_literal(
    node: Any, identity_columns: set[str]
) -> bool:
    """True if the tree has an `identity-column = literal` comparison.

    Walks every `A_Expr` and fires when the operator is `=` and one
    operand references an identity-named column while the *other* is
    a literal constant. Requiring the two on opposite operands keeps
    the rule on the `tenant_id = 1` shape.
    """

    def walk(n: Any) -> bool:
        if n is None:
            return False
        if isinstance(n, (list, tuple)):
            return any(walk(item) for item in n)
        if isinstance(n, A_Expr) and _is_equality(n):
            lhs, rhs = n.lexpr, n.rexpr
            if (
                _operand_is_identity_column(lhs, identity_columns)
                and _is_literal_operand(rhs)
            ) or (
                _operand_is_identity_column(rhs, identity_columns)
                and _is_literal_operand(lhs)
            ):
                return True
            # fall through — A_Expr is a Node; keep walking its
            # operands for nested A_Expr nodes and sub-selects.
        if isinstance(n, Node):
            for field_name in n:
                if walk(getattr(n, field_name, None)):
                    return True
        return False

    return walk(node)


class SEC021:
    id: str = "SEC021"
    severity: Severity = "info"
    title: str = (
        "Policy compares an identity column against a hardcoded literal"
    )

    def check(
        self, schema: Schema, options: dict[str, Any]
    ) -> list[Violation]:
        allowlist = parse_policy_id_allowlist("SEC021", options)
        identity_columns = _parse_identity_columns(options)
        out: list[Violation] = []
        for table in schema.tables:
            for policy in table.policies:
                fires = False
                for ast in (policy.using_ast, policy.with_check_ast):
                    if ast is not None and (
                        _compares_identity_column_to_literal(
                            ast, identity_columns
                        )
                    ):
                        fires = True
                        break
                if not fires:
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
                "compares an identity column (a tenant / owner-style "
                "column) against a hardcoded literal — e.g. "
                "`tenant_id = 1`. If that literal is the policy's only "
                "discriminator, every session is handed the same fixed "
                "slice of rows instead of being scoped to its own tenant "
                "— almost always a scaffolding value left in place of the "
                "per-request session context. (If the literal is instead "
                "an additive sentinel — one disjunct of an OR alongside a "
                "real per-request scope, e.g. marking shared/public rows — "
                "that is legitimate.) Key the per-tenant comparison off a "
                "value the application sets per request — "
                "current_setting('app.tenant_id'), or a JWT claim. If the "
                "fixed value is intentional (a table pinned to one tenant, "
                "an admin-only policy, a shared-row sentinel), allowlist "
                f"this policy as {pid!r} in [lint.rules.SEC021]."
            ),
            location=pid,
        )
