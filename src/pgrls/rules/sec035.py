"""SEC035 — UNIQUE constraint not scoped to the tenant discriminator.

A multi-tenant table whose rows are isolated by a discriminator column
(`tenant_id = current_setting('app.tenant')`, `user_id = auth.uid()`, …)
must scope its UNIQUE constraints by that same column. A *global* unique —
`UNIQUE (email)` instead of `UNIQUE (tenant_id, email)` — has two failure
modes, neither of which RLS prevents:

1. **Cross-tenant existence leak.** RLS hides other tenants' rows from
   `SELECT`, but the unique index is enforced across *all* rows. Inserting
   `email = 'a@b.com'` when another (invisible) tenant already holds it
   raises `duplicate key value violates unique constraint` — telling the
   caller a value is taken in a tenant they can't see. An oracle for
   enumerating data across the isolation boundary.
2. **Functional false-conflict.** Two tenants legitimately cannot both use
   the same email/slug/username, even though each should own its own
   namespace.

The fix is a composite unique that leads with (or includes) the
discriminator: `UNIQUE (tenant_id, email)`.

Detection is conservative — it flags a unique index only when all of:

* the table has RLS enabled and at least one policy,
* some policy scopes a column by `=` against an auth-context value (the
  discriminator); if none is found the table's tenancy is unknown and
  SEC035 stays silent,
* the index is `UNIQUE` but **not** the PRIMARY KEY (a surrogate PK is
  global by design — captured via `Index.is_primary`, snapshot v13+),
* the index does **not** include any discriminator column, and
* the index's columns are not *all* `uuid` (a uuid is globally unique by
  construction; a `UNIQUE (some_uuid)` leaks nothing enumerable).

The discriminator search errs broad (an auth call anywhere on the other
side of the `=` counts), so SEC035 under-flags rather than risk a false
positive on a correctly-scoped table.

Severity: warning. Allowlist a table where a global unique is intentional
(a deliberately cluster-wide identifier):

```toml
[lint.rules.SEC035]
allowlist = ["public.api_tokens"]
# Replaces the default discriminator-detection set
# {auth.uid, auth.role, auth.jwt, current_setting}.
auth_functions = ["auth.uid", "current_setting", "app.tenant"]
```
"""
from __future__ import annotations

from typing import Any

from pglast.ast import A_Expr, Node, SubLink
from pglast.enums import A_Expr_Kind

from pgrls.ast_utils import extract_column_refs, find_func_calls, own_column_ref
from pgrls.model import Schema, Table
from pgrls.rules._allowlist import parse_table_ref_allowlist, table_in_allowlist
from pgrls.violations import Severity, Violation

# Same default auth-context set as SEC030 / PERF001: a column compared by
# `=` to one of these is acting as a tenant/user discriminator.
_DEFAULT_AUTH_FUNCTIONS: frozenset[str] = frozenset(
    {"auth.uid", "auth.role", "auth.jwt", "current_setting"}
)
_UUID_TYPES = frozenset({"uuid"})


def _parse_auth_functions(options: dict[str, Any]) -> set[str]:
    raw = options.get("auth_functions")
    if raw is None:
        return set(_DEFAULT_AUTH_FUNCTIONS)
    if not isinstance(raw, list) or not all(isinstance(s, str) for s in raw):
        raise TypeError(
            "[lint.rules.SEC035].auth_functions must be a list of strings "
            '(e.g. ["auth.uid", "current_setting"]).'
        )
    return set(raw)


def _own_columns(side: Any, table: Table) -> set[str]:
    """Bare names of `table`'s own columns directly referenced in `side`.

    Resolves bare / table-qualified / schema-qualified refs against
    `table.columns` (the resolution SEC005 / SEC018 / SEC030 use), skipping
    refs inside sub-selects so only a direct operand counts.
    """
    names: set[str] = set()
    for ref in extract_column_refs(side, exclude_sublinks=True):
        col = own_column_ref(ref, table)
        if col is not None:
            names.add(col)
    return names


def _discriminator_columns(table: Table, auth_functions: set[str]) -> set[str]:
    """Own-table columns some policy compares by `=` against an auth value.

    Walks every policy's USING / WITH CHECK AST for a scalar `=` whose one
    side is a direct own-table column and whose other side references an
    auth-context function (directly or inside a sub-select). Deliberately
    broader than SEC030's fromless-only rule: a broader discriminator set
    means SEC035 credits more uniques as scoped and under-flags — the safe
    direction for avoiding false positives.

    The walk does NOT descend into a `SubLink` body (same guard as
    SEC030's `_scoping_columns`): a discriminator equality must be a
    predicate of the policy itself, not of a sub-query. Descending
    would let a column inside a sub-select ACL (`… (SELECT 1 FROM acl
    WHERE tenant_id = auth.uid())`) that happens to share a bare name
    with an own-table column be wrongly credited as the table's
    discriminator — suppressing a genuine cross-tenant UNIQUE finding.
    """
    cols: set[str] = set()

    def walk(node: Any) -> None:
        if node is None:
            return
        if isinstance(node, (list, tuple)):
            for item in node:
                walk(item)
            return
        if isinstance(node, SubLink):
            return
        if isinstance(node, A_Expr) and node.kind == A_Expr_Kind.AEXPR_OP:
            op = node.name[-1].sval if node.name else None
            if op == "=":
                left, right = node.lexpr, node.rexpr
                if find_func_calls(right, auth_functions):
                    cols.update(_own_columns(left, table))
                if find_func_calls(left, auth_functions):
                    cols.update(_own_columns(right, table))
        if isinstance(node, Node):
            for field_name in node:
                walk(getattr(node, field_name, None))

    for policy in table.policies:
        walk(policy.using_ast)
        walk(policy.with_check_ast)
    return cols


class SEC035:
    id: str = "SEC035"
    severity: Severity = "warning"
    title: str = "UNIQUE constraint not scoped to the tenant discriminator"

    def check(
        self, schema: Schema, options: dict[str, Any]
    ) -> list[Violation]:
        allowlist = parse_table_ref_allowlist("SEC035", options)
        auth_functions = _parse_auth_functions(options)
        out: list[Violation] = []
        for table in schema.tables:
            if not table.rls_enabled or not table.policies or not table.indexes:
                continue
            if table_in_allowlist(table, allowlist):
                continue
            discriminators = _discriminator_columns(table, auth_functions)
            if not discriminators:
                continue
            coltype = {c.name: c.data_type for c in table.column_details}
            for index in table.indexes:
                if not index.is_unique or index.is_primary:
                    continue
                cols = [c for c in index.columns if c]  # drop expression slots
                if not cols:
                    continue
                if discriminators.intersection(cols):
                    continue  # already scoped by a discriminator
                if all(coltype.get(c) in _UUID_TYPES for c in cols):
                    continue  # globally unique by construction; leaks nothing
                out.append(self._violation(table, index, sorted(discriminators)))
        return out

    def _violation(
        self, table: Table, index: Any, discriminators: list[str]
    ) -> Violation:
        disc = discriminators[0]
        cols = ", ".join(c for c in index.columns if c)
        return Violation(
            rule_id=self.id,
            severity=self.severity,
            title=self.title,
            message=(
                f"UNIQUE index {index.name!r} on {table.qualified_name} "
                f"covers ({cols}) but not the tenant discriminator "
                f"{disc!r} that the table's policies scope by. RLS hides "
                "other tenants' rows from SELECT, but the unique constraint "
                "is enforced across all of them — an INSERT colliding with "
                "an invisible tenant's row raises a duplicate-key error, "
                "leaking cross-tenant existence and blocking a legitimate "
                f"write. Make it a composite UNIQUE leading with {disc!r} "
                f"(e.g. ({disc}, {cols})), or allowlist "
                f"{table.qualified_name!r} in [lint.rules.SEC035] if a "
                "cluster-wide unique is intended."
            ),
            location=f"{table.qualified_name} ({index.name})",
        )
