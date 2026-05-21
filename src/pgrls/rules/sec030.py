"""SEC030 — policy scopes by a nullable discriminator column.

A row-scoping policy keys visibility off a column compared to a
per-request auth value — the tenant or user discriminator:

```sql
CREATE TABLE documents (id uuid, tenant_id int, body text);   -- nullable!
ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON documents
    USING (tenant_id = current_setting('app.tenant')::int);
```

If that discriminator column is **nullable**, two things go wrong:

1. **Silent row-hiding (today).** Under plain `=`, a row whose
   `tenant_id` is `NULL` evaluates `NULL = <setting>` → `NULL`,
   which RLS treats as *not* matching. The row is invisible to
   every tenant — not leaked, but silently unreachable. A row that
   should belong to someone belongs to no one.
2. **Latent cross-tenant leak (one edit away).** The nullable
   column is a loaded gun. The moment any policy on the table uses a
   NULL-tolerant form of the same key — `tenant_id IS NOT DISTINCT
   FROM <setting>`, `tenant_id = <setting> OR tenant_id IS NULL`,
   `COALESCE(tenant_id, <setting>) = <setting>` — every `NULL` row
   becomes visible to **every** tenant at once. A `NOT NULL`
   discriminator makes that whole failure mode unreachable.

SEC030 fires when a table has RLS enabled, a policy, captured column
nullability, and a **nullable** column that some policy compares with
`=` against an auth-context value (`current_setting`, `auth.uid`,
`auth.role`, `auth.jwt` by default). The remedy is usually
`ALTER TABLE … ALTER COLUMN … SET NOT NULL` (after backfilling any
existing `NULL`s), plus a `DEFAULT` or trigger so the column is always
populated.

pgrls can't know whether the `NULL`s are intentional, so SEC030 is
**info** severity — it never fails CI by default. It is the
nullable-discriminator companion to two warning-level neighbours:

* **SEC018** flags the wrong *type* of discriminator (a column
  compared to `current_user` / `session_user` — the role identity,
  constant under a shared pool). SEC030 assumes the *right* type (a
  session-GUC / JWT value) and flags it being nullable. The two are
  disjoint: SEC018 keys on role-identity functions, SEC030 keys on
  session-context functions.
* **SEC027** flags a principal column *no* policy scopes by. SEC030
  flags a column a policy *does* scope by, but that is nullable.

Detection is structural and deliberately conservative:

* **Scalar equality only.** Only a plain binary `col = <auth value>`
  (`A_Expr` kind `AEXPR_OP`) counts — the canonical scoping shape.
  `col <> …`, `col > …`, and other operators are not row-identity
  keys, so `created_at > current_setting('app.cutoff')` (a
  legitimate non-tenant use of `current_setting`) never trips it.
  Array-membership `<auth value> = ANY(tags)` (kind `AEXPR_OP_ANY`)
  is also out of scope — a multi-value membership test is a
  different access model from a scalar discriminator.
* **Own-table columns only.** The column operand must belong to the
  policy's own table (same resolution SEC005 / SEC018 use), so a
  sub-select join column or catalog lookup is not mistaken for the
  discriminator.
* **Column is a direct operand; the auth value may be wrapped in a
  fromless sub-select.** The discriminator column must be a direct
  operand of the `=` (column extraction excludes sub-selects), but
  the auth value is detected even inside a scalar sub-select that has
  no `FROM` clause — `tenant_id = (SELECT current_setting('app.tenant'))`
  fires. That wrapped form is the one PERF001 *recommends* (evaluated
  once per statement, not per row), so missing it would blind the
  rule to the best-written policies. A sub-select *with* a `FROM`
  clause is a lookup whose internal predicates are not the value the
  column is compared to, so `id = (SELECT x FROM acl WHERE m =
  current_setting(…))` does **not** fire on `id` — the auth call
  scopes the lookup, not the outer column.
* **Needs captured nullability.** A table whose `column_details`
  weren't captured (a hand-built fixture, or a pre-v5 snapshot) is
  skipped — nullability is unknowable, so the rule stays silent
  until the schema is re-introspected.

Configure the auth-context function set (replaces the default):

```toml
[lint.rules.SEC030]
auth_functions = ["auth.uid", "current_setting", "request.jwt.claim"]
```

Allowlist tables where a nullable discriminator is intentional (the
`NULL`s are a documented "unassigned" sentinel and no NULL-tolerant
policy exists):

```toml
[lint.rules.SEC030]
allowlist = ["public.staging_events"]
```

Severity: info. No auto-fix — `SET NOT NULL` fails on a column that
already holds `NULL`s, so the remedy needs a backfill and a
population strategy pgrls can't author.
"""
from __future__ import annotations

from typing import Any

from pglast.ast import A_Expr, Node, SelectStmt, String, SubLink
from pglast.enums import A_Expr_Kind

from pgrls.ast_utils import extract_column_refs, find_func_calls
from pgrls.model import Schema, Table
from pgrls.rules._allowlist import parse_table_ref_allowlist
from pgrls.violations import Severity, Violation

# Functions that read a per-request session value — the *correct*
# discriminator type for pooled application code (SEC018's docstring
# explains why). Same default set as PERF001 / SEC026. A column
# compared to one of these by `=` is acting as a tenant/user key.
_DEFAULT_AUTH_FUNCTIONS: frozenset[str] = frozenset(
    {"auth.uid", "auth.role", "auth.jwt", "current_setting"}
)


def _parse_auth_functions(options: dict[str, Any]) -> set[str]:
    raw = options.get("auth_functions")
    if raw is None:
        return set(_DEFAULT_AUTH_FUNCTIONS)
    if not isinstance(raw, list) or not all(isinstance(s, str) for s in raw):
        raise TypeError(
            "[lint.rules.SEC030].auth_functions must be a list of "
            'strings (e.g. ["auth.uid", "current_setting"]).'
        )
    return set(raw)


def _table_allowlisted(table: Table, allowlist: set[str]) -> bool:
    """True if the table is named by bare or schema-qualified form
    (mirrors SEC001 / SEC027)."""
    return (
        table.name in allowlist
        or f"{table.schema}.{table.name}" in allowlist
    )


def _expr_op(node: A_Expr) -> str | None:
    """Trailing element of `A_Expr.name` — the bare operator.

    `A_Expr.name` is a list of `String` nodes (`pg_catalog.=` →
    `["pg_catalog", "="]`); the last element is the operator. Mirrors
    SEC026's `_expr_name`.
    """
    parts: list[str] = []
    for f in node.name or ():
        if isinstance(f, String):
            parts.append(f.sval)
    return parts[-1] if parts else None


def _own_column_names(side: Any, table: Table) -> set[str]:
    """Bare names of `table`'s own columns referenced in `side`.

    Resolves bare (`col`), table-qualified (`t.col`), and
    schema-qualified (`s.t.col`) refs against `table.columns`, the
    same own-column resolution SEC005 / SEC018 use. Extraction passes
    `exclude_sublinks=True` so a column inside a sub-select on this
    operand is kept out of the name set — the discriminator must be a
    direct operand of the comparison.
    """
    names: set[str] = set()
    for ref in extract_column_refs(side, exclude_sublinks=True):
        if len(ref) == 1 and ref[0] in table.columns:
            names.add(ref[0])
        elif len(ref) == 2 and ref[0] == table.name and ref[1] in table.columns:
            names.add(ref[1])
        elif (
            len(ref) == 3
            and ref[0] == table.schema
            and ref[1] == table.name
            and ref[2] in table.columns
        ):
            names.add(ref[2])
    return names


def _fromless_subselects(side: Any) -> list[SelectStmt]:
    """Scalar sub-selects in `side` that have NO from clause.

    A `(SELECT current_setting('app.tenant'))` — no FROM — carries the
    compared value in its target list; that is the wrapped form
    PERF001 recommends. A sub-select WITH a from clause (`(SELECT x
    FROM acl WHERE m = current_setting(…))`) is a lookup whose
    internal predicates are not the value the outer column is compared
    to, so it must NOT be treated as the auth operand. The walk does
    not descend into sub-select bodies — only their fromless-ness is
    inspected at this level.
    """
    out: list[SelectStmt] = []

    def walk(n: Any) -> None:
        if n is None:
            return
        if isinstance(n, (list, tuple)):
            for item in n:
                walk(item)
            return
        if isinstance(n, SubLink):
            sub = n.subselect
            if isinstance(sub, SelectStmt) and not sub.fromClause:
                out.append(sub)
            return
        if isinstance(n, Node):
            for field_name in n:
                walk(getattr(n, field_name, None))

    walk(side)
    return out


def _side_has_auth_call(side: Any, auth_functions: set[str]) -> bool:
    # The auth value is the operand the column is compared to. Count
    # it when it is a *direct* call (`col = current_setting()`) or
    # lives in the projection of a fromless scalar sub-select
    # (`col = (SELECT current_setting())`, the form PERF001
    # recommends — one evaluation per statement, not per row).
    # `exclude_sublinks=True` on the direct pass keeps a sub-select's
    # internal predicate out of the operand's value; the fromless
    # branch then re-adds the wrapped recommended form. A sub-select
    # WITH a from clause is a lookup, not the compared value, so it is
    # excluded — avoiding a false positive on
    # `id = (SELECT x FROM acl WHERE m = current_setting(…))`.
    if find_func_calls(side, auth_functions, exclude_sublinks=True):
        return True
    return any(
        find_func_calls(sub.targetList, auth_functions, exclude_sublinks=True)
        for sub in _fromless_subselects(side)
    )


def _scoping_columns(node: Any, table: Table, auth_functions: set[str]) -> set[str]:
    """Own columns compared with `=` against an auth-context value.

    Walks the policy predicate's `A_Expr` nodes; when the operator is
    a scalar `=` and one operand carries an auth-context call while
    the *other* carries an own column, the own column(s) on that other
    side are scoping keys. Requiring the two on opposite operands
    distinguishes a scoping predicate (`tenant_id = current_setting(…)`)
    from an auth call used elsewhere.

    The walk does NOT descend into a `SubLink` body: a
    discriminator-equality must be a predicate of the policy itself,
    not of a sub-query. The one wrapped form that matters —
    `col = (SELECT current_setting())` — is recognised at the outer
    `A_Expr` by `_side_has_auth_call` (which inspects the fromless
    sub-select's projection), so descending is unnecessary. Skipping
    sub-query bodies also avoids pairing an inner unqualified column
    with a same-named own-table column (the bare-name collision SEC018
    documents) inside a `(SELECT … FROM other WHERE col = auth())`
    lookup.
    """
    found: set[str] = set()

    def walk(n: Any) -> None:
        if n is None:
            return
        if isinstance(n, (list, tuple)):
            for item in n:
                walk(item)
            return
        if isinstance(n, SubLink):
            return
        if (
            isinstance(n, A_Expr)
            and n.kind == A_Expr_Kind.AEXPR_OP
            and _expr_op(n) == "="
        ):
            lhs, rhs = n.lexpr, n.rexpr
            if _side_has_auth_call(lhs, auth_functions):
                found.update(_own_column_names(rhs, table))
            if _side_has_auth_call(rhs, auth_functions):
                found.update(_own_column_names(lhs, table))
            # fall through — keep walking operands for nested A_Expr
            # nodes (boolean AND/OR chains), but not into sub-selects.
        if isinstance(n, Node):
            for field_name in n:
                walk(getattr(n, field_name, None))

    walk(node)
    return found


class SEC030:
    id: str = "SEC030"
    severity: Severity = "info"
    title: str = "Policy scopes by a nullable discriminator column"

    def check(
        self, schema: Schema, options: dict[str, Any]
    ) -> list[Violation]:
        auth_functions = _parse_auth_functions(options)
        allowlist = parse_table_ref_allowlist("SEC030", options)
        out: list[Violation] = []
        for table in schema.tables:
            if not table.rls_enabled:
                continue
            if not table.policies:
                continue
            # Nullability comes from column_details (snapshot v5+);
            # without it the rule can't tell nullable from NOT NULL,
            # so skip — mirrors SEC018's no-column-list degradation.
            if not table.column_details:
                continue
            if _table_allowlisted(table, allowlist):
                continue

            scoping: set[str] = set()
            for policy in table.policies:
                for ast in (policy.using_ast, policy.with_check_ast):
                    if ast is not None:
                        scoping |= _scoping_columns(ast, table, auth_functions)
            if not scoping:
                continue

            nullable = {
                c.name for c in table.column_details if c.is_nullable
            }
            nullable_scoping = sorted(scoping & nullable)
            if not nullable_scoping:
                continue

            cols = ", ".join(repr(c) for c in nullable_scoping)
            out.append(
                Violation(
                    rule_id="SEC030",
                    severity=self.severity,
                    title=self.title,
                    message=(
                        f"Table {table.qualified_name} scopes row access "
                        f"by the nullable column(s) {cols}. A row whose "
                        "discriminator is NULL is silently invisible to "
                        "every tenant under `=`, and becomes visible to "
                        "all of them the moment a policy uses a "
                        "NULL-tolerant form (`IS NOT DISTINCT FROM`, "
                        "`… OR col IS NULL`, `COALESCE(col, …)`). Add "
                        "NOT NULL to the discriminator (after backfilling "
                        "existing NULLs), or if the NULLs are an "
                        "intentional sentinel add "
                        f"{table.schema}.{table.name} to "
                        "[lint.rules.SEC030].allowlist."
                    ),
                    location=f"{table.schema}.{table.name}",
                )
            )
        return out
