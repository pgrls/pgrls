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
* **Identity/discriminator column names only.** The hazard is specific
  to a tenant/user key, so the own column must additionally carry a
  discriminator name (`tenant_id`, `user_id`, `org_id`, … — the same
  default set SEC021 uses, overridable via `identity_columns`). A
  non-discriminator column compared to a session value — a point-in-time
  read `created_at = current_setting('app.snapshot_time')::timestamptz` —
  does NOT fire: a NULL there is fail-closed, and the `SET NOT NULL`
  remedy would wrongly break a legitimately-nullable timestamp.
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

Configure which column names count as discriminators (replaces the
default identity set — add a project-specific key, or narrow it):

```toml
[lint.rules.SEC030]
identity_columns = ["tenant_id", "workspace", "region"]
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

from pglast.ast import A_Expr, ColumnRef, Node, SelectStmt, String, SubLink, TypeCast
from pglast.enums import A_Expr_Kind

from pgrls.ast_utils import find_func_calls, own_column_ref
from pgrls.model import Schema, Table
from pgrls.rules._allowlist import parse_table_ref_allowlist, table_in_allowlist
# Reuse SEC021's identity/discriminator column-name set as the shared
# default so the two rules' notion of "what looks like a tenant/user key"
# cannot drift (R15 #6). SEC030 keeps its own configurable override.
from pgrls.rules.sec021 import _DEFAULT_IDENTITY_COLUMNS
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


def _parse_identity_columns(options: dict[str, Any]) -> set[str]:
    """Column names SEC030 treats as tenant/user discriminators.

    SEC030's hazard model — silent row-hiding plus a loaded-gun
    cross-tenant leak one NULL-tolerant edit away — is specific to a
    tenant/user DISCRIMINATOR. A non-discriminator column that merely
    happens to be compared `=` to a session value (e.g. a point-in-time
    read `created_at = current_setting('app.snapshot_time')::timestamptz`)
    is NOT a discriminator: a NULL there is fail-closed and a NULL-
    tolerant edit only widens a time filter, not a tenant boundary.
    Telling the operator to `SET NOT NULL` on such a column is wrong, so
    gate firing on an identity-column name. Defaults to the same set
    SEC021 uses (single source of truth) and is overridable per project
    with `[lint.rules.SEC030].identity_columns`.
    """
    raw = options.get("identity_columns")
    if raw is None:
        return set(_DEFAULT_IDENTITY_COLUMNS)
    if not isinstance(raw, list) or not all(isinstance(s, str) for s in raw):
        raise TypeError(
            "[lint.rules.SEC030].identity_columns must be a list of "
            'column names, e.g. ["tenant_id", "org_id"].'
        )
    # Case-fold: Postgres lowercases unquoted identifiers, and the
    # column-name comparison lowercases the operand too.
    return {s.lower() for s in raw}


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


def _direct_own_column(side: Any, table: Table) -> str | None:
    """The own-column name when `side` IS that column as DIRECT operand.

    The operand node must itself be a `ColumnRef` (optionally
    `TypeCast`-wrapped — `tenant_id::text`) that resolves against
    `table.columns` — the same own-column resolution SEC005 / SEC018
    use. Requiring the DIRECT operand, not merely the column appearing
    somewhere in the side's subtree, keeps SEC030 on the documented
    scalar-equality shape (`tenant_id = current_setting(…)`) and
    excludes a derived value of the column
    (`substring(tenant_id, 1, 2) = current_setting(…)`), which scopes by
    a transform — not by the column the message would name.
    """
    while isinstance(side, TypeCast):
        side = side.arg
    if not isinstance(side, ColumnRef):
        return None
    names = tuple(f.sval for f in (side.fields or ()) if isinstance(f, String))
    if not names:
        return None
    return own_column_ref(names, table)


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


def _scoping_columns(
    node: Any,
    table: Table,
    auth_functions: set[str],
    identity_columns: set[str],
    *,
    null_safe: bool = False,
) -> set[str]:
    """Own *discriminator* columns compared with `=` against an auth value.

    Walks the policy predicate's `A_Expr` nodes; when the operator is
    a scalar `=` and one operand carries an auth-context call while
    the *other* carries an own column, the own column(s) on that other
    side are scoping keys. Requiring the two on opposite operands
    distinguishes a scoping predicate (`tenant_id = current_setting(…)`)
    from an auth call used elsewhere.

    `null_safe` (default False — SEC030's behaviour is unchanged) also
    treats NULL-safe equality `col IS NOT DISTINCT FROM <auth value>`
    (`AEXPR_NOT_DISTINCT`, operator `=`) as a scoping match. SEC030 leaves
    it off on purpose: a nullable column scoped by `IS NOT DISTINCT FROM`
    is the dangerous NULL-tolerant *leak* form, not the silent-row-hiding
    `=` form SEC030 flags. SEC040 turns it on because there the *presence*
    of any write-side binding clears the finding, so a NULL-safe re-
    assertion (strictly stronger than `=`) must count or SEC040 would
    false-fire on a hardened policy.

    The own column must additionally be an identity/discriminator name
    (`identity_columns`) — SEC030's hazard is specific to a tenant/user
    key, so a non-discriminator column compared to a session value (e.g.
    a snapshot-time `created_at = current_setting(…)`) is not surfaced
    (it would otherwise mis-advise `SET NOT NULL` on a legitimately-
    nullable timestamp).

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
            and _expr_op(n) == "="
            and (
                n.kind == A_Expr_Kind.AEXPR_OP
                or (null_safe and n.kind == A_Expr_Kind.AEXPR_NOT_DISTINCT)
            )
        ):
            lhs, rhs = n.lexpr, n.rexpr
            if _side_has_auth_call(lhs, auth_functions):
                col = _direct_own_column(rhs, table)
                if col is not None and col.lower() in identity_columns:
                    found.add(col)
            if _side_has_auth_call(rhs, auth_functions):
                col = _direct_own_column(lhs, table)
                if col is not None and col.lower() in identity_columns:
                    found.add(col)
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
        identity_columns = _parse_identity_columns(options)
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
            if table_in_allowlist(table, allowlist):
                continue

            scoping: set[str] = set()
            for policy in table.policies:
                for ast in (policy.using_ast, policy.with_check_ast):
                    if ast is not None:
                        scoping |= _scoping_columns(
                            ast, table, auth_functions, identity_columns
                        )
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
