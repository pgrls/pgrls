"""`pgrls generate` — synthesize gold-standard RLS for tenant tables.

pgrls lints, fixes, tests, and diffs RLS; this module *produces* it. For a
table that carries a tenant-discriminator column but has no row-security
policies, `generate` emits the complete correct setup — `ENABLE` + `FORCE`
row security, a permissive tenant-isolation policy, a restrictive floor,
and the supporting index — designed so the result lints with zero
findings (the gold-standard guarantee, pinned by an end-to-end test).

Scope is the common single-column tenant-isolation case. The richer shapes
(per-CRUD policies, membership-join `EXISTS`, row-owner `auth.uid()`) are
out of scope; `generate` never touches a table that already has policies,
so it can't clobber hand-written intent.

The emitted policies are built as `model.Policy` objects and rendered via
`model.policy_to_sql`, so generated DDL round-trips through pgrls's own
model. ENABLE/FORCE/index statements reuse the SEC001/SEC002/PERF003 fixer
templates verbatim. Output is a list of `fixers.Fix`, so the command reuses
`render_fixes` / `render_migration` and the `fix --apply` execution path.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from pgrls.fixers import Fix
from pgrls.fixers._idents import quote_ident, quote_qualified
from pgrls.model import Policy, Schema, Table, policy_to_sql

Convention = Literal["app-guc", "postgrest"]

# Column types where casting `current_setting(...)` (which returns text) is
# a no-op; for every other type the cast is required for the comparison to
# work and for the btree index to be usable.
_TEXT_TYPES = frozenset({"text", "character varying", "varchar", "citext", "name"})


@dataclass(frozen=True)
class GenerateOptions:
    """How `generate` builds policies. Every field is CLI/config-overridable."""

    tenant_column: str = "tenant_id"
    convention: Convention = "app-guc"
    # Explicit session setting name; when None it is derived per column from
    # the convention (`app.<col>` or `request.jwt.claim.<col>`).
    setting_name: str | None = None
    role: str = "authenticated"
    restrictive: bool = True
    # Explicit (schema, table) -> discriminator column overrides, for tables
    # whose column isn't the conventional `tenant_column` (e.g. `org_id`).
    tables: tuple[tuple[str, str, str], ...] = ()

    def resolved_setting(self, column: str) -> str:
        if self.setting_name:
            return self.setting_name
        if self.convention == "postgrest":
            return f"request.jwt.claim.{column}"
        return f"app.{column}"


@dataclass(frozen=True)
class GenerateResult:
    statements: tuple[Fix, ...] = ()
    # (qualified_name, reason) for tables that matched but were not generated.
    skipped: tuple[tuple[str, str], ...] = ()
    # Advisory messages (e.g. nullable discriminator → SEC030 will flag).
    notes: tuple[str, ...] = ()


def session_predicate(
    column: str, coltype: str | None, options: GenerateOptions
) -> str:
    """Build the policy predicate comparing the column to the session value.

    Shape: `col = (SELECT current_setting('<setting>', true)::<type>)`.

    - The `(SELECT …)` wrapper forces Postgres to evaluate the setting once
      per statement (a cached InitPlan) rather than per candidate row — the
      same rewrite PERF001 flags, so an unwrapped form would not lint
      clean. The column stays bare on the left, so the index is still used.
    - A two-arg `current_setting(…, true)` returns NULL when the setting is
      unset, making `col = NULL` evaluate to NULL → the row is denied (the
      safe default; this is NOT the SEC004 `IS NULL OR …` expose footgun).
    """
    setting = options.resolved_setting(column)
    # `setting` lands inside a single-quoted SQL string literal.
    escaped = setting.replace("'", "''")
    call = f"current_setting('{escaped}', true)"
    if coltype and coltype.lower() not in _TEXT_TYPES:
        call = f"{call}::{coltype}"
    return f"{quote_ident(column)} = (SELECT {call})"


def _column_type(table: Table, column: str) -> str | None:
    for col in table.column_details:
        if col.name == column:
            return col.data_type
    return None


def _column_nullable(table: Table, column: str) -> bool:
    for col in table.column_details:
        if col.name == column:
            return col.is_nullable
    # Unknown (older snapshot without column_details) — assume nullable so
    # we surface the SEC030 caveat rather than silently asserting NOT NULL.
    return True


def _statements_for_table(
    table: Table, column: str, options: GenerateOptions
) -> list[Fix]:
    qname = quote_qualified(table.schema, table.name)
    pred = session_predicate(column, _column_type(table, column), options)
    out: list[Fix] = []

    if not table.rls_enabled:
        out.append(
            Fix(
                rule_id="SEC001",
                location=table.qualified_name,
                sql=f"ALTER TABLE {qname} ENABLE ROW LEVEL SECURITY;",
                description=f"Enable row-level security on {table.qualified_name}.",
            )
        )
    if not table.force_rls:
        out.append(
            Fix(
                rule_id="SEC002",
                location=table.qualified_name,
                sql=f"ALTER TABLE {qname} FORCE ROW LEVEL SECURITY;",
                description=(
                    f"Force row-level security on {table.qualified_name} so "
                    "the table owner is also subject to policies."
                ),
            )
        )

    permissive = Policy(
        name=f"{table.name}_tenant_isolation",
        command="ALL",
        permissive=True,
        roles=(options.role,),
        using_sql=pred,
        with_check_sql=pred,
    )
    out.append(
        Fix(
            rule_id="RLS",
            location=f"{table.qualified_name}.{permissive.name}",
            sql=policy_to_sql(permissive, qname),
            description=(
                f"Permissive tenant-isolation policy on {table.qualified_name} "
                f"scoping rows to the {column!r} discriminator for role "
                f"{options.role!r}."
            ),
        )
    )

    if options.restrictive:
        floor = Policy(
            name=f"{table.name}_tenant_floor",
            command="ALL",
            permissive=False,
            roles=(options.role,),
            using_sql=pred,
            with_check_sql=pred,
        )
        out.append(
            Fix(
                rule_id="RLS",
                location=f"{table.qualified_name}.{floor.name}",
                sql=policy_to_sql(floor, qname),
                description=(
                    f"Restrictive tenant floor on {table.qualified_name} — "
                    "defense-in-depth: AND-combines with every permissive "
                    "policy so the tenant scope holds even if a broader "
                    "policy is added later."
                ),
            )
        )

    out.append(
        Fix(
            rule_id="PERF003",
            location=f"{table.qualified_name} ({column})",
            sql=f"CREATE INDEX ON {qname} ({quote_ident(column)});",
            description=(
                f"Index {table.qualified_name}.{column} — the policies filter "
                "on it, so without an index every row check is a seq scan."
            ),
        )
    )
    return out


def plan_generation(
    schema: Schema, options: GenerateOptions
) -> GenerateResult:
    """Decide which tables to generate RLS for and build the statements.

    Targets a table when it carries the discriminator column (the
    conventional `tenant_column`, or an explicit `--table` override) and
    has **no** policies. A table that already has any policy is skipped and
    reported — `generate` never clobbers existing policy intent. Re-running
    after applying is therefore a no-op.
    """
    explicit: dict[tuple[str, str], str] = {
        (s, n): col for (s, n, col) in options.tables
    }
    seen: set[tuple[str, str]] = set()
    statements: list[Fix] = []
    skipped: list[tuple[str, str]] = []
    notes: list[str] = []

    for table in sorted(schema.tables, key=lambda t: t.qualified_name):
        key = (table.schema, table.name)
        if key in explicit:
            column = explicit[key]
        elif options.tenant_column in table.columns:
            column = options.tenant_column
        else:
            continue  # not a target
        seen.add(key)

        if column not in table.columns:
            skipped.append(
                (table.qualified_name, f"column {column!r} not found on table")
            )
            continue
        if table.policies:
            skipped.append(
                (
                    table.qualified_name,
                    "already has policies — refine with `pgrls lint` / `fix`",
                )
            )
            continue

        statements.extend(_statements_for_table(table, column, options))
        if _column_nullable(table, column):
            notes.append(
                f"{table.qualified_name}.{column} is nullable — a NULL row "
                "escapes tenant scoping; consider `ALTER TABLE "
                f"{quote_qualified(table.schema, table.name)} ALTER COLUMN "
                f"{quote_ident(column)} SET NOT NULL;` (SEC030 flags this "
                "otherwise)."
            )

    # Explicit --table entries that matched no introspected table.
    for (s, n) in explicit:
        if (s, n) not in seen:
            skipped.append((f"{s}.{n}", "table not found in scanned schemas"))

    return GenerateResult(
        statements=tuple(statements),
        skipped=tuple(sorted(skipped)),
        notes=tuple(notes),
    )
