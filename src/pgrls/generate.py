"""`pgrls generate` — synthesize gold-standard RLS.

pgrls lints, fixes, tests, and diffs RLS; this module *produces* it. For a
table that carries a discriminator column but has no row-security policies,
`generate` emits the complete correct setup — `ENABLE` + `FORCE` row
security, a permissive isolation policy, a restrictive floor, and the
supporting index — designed so the result lints with zero findings (the
gold-standard guarantee, pinned by end-to-end tests).

Two scoping models (see `GenerateOptions.model`): `tenant` (per-tenant
isolation on `tenant_id`) and `owner` (per-user ownership on `user_id`,
incl. the Supabase `(SELECT auth.uid())` form). Scope is the common
single-column case for each; the richer shapes (per-CRUD policies,
membership-join `EXISTS`) stay hand-written. `generate` never touches a
table that already has policies, so it can't clobber hand-written intent.

The emitted policies are built as `model.Policy` objects and rendered via
`model.policy_to_sql`, so generated DDL round-trips through pgrls's own
model. The ENABLE/FORCE/index statements are emitted with the shared
`fixers._idents.enable_rls_sql` / `force_rls_sql` / `create_index_sql`
builders — the same builders the SEC001/SEC002/PERF003 fixers use, so the
generated DDL is byte-identical to what `pgrls fix` would emit. Output is a
list of `fixers.Fix`, so the command reuses `render_fixes` /
`render_migration` and the `fix --apply` execution path.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from pgrls.fixers import Fix
from pgrls.fixers._idents import (
    create_index_sql,
    enable_rls_sql,
    force_rls_sql,
    quote_ident,
    quote_qualified,
)
from pgrls.model import (
    Policy,
    Schema,
    Table,
    _is_safe_data_type,
    policy_to_sql,
)

Convention = Literal["app-guc", "postgrest", "supabase"]
# What the discriminator scopes rows to: a tenant (per-tenant isolation) or
# the current user (per-row ownership). Drives the default column, the
# postgrest claim, and the policy names.
Model = Literal["tenant", "owner"]

# Column types where casting `current_setting(...)` (which returns text) is
# a no-op; for every other type the cast is required for the comparison to
# work and for the btree index to be usable.
_TEXT_TYPES = frozenset({"text", "character varying", "varchar", "citext", "name"})


@dataclass(frozen=True)
class GenerateOptions:
    """How `generate` builds policies. Every field is CLI/config-overridable."""

    tenant_column: str = "tenant_id"
    model: Model = "tenant"
    convention: Convention = "app-guc"
    # Explicit session setting name; when None it is derived from the
    # convention + model (`app.<col>` / `request.jwt.claim.<claim>`).
    setting_name: str | None = None
    # Auth function for the `supabase` convention (owner model): the policy
    # compares the column to `(SELECT <auth_function>())`.
    auth_function: str = "auth.uid"
    role: str = "authenticated"
    restrictive: bool = True
    # Explicit (schema, table) -> discriminator column overrides, for tables
    # whose column isn't the conventional one (e.g. `org_id`).
    tables: tuple[tuple[str, str, str], ...] = ()
    # Compare against a RAISING binding helper instead of a bare
    # `current_setting(..., true)`, so a query that forgot to bind a tenant
    # errors instead of silently returning nothing. See `session_predicate`.
    strict_binding: bool = False

    @property
    def binding_function(self) -> str:
        """Qualified name of the raising helper `--strict-binding` emits."""
        return f"pgrls_require_{self.label}"

    @property
    def label(self) -> str:
        """`tenant` / `owner` — used in policy names and descriptions."""
        return "owner" if self.model == "owner" else "tenant"

    def resolved_setting(self, column: str) -> str:
        if self.setting_name:
            return self.setting_name
        if self.convention == "postgrest":
            # The owner model scopes to the JWT subject (`sub`), not a
            # per-column claim; the tenant model reads the column's claim.
            claim = "sub" if self.model == "owner" else column
            return f"request.jwt.claim.{claim}"
        return f"app.{column}"


@dataclass(frozen=True)
class GenerateResult:
    statements: tuple[Fix, ...] = ()
    # (qualified_name, reason) for tables that matched but were not generated.
    skipped: tuple[tuple[str, str], ...] = ()
    # Advisory messages (e.g. nullable discriminator → SEC030 will flag).
    notes: tuple[str, ...] = ()


def _auth_function_sql(fn: str) -> str:
    """Render an `--auth-function` value as a quoted function reference.

    Accepts a bare name (`uid` -> `"uid"`) or a `schema.function` pair
    (`auth.uid` -> `auth."uid"`), splitting on the rightmost dot and
    quoting each segment independently.

    A value with MORE THAN ONE dot is rejected: pgrls qualifies a
    function as schema.function only, so `rpartition('.')` would fold the
    extra dots into a single quoted schema (`a.b.c` -> `"a.b".c()`),
    silently emitting a reference to a function that does not exist —
    `generate --apply` then aborts the whole all-or-nothing batch with a
    Postgres "function does not exist" error. Reject early with a clear
    message instead (mirrors the `seed()` table-name guard in
    testing/client.py). A schema or function name that genuinely contains
    a dot must be handled by passing the qualified pieces explicitly; it
    cannot be disambiguated from a dotted name here.
    """
    if fn.count(".") > 1:
        raise ValueError(
            f"--auth-function {fn!r} has more than one dot. Expected a "
            'bare function name (e.g. "uid") or a schema-qualified name '
            '(e.g. "auth.uid"); a multi-part name is ambiguous and would '
            "render an invalid function reference."
        )
    if "." in fn:
        schema_part, _, name_part = fn.rpartition(".")
        return quote_qualified(schema_part, name_part)
    return quote_ident(fn)


def session_predicate(
    column: str, coltype: str | None, options: GenerateOptions
) -> str:
    """Build the policy predicate comparing the column to the session value.

    Shape: `col = (SELECT current_setting('<setting>', true)::<type>)`, or
    `col = (SELECT auth.uid())` under the `supabase` convention.

    - The `(SELECT …)` wrapper forces Postgres to evaluate the read once per
      statement (a cached InitPlan) rather than per candidate row — the same
      rewrite PERF001 flags, so an unwrapped form would not lint clean. The
      column stays bare on the left, so the index is still used.
    - A two-arg `current_setting(…, true)` returns NULL when the setting is
      unset, making `col = NULL` evaluate to NULL → the row is denied (the
      safe default; this is NOT the SEC004 `IS NULL OR …` expose footgun).
      `auth.uid()` likewise returns NULL for an unauthenticated request.

    Under `strict_binding` the session read becomes a call to a helper that
    RAISES when nothing is bound, so a query whose connection never set the
    GUC errors instead of quietly returning nothing. That silence is the
    default's one real cost: an unbound query and a genuinely-empty result
    are indistinguishable to the caller, so an application that forgets to
    bind a tenant reports 404s rather than failing loudly, and no test that
    connects as the owner can tell the difference.

    The wrapper stays. Measured on PG16, a 10,000-row scan calls the helper
    **10,001 times** unwrapped and **once** wrapped, so the unwrapped form
    trades a 10,000x per-query cost for its stricter firing — and PERF001
    would flag it besides. Wrapped, the InitPlan is evaluated when the scan
    produces a candidate row to filter, which means the raise fires exactly
    when a row *would have been returned and was about to be wrongly
    hidden*. When nothing matched anyway — an empty table, a token that does
    not exist — it stays silent, and there the empty result was the truthful
    answer, so a legitimate 404 is never converted into an error.
    """
    qcol = quote_ident(column)
    if options.strict_binding:
        # The helper takes the setting name so ONE function serves every
        # table, and returns text; the cast (if any) is applied outside it
        # exactly as in the non-strict form.
        setting = options.resolved_setting(column)
        escaped = setting.replace("'", "''")
        call = f"{quote_ident(options.binding_function)}('{escaped}')"
        if coltype and coltype.lower() not in _TEXT_TYPES:
            if not _is_safe_data_type(coltype):
                raise ValueError(
                    f"refusing to build a cast from an unsafe column type "
                    f"{coltype!r} for column {column!r}: it does not parse as "
                    "a single bare column type. This should never happen for "
                    "a type read from live introspection."
                )
            call = f"{call}::{coltype}"
        return f"{qcol} = (SELECT {call})"

    if options.convention == "supabase":
        # `col = (SELECT auth.uid())` — the canonical Supabase row-owner
        # form. No cast: auth.uid() returns uuid (match a uuid column).
        fn_sql = _auth_function_sql(options.auth_function)
        return f"{qcol} = (SELECT {fn_sql}())"

    setting = options.resolved_setting(column)
    # `setting` lands inside a single-quoted SQL string literal.
    escaped = setting.replace("'", "''")
    call = f"current_setting('{escaped}', true)"
    if coltype and coltype.lower() not in _TEXT_TYPES:
        # `coltype` is spliced raw into a `::<type>` cast. It comes from
        # live introspection (`format_type`), which is always a benign
        # type expression — but route it through the same probe-parse
        # validator the snapshot trust boundary uses, so the cast can
        # never become an injection sink if a snapshot-fed source is
        # added later. A real type (`uuid`, `numeric(10,2)`, `text[]`,
        # `"My Type"`) passes; a tampered `uuid); DROP …` is rejected.
        if not _is_safe_data_type(coltype):
            raise ValueError(
                f"refusing to build a cast from an unsafe column type "
                f"{coltype!r} for column {column!r}: it does not parse as a "
                "single bare column type. This should never happen for a "
                "type read from live introspection."
            )
        call = f"{call}::{coltype}"
    return f"{qcol} = (SELECT {call})"


def _column_type(table: Table, column: str) -> str | None:
    for col in table.column_details:
        if col.name == column:
            return col.data_type
    return None


def _column_nullable(table: Table, column: str) -> bool:
    for col in table.column_details:
        if col.name == column:
            return col.is_nullable
    # Unknown (older snapshot without column_details). plan_generation
    # now skips a table whose discriminator has no captured type before
    # consulting nullability, so this fallback is unreachable from that
    # path; keep it as a defensive default (assume nullable → surface the
    # SEC030 caveat rather than silently asserting NOT NULL).
    return True  # pragma: no cover - guarded by the type-info skip


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
                sql=enable_rls_sql(qname),
                description=f"Enable row-level security on {table.qualified_name}.",
            )
        )
    if not table.force_rls:
        out.append(
            Fix(
                rule_id="SEC002",
                location=table.qualified_name,
                sql=force_rls_sql(qname),
                description=(
                    f"Force row-level security on {table.qualified_name} so "
                    "the table owner is also subject to policies."
                ),
            )
        )

    label = options.label
    permissive = Policy(
        name=f"{table.name}_{label}_isolation",
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
                f"Permissive {label}-isolation policy on "
                f"{table.qualified_name} scoping rows to the {column!r} "
                f"discriminator for role {options.role!r}."
            ),
        )
    )

    if options.restrictive:
        floor = Policy(
            name=f"{table.name}_{label}_floor",
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
                    f"Restrictive {label} floor on {table.qualified_name} — "
                    "defense-in-depth: AND-combines with every permissive "
                    "policy so the scope holds even if a broader policy is "
                    "added later."
                ),
            )
        )

    out.append(
        Fix(
            rule_id="PERF003",
            location=f"{table.qualified_name} ({column})",
            sql=create_index_sql(qname, column),
            description=(
                f"Index {table.qualified_name}.{column} — the policies filter "
                "on it, so without an index every row check is a seq scan."
            ),
        )
    )
    return out


def binding_function_sql(options: GenerateOptions) -> str:
    """`CREATE OR REPLACE FUNCTION` for the `--strict-binding` helper.

    Takes the setting name so one function serves every table, and RAISES
    `insufficient_privilege` when nothing is bound — the code an application
    can catch and map to a 500 rather than the 404 an unbound query
    currently produces. `STABLE` so the wrapped `(SELECT ...)` InitPlan is
    evaluated once per statement.

    `current_setting(name, true)` is used INSIDE the helper for the same
    reason the non-strict predicate uses it: the one-argument form raises a
    bare `unrecognized configuration parameter` that says nothing about
    tenancy. Reading it with `missing_ok` and raising our own message is
    what turns a silent empty result into a diagnosis.

    Empty string is treated as unbound: `SET app.x = ''` is what a helper
    that stringifies a null id produces, and it fails the same silent way.
    """
    fn = quote_ident(options.binding_function)
    label = options.label
    return (
        f"CREATE OR REPLACE FUNCTION {fn}(setting_name text)\n"
        "RETURNS text\n"
        "LANGUAGE plpgsql\n"
        "STABLE\n"
        "AS $$\n"
        "DECLARE\n"
        "    v text := current_setting(setting_name, true);\n"
        "BEGIN\n"
        "    IF v IS NULL OR v = '' THEN\n"
        "        RAISE EXCEPTION\n"
        f"            'no {label} bound: % is not set on this connection',\n"
        "            setting_name\n"
        "            USING ERRCODE = 'insufficient_privilege',\n"
        f"                  HINT = 'Bind the {label} before querying "
        "(e.g. SET LOCAL), or use a connection helper that does.';\n"
        "    END IF;\n"
        "    RETURN v;\n"
        "END\n"
        "$$;"
    )


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

        if table.partition_of is not None:
            # Declarative-partition child. Postgres does not propagate
            # relrowsecurity to children, but RLS on the partitioned parent
            # covers queries routed through it (SEC001 skips a covered child
            # for the same reason), and a CREATE INDEX on the parent cascades
            # to every child. Generating per-child policies + a per-child
            # index would duplicate the parent's cascading index and is
            # rarely what's wanted — so set up the parent and skip children.
            # Point at the ROOT partitioned table (the one that actually
            # gets the generated RLS), not the immediate parent — for a
            # multi-level partition the immediate parent is itself a skipped
            # child. Mirrors SEC001, which names `ancestors[-1]`.
            ancestors = list(schema.ancestors_of(table))
            if ancestors:
                root_name = ancestors[-1].qualified_name
            else:
                root_name = f"{table.partition_of[0]}.{table.partition_of[1]}"
            skipped.append(
                (
                    table.qualified_name,
                    f"partition of {root_name} — generate RLS on the "
                    "partitioned parent (it covers parent-routed queries and "
                    "its index cascades to children); hand-write per-child "
                    "policies only if you allow direct partition access",
                )
            )
            continue

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

        if _column_type(table, column) is None:
            # No captured type for the discriminator — a pre-v5 snapshot
            # whose `column_details` is empty. Without the type we cannot
            # emit a correctly-cast predicate (`tenant_id = (SELECT
            # current_setting(...))` with no `::uuid` is invalid for a
            # non-text column), so refuse rather than emit a predicate
            # that may not apply / lint clean. Live introspection always
            # carries column_details, so this only guards a stale
            # snapshot fed to plan_generation; re-introspect to generate.
            skipped.append(
                (
                    table.qualified_name,
                    f"no captured type for column {column!r} (pre-v5 "
                    "snapshot) — re-introspect against a live database to "
                    "generate a correctly-cast predicate",
                )
            )
            continue

        statements.extend(_statements_for_table(table, column, options))
        if _column_nullable(table, column):
            notes.append(
                f"{table.qualified_name}.{column} is nullable — a NULL row "
                f"escapes {options.label} scoping; consider `ALTER TABLE "
                f"{quote_qualified(table.schema, table.name)} ALTER COLUMN "
                f"{quote_ident(column)} SET NOT NULL;` (SEC030 flags this "
                "otherwise)."
            )

    # Explicit --table entries that matched no introspected table.
    for (s, n) in explicit:
        if (s, n) not in seen:
            skipped.append((f"{s}.{n}", "table not found in scanned schemas"))

    if options.strict_binding and statements:
        # One helper for the whole run, ordered first: every generated
        # policy references it, so it must exist before they are created.
        statements.insert(
            0,
            Fix(
                rule_id="RLS",
                location=options.binding_function,
                sql=binding_function_sql(options),
                description=(
                    f"Create {options.binding_function}(), which raises when "
                    f"no {options.label} is bound on the connection, so an "
                    "unbound query errors instead of returning nothing."
                ),
            ),
        )
    return GenerateResult(
        statements=tuple(statements),
        skipped=tuple(sorted(skipped)),
        notes=tuple(notes),
    )
