# pgrls architecture

A walkthrough of how the linter is wired together, for power users
who want to understand what pgrls does internally and for would-be
contributors. For the user-facing tour see
[`README.md`](../README.md); for the "how do I add a rule?" worked
tutorial see [`docs/RULE_AUTHORING.md`](RULE_AUTHORING.md).

## The big picture

```
                ┌─────────────────────────────────┐
                │  Postgres database (any source) │
                └────────────────┬────────────────┘
                                 │   read-only catalog queries
                                 ▼
                ┌─────────────────────────────────┐
                │  pgrls.introspect               │
                │  (SQL → Schema model)           │
                └────────────────┬────────────────┘
                                 │   Schema(tables=...)
                                 ▼
                ┌─────────────────────────────────┐
                │  Rules                          │
                │  (Schema, options) → Violations │
                └────────────────┬────────────────┘
                                 │   list[Violation]
                ┌────────────────┴────────────────┐
                ▼                                  ▼
   ┌─────────────────────────┐       ┌────────────────────────────┐
   │  Formatters             │       │  Fixers (subset of rules)  │
   │  text/json/sarif/...    │       │  emit remediation SQL      │
   └─────────────────────────┘       └────────────────────────────┘
```

Five layers, each with one job:

1. **Introspection** reads the Postgres catalog and builds an
   immutable `Schema` model.
2. **The Schema model** (`pgrls.model`) is the in-memory shape every
   downstream layer consumes.
3. **Rules** (`pgrls.rules.*`) check the schema and emit
   `Violation`s. Rules never connect to a database; they're pure
   functions over the `Schema`.
4. **Formatters** (`pgrls.formatters.*`) render the violations as
   text, JSON, SARIF, Markdown, GitHub annotations, or JUnit XML.
5. **Fixers** (`pgrls.fixers.*`) translate a subset of violations
   into remediation SQL.

The CLI (`pgrls.cli`) wires them: it parses flags, calls
introspection, runs the registry, picks the formatter, and exits with
a code that reflects the `--fail-on` threshold.

## Layer 1 — Introspection

[`src/pgrls/introspect.py`](../src/pgrls/introspect.py) is the only
module that talks SQL. It opens a `psycopg.Connection`, runs a fixed
set of read-only queries against `pg_class`, `pg_policy`,
`pg_attribute`, `pg_index`, `pg_proc`, `pg_views`, `pg_trigger`,
`pg_roles`, etc., and returns an immutable `Schema`.

Highlights:

- **Read-only.** No DDL, no row-level reads of user tables — just
  catalog reads.
- **Schema-scoped.** `--schemas public,tenant` (or `[lint].schemas`
  in config) narrows the query set so pgrls doesn't lint
  `pg_catalog`, `information_schema`, or Supabase's internal
  `auth`/`storage`/`realtime` schemas.
- **Snapshot-versioned.** The introspector emits a snapshot at the
  current `SNAPSHOT_VERSION` (a module-level constant in
  [`pgrls.model`](../src/pgrls/model.py)); older snapshots
  round-trip through the model with sentinel values for fields
  introduced later (e.g. `column_details` is empty on older
  snapshots, which is how SEC030 knows to skip rather than
  mis-fire).
- **Idempotent.** Two calls against the same database return
  equal-by-value `Schema`s. This is what makes `pgrls snapshot`
  reproducible and `pgrls diff` deterministic.

## Layer 2 — The `Schema` model

[`src/pgrls/model.py`](../src/pgrls/model.py) defines the dataclasses
every other layer consumes:

- **`Schema(tables, views=..., security_definer_functions=..., ...)`**
  — the top-level container; immutable.
- **`Table(schema, name, rls_enabled, force_rls, policies, columns,
  column_details, indexes, triggers, partition_of=...)`** — every
  table in scope.
- **`Policy(name, command, permissive, roles, using_sql, using_ast,
  with_check_sql, with_check_ast)`** — one CREATE POLICY entry. The
  `_ast` fields are the parsed expression trees (via `pglast`); the
  `_sql` fields are the raw text from `pg_get_expr()`.
- **`Index(name, columns, method, is_unique, is_partial, ...)`** —
  one CREATE INDEX entry. `columns` is a tuple; expression-index
  positions render as the empty string `""`.
- **`Trigger(...)`, `View(...)`, `Role(...)`** — round out the
  pieces some rules need.

All fields are kwargs-only by convention; positional order is not
committed across releases.

A rule almost never needs to know how the data was loaded — it asks
the `Schema` directly: *"which tables have RLS on but no policies?"*,
*"does this table have an index whose leading column is `tenant_id`?"*

## Layer 3 — Rules

[`src/pgrls/rules/`](../src/pgrls/rules/) holds one module per rule
plus the registry. Each rule is a small class:

```python
class SEC024:
    id: str = "SEC024"
    severity: Severity = "info"
    title: str = "current_setting parameter name is unqualified"

    def check(
        self, schema: Schema, options: dict[str, Any],
    ) -> list[Violation]: ...
```

The protocol lives at the top of
[`rules/__init__.py`](../src/pgrls/rules/__init__.py); see
[`docs/RULE_AUTHORING.md`](RULE_AUTHORING.md) for a worked tutorial
on writing one.

A few shared helpers worth knowing:

- **[`pgrls.ast_utils`](../src/pgrls/ast_utils.py)** — `pglast`
  walkers. `extract_column_refs`, `extract_range_vars`,
  `find_func_calls`, `is_literal_true`, etc. These handle the AST
  gotchas (sub-link descent, `TypeCast` wrappers, `BoolExpr.args`
  lists, qualified function names like `pg_catalog.current_setting`).
- **[`pgrls.rules._allowlist`](../src/pgrls/rules/_allowlist.py)**
  — `parse_policy_id_allowlist` and `parse_table_ref_allowlist`.
  Don't roll your own.

Rules are run by the registry
([`default_registry()`](../src/pgrls/rules/__init__.py)); each rule
runs against the full `Schema` and its own per-rule
`[lint.rules.<ID>]` options block. A `RecursionError` from a single
rule is caught and re-raised as a `RuntimeError` naming the rule —
one pathological policy can't take down the whole lint run silently.

## Layer 4 — Formatters

[`src/pgrls/formatters/`](../src/pgrls/formatters/) renders the list
of `Violation`s into text, JSON, SARIF, Markdown, GitHub Actions
annotations, or JUnit XML. The JSON / SARIF / JUnit schemas are
**stable**: tooling that consumes them can pin to a major and
upgrade safely.

The text formatter is what shows up in a terminal; the SARIF
formatter is what flows into GitHub Code Scanning via the same
`github/codeql-action/upload-sarif` Action CodeQL uses. The GitHub
formatter (`--format github`) emits inline-PR annotations.

## Layer 5 — Fixers

[`src/pgrls/fixers/`](../src/pgrls/fixers/) holds the 12 rules whose
remediation is mechanical: it can be expressed as a finite
`DROP POLICY` / `CREATE POLICY` / `CREATE INDEX` SQL snippet without
knowing the user's intent.

The fixer protocol is small:

```python
@dataclass(frozen=True)
class Fix:
    rule_id: str
    location: str         # qualified policy ID / table name
    sql: str              # the remediation, with a trailing semicolon
    description: str      # a one-line human-facing summary

@runtime_checkable
class Fixer(Protocol):
    rule_id: str
    def fix(self, schema: Schema, options: dict[str, Any]) -> list[Fix]: ...
```

Note `fix` takes the same `(schema, options)` shape as `Rule.check`, not
a list of pre-computed violations — fixers re-walk the schema so they
can emit precise remediation SQL even when the rule's aggregation
boundary is different from the fixer's.

`pgrls fix` runs the registered fixers against the active violations
and concatenates the `Fix.sql` blocks into one migration-ready output
(`--output 001_pgrls_fixes.sql` writes it; default is stdout).
`pgrls fix --check` is the dry-run.

A rule with no mechanical remediation does not have a fixer (e.g.
SEC004 — pgrls can't author your real auth check). That's deliberate;
fixers' value is precisely that they're safe to apply without human
review.

## The diff layer (`pgrls diff` / `pgrls snapshot`)

[`src/pgrls/diff/`](../src/pgrls/diff/) is a separate subsystem with
its own narrow purpose: take two snapshots (or one snapshot + one
live database) and report what changed.

`pgrls diff` doesn't run the rule registry. Instead it walks the two
`Schema`s pairwise and emits typed `Change` records — `policy_added`,
`policy_dropped`, `policy_predicate_changed`,
`policy_with_check_changed`, `role_grant_added`, `table_rls_enabled`,
etc. Each `Change` carries one of four classifications:

- **SAFE** — predicate tightened, no new role grant, no new
  permissive policy.
- **BREAKING** — predicate widened OR a new permissive policy grants
  access where none existed before.
- **REQUIRES_REVIEW** — semantically ambiguous (e.g. an OR-branch
  added that may or may not widen, depending on data).
- **DANGEROUS** — a class of regressions that almost always means
  a leak (e.g. an `IS NULL OR …` disjunct added, a `BYPASSRLS` role
  newly granted).

The "is this new predicate strictly narrower?" decision is two-layer:
syntactic AST patterns (always on) and optional Z3-driven SAT
implication (`pip install pgrls[diff-z3]`) for cases the syntactic
matcher can't decide. Z3 falls back to `REQUIRES_REVIEW` rather than
falsely claiming `SAFE`.

`pgrls diff --apply migration.sql` does the same thing but ingests a
SQL migration as input: it spins up an ephemeral Postgres
(`pip install pgrls[diff-apply]` for the testcontainers dependency),
applies the baseline schema, applies the migration, snapshots, and
diffs. Useful for *"does this PR widen any policy?"* checks at PR time
without needing a real CI database.

## The testing toolkit

[`src/pgrls/testing/`](../src/pgrls/testing/) is the runtime-side
counterpart to the linter — a pytest plugin
(`pgrls = "pgrls.testing.pytest_plugin"` per
`[project.entry-points.pytest11]`) for writing RLS isolation tests.
It's a thin wrapper around `psycopg`:

- **`PgrlsTestClient`** — per-test connection + transaction, with
  `as_role(role, claims=...)` for switching identities, `seed(table,
  rows)`, `exec(sql, *, params=())`, `fetchall(sql, *, params=())`,
  and five assertion helpers (`assert_rows`, `assert_visible`,
  `assert_invisible`, `assert_rejected`, `assert_silently_dropped`).
- **`pgrls_db`** — the canonical pytest fixture: per-test
  transaction, rolled back at end so nothing persists between tests.
- **`pgrls_test_database_url`** — the override hook for
  testcontainers-style setups (declare a fixture of the same name in
  your `conftest.py`).

It assumes the PostgREST conventions (`SET LOCAL ROLE` + the
`request.jwt.claims` GUC), so a Supabase / PostgREST project can drop
it in without writing any glue.

## The CLI

[`src/pgrls/cli.py`](../src/pgrls/cli.py) is the user-facing surface.
A handful of commands, each a Click sub-command:

- **`pgrls lint`** — introspect → run rules → format → exit per
  `--fail-on`.
- **`pgrls fix`** — introspect → run rules → run fixers → emit
  remediation SQL (`--check` to dry-run).
- **`pgrls snapshot`** — introspect → write `Schema.to_dict()` to
  stdout or `--output`.
- **`pgrls diff`** — load two snapshots (or one snapshot + live DB,
  or `--apply migration.sql`) → classify changes → format.
- **`pgrls report`** — introspect → build a per-table posture
  summary (RLS on/off, FORCE, policy counts, status) → format.
- **`pgrls explain [RULE]`** — print the rule's docstring or the
  catalog (the `--format json`/`markdown` variants are stable
  enough to be embedded in tooling).
- **`pgrls init`** — scaffold a commented `pgrls.toml` with the
  `#:schema` directive.

Each command resolves the connection string the same way: explicit
`--database-url` flag → `$DATABASE_URL` → config-file
`[database].url` → error. Error paths (bad TOML, unknown schema,
unreachable database, unwritable output file) all surface as a
`ToolError` (exit 2) with a clean message — never a Python traceback.

## Why pure-Python + pglast

The rule layer is pure Python because the alternatives — embed
Postgres's own parser via FFI, or shell out to `pg_query` — both add
a binary-toolchain dependency without paying for themselves: pglast
ships pre-built wheels, parses every PG 15-17 dialect we need, and
gives back a typed AST. The whole linter installs from a single
`pip install pgrls` with no compiler, no system dependencies, and no
Postgres client. That trade-off is load-bearing for the CI story.

## Where to learn more

- [`docs/RULE_AUTHORING.md`](RULE_AUTHORING.md) — the worked tutorial
  for adding a rule.
- [`docs/QUICKSTART.md`](QUICKSTART.md) — 5-minute first-run.
- [`AGENTS.md`](../AGENTS.md) — every rule with its reference
  paragraph.
- [`docs/pgrls-test-protocol.md`](pgrls-test-protocol.md) — the
  cross-language Layer 1 contract (Postgres-side wire protocol) the
  TypeScript and Go ports also implement.
