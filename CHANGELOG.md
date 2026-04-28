# Changelog

All notable changes to pgrls.

The format follows [Keep a Changelog](https://keepachangelog.com/), and
this project adheres to [Semantic Versioning](https://semver.org/).
While in 0.x, the public surface is the CLI, the snapshot JSON shape,
and the `pgrls.toml` configuration schema; minor bumps may include
breaking changes — they will be called out in this file.

## [Unreleased]

## [0.0.7] - 2026-04-27

### Added
- **Three new rules**:
  - `SEC011` (warning) — policy expression has an `OR true`
    branch. Common shape of a leftover debug bypass. Detection
    is narrow on purpose — only the literal `true` `A_Const`
    inside an `OR` BoolExpr counts.
  - `PERF002` (warning) — policy expression uses a VOLATILE
    function. Default set: `random`, `clock_timestamp`,
    `nextval`, `gen_random_uuid`, `pg_backend_pid`. Bad on two
    counts: non-determinism (`random() < 0.5` admits/denies rows
    unpredictably) and per-row evaluation cost. STABLE
    alternatives like `now()` are NOT in this set; PERF001
    handles them.
  - `HYG002` (warning) — policy named like a placeholder (`todo`,
    `fixme`, `wip`, `tmp`, `temp`, `hack`, `xxx`, `debug`,
    `draft`, `placeholder`). Identifier tokenizer handles
    snake_case, camelCase, and SCREAMING_SNAKE so `todo_owner`,
    `TmpReadAll`, `WIP_POLICY` all match while `stop_at_midnight`
    does not.
- **`pgrls fix` subcommand** — auto-remediates SEC002 and PERF001.
  SEC002 emits `ALTER TABLE … FORCE ROW LEVEL SECURITY;`. PERF001
  walks the policy USING via pglast, replaces unwrapped auth
  calls with `(SELECT …)` SubLinks, and emits an `ALTER POLICY
  … USING (…) [WITH CHECK (…)];` statement. WITH CHECK is
  preserved verbatim. Default mode is dry-run; `--apply` executes.
  `--rule SEC002` / `--rule PERF001` filter. Other rules
  (SEC003 — which role? SEC005 — which column? SEC009 — what
  policy?) require human intent and are not auto-fixed.

### Changed
- **Demo restructured into per-case folders.** Each use case now
  lives at `demo/cases/NN-slug/` with `setup.sql` + `test_uc<NN>.py`
  side by side — open one folder to read the SQL fixture and the
  test assertions together. Shared schema setup (auth schema +
  `auth.uid` / `auth.role` / `auth.jwt` stubs) lives at
  `demo/cases/_shared.sql`. Conftest exposes helpers (`lint`,
  `lint_json`, `base_config`, `all_rule_ids`, `pgrls_toml`) as
  fixtures so each test declares precisely what it needs in its
  signature. 79 cases / 83 tests.

## [0.0.6] - 2026-04-27

### Added
- **Two new rules**:
  - `SEC009` (warning) — RLS enabled but no policies defined.
    Postgres treats this as deny-all: every query returns no rows
    regardless of role. Almost always a forgotten step from a
    migration that enabled RLS planning to add policies.
  - `SEC010` (warning) — policy `USING` clause is the literal
    `false`. Mirror of SEC008. Denies every row through the policy
    form when the right primitive is `REVOKE ALL ON TABLE … FROM
    role` at the GRANT layer; the policy form is misleading because
    the table looks "RLS protected" when it's actually disabled.
- **SARIF v2.1.0 output**. `pgrls lint --format sarif` emits a SARIF
  document GitHub Code Scanning (and similar aggregators) consume
  directly: one `run`, deduped `tool.driver.rules[]` with name +
  shortDescription + helpUri pointing at the AGENTS.md anchor, and
  one `result` per violation locating the finding via
  `logicalLocations[0].fullyQualifiedName`. Severity maps as
  error → "error", warning → "warning", info → "note" (SARIF
  v2.1.0 has no "info" level).

### Changed
- README CI integration recipe now uploads SARIF via
  `github/codeql-action/upload-sarif@v3`, putting findings inline
  on PRs as code-scanning alerts. JSON remains documented for the
  `jq` / dashboard / build-artifact use cases.
- The combined fixture (`tests/fixtures/all_bad.sql`) gained a
  SEC010 block and acknowledges that its existing SEC002 block has
  always also been a SEC009 case (RLS enabled, no policies). The
  `_ALL_RULE_IDS` constant in test files grew SEC009 + SEC010.

## [0.0.5] - 2026-04-27

### Added
- `pgrls lint --format json` emits a stable, machine-readable shape
  with `violations[]` and `summary{}` keys. Pretty-printed,
  `ensure_ascii=False`, trailing newline. The keys are the public CI
  contract; consumers that ignore unknown keys keep working when the
  shape grows.
- `.pre-commit-hooks.yaml` so consumers can drop `pgrls-lint` into
  their `pre-commit` pipeline. README's new "CI integration" section
  shows both the pre-commit recipe and a minimal GitHub Actions
  workflow that spins up Postgres as a service container, applies a
  schema, and emits the JSON report as a build artifact.
- `CHANGELOG.md` (this file). Backfilled from tag annotations and
  GitHub release notes for v0.0.1 — v0.0.4.

## [0.0.4] - 2026-04-27

### Added
- **Four new rules**:
  - `SEC005` (warning) — policy expression has no own-column reference.
    The predicate gates by who-asks, not by which-row.
  - `SEC007` (info) — every policy on a table is permissive. Suggests
    adding a RESTRICTIVE floor.
  - `SEC008` (warning) — policy `USING` clause is the literal `true`.
  - `PERF001` (warning) — auth function called per-row in `USING`
    (unwrapped). Fix is `(SELECT auth.uid())`.
- **SEC001 partition awareness**. The introspector now returns
  `relkind='p'` parents alongside `'r'` tables, and links each
  declarative-partition child to its parent via the new
  `Table.partition_of` field. SEC001 walks the chain and emits one of
  three messages: classic standalone, "is a partition of `<root>`"
  when the visible root also lacks RLS, and "ancestor chain leaves
  the scanned schemas" when the chain exits the introspected scope.
- `Schema.ancestors_of(table)` iterator (cached_property-backed for
  O(N) rather than O(N²) on partition-heavy schemas).
- 67-use-case demo in `demo/` with two run modes (Docker via
  `run.sh`, testcontainers via `pytest demo/test_demo.py`). 69 demo
  tests.

### Fixed
- `find_func_calls(exclude_sublinks=True)` now walks `SubLink.testexpr`
  before bailing, so `auth.uid() IN (SELECT id FROM trusted)` is
  caught by PERF001 (the auth call is on the LHS, not inside the
  subselect).
- SEC005 falsely fired on the correlated-EXISTS membership pattern
  (`EXISTS (SELECT 1 FROM members m WHERE m.tenant_id = tenant_id)`).
  The rule now walks subqueries; documented rare false negative when
  a subquery references a column with the same bare name as one on
  the policy's table.
- `Schema.ancestors_of` raises `ValueError` on a `partition_of` cycle
  instead of silently truncating. (Postgres can't produce a cycle in
  pg_inherits; only corrupted state can.)

### Changed
- Snapshot version 1 → 2: each table dict now includes a
  `partition_of` key (a 2-list `[schema, name]` for declarative
  partition children, or `null`). Existing snapshots remain valid;
  consumers must accept the new field.
- AGENTS.md and `pgrls.example.toml` document the SEC001 partition
  behavior and the direct-child-access caveat.

## [0.0.3] - 2026-04-25

### Added
- **Five new rules**:
  - `SEC002` (error) — tables with RLS enabled but
    `FORCE ROW LEVEL SECURITY` off.
  - `SEC003` (error) — permissive policies granted to `PUBLIC`.
  - `SEC004` (error) — inverted auth check (Lovable CVE pattern):
    top-level `auth.uid() IS NULL OR ...` disjuncts.
  - `SEC006` (error) — `INSERT` / `UPDATE` / `ALL` policies with no
    `WITH CHECK` clause.
  - `HYG001` (error) — policies referencing columns that don't exist
    on the table.
- Per-rule configuration in `pgrls.toml`. SEC002 / SEC003 / SEC006
  take an `allowlist`; SEC004 takes an `auth_functions` override for
  non-Supabase auth helpers.
- Eager AST parsing of policy `USING` and `WITH CHECK` via
  [pglast](https://github.com/lelit/pglast). New (internal) AST
  helpers: `parse_expr`, `top_level_disjuncts`, `extract_column_refs`,
  `find_func_calls`, `match_is_null`.
- Introspection collects `pg_attribute` columns for HYG001's column
  existence check.

## [0.0.2] - 2026-04-25

### Changed
- Coverage hardening across the existing surface (no new rules).
  Tests now exercise CLI bad-input paths, multi-schema introspection,
  and OID-zero `polroles` resolving to `PUBLIC`.

## [0.0.1] - 2026-04-25

### Added
- First release.
- `SEC001` (error) — RLS not enabled on a table in a configured
  schema. Allowlist supports unqualified or schema-qualified names.
- `pgrls lint` CLI with the text output formatter.
- Introspection from `pg_catalog`: tables, RLS flags, policies,
  policy roles.
- `pgrls.toml` configuration loader with environment-variable
  substitution (`$VAR` and `${VAR}`).
