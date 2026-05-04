# Changelog

All notable changes to pgrls.

The format follows [Keep a Changelog](https://keepachangelog.com/), and
this project adheres to [Semantic Versioning](https://semver.org/).
While in 0.x, the public surface is the CLI, the snapshot JSON shape,
and the `pgrls.toml` configuration schema; minor bumps may include
breaking changes — they will be called out in this file.

## [Unreleased]

## [0.3.0] - 2026-04-30

### BREAKING
- **Postgres floor bumped 13 → 15.** Older PG releases (10–14) are no
  longer supported. The CI matrix is narrowed to {15, 16, 17}. The
  proximate driver is the new VIEW001 rule and its auto-fixer:
  `security_invoker` is a PG15+ reloption, so a floor below 15 would
  ship a rule the runtime can't satisfy. The conftest's PG-version
  gate, the demo `run.sh` image tag list, the `tests/test_floor_currency`
  fixture, and the AGENTS.md / README disclaimers all reflect the new
  floor.

### Added
- **Four VIEW lint rules.** A new rule category alongside SEC / PERF /
  HYG. Each rule walks the schema's view → table dependency graph and
  fires only when the view actually references an RLS-protected
  table — views over reference data don't trigger.
  - `VIEW001` (error) — view bypasses RLS without
    `WITH (security_invoker = true)`. PG15+ defaults
    `security_invoker` to false; without the flag the view runs
    queries with the view *owner's* privileges and RLS on the
    underlying table is evaluated against the owner instead of the
    calling user. Materialized views are skipped (VIEW003's domain).
  - `VIEW002` (warning) — view is not a `security_barrier`. Without
    the flag, a caller-supplied predicate (e.g. a volatile / side-
    effecting `leak()` in `WHERE`) can be pushed below the view's
    RLS-derived filter and observe rows the caller should never have
    seen. Independent of VIEW001 — neither subsumes the other; a view
    lacking both flags fires both rules.
  - `VIEW003` (warning) — materialized view captures RLS-protected
    data at REFRESH time. A matview reads from its own physical heap
    at query time and does NOT re-evaluate the underlying body, so
    RLS on source tables is bypassed regardless of any flag.
    Architectural fix only (per-tenant refresh, or per-tenant
    matview); no auto-fixer.
  - `VIEW004` (warning) — view calls a `SECURITY DEFINER` function
    that, in turn, reads from an RLS-protected table. The function
    runs with the function owner's privileges, so RLS is evaluated
    against the owner — bypass happens one frame below the view,
    so VIEW001's `security_invoker` defense doesn't help. Three
    documented false-negative paths (non-SQL language, unparseable
    SQL, cross-scope SECDEF function) match the existing AST-based
    rule convention. Over-attributes rather than under-reports when
    a function body uses an unqualified table name shared between
    two RLS-protected schemas.
- **Two new auto-fixers**, doubling the previously fixable surface.
  - `VIEW001Fixer` — emits `ALTER VIEW <schema>.<view> SET
    (security_invoker = true);` per offending view. Mirrors VIEW001's
    detection in lockstep so the fixer never emits an ALTER for a
    view the rule wouldn't flag.
  - `VIEW002Fixer` — emits `ALTER VIEW <schema>.<view> SET
    (security_barrier = true);` with the same lockstep detection. A
    view lacking both flags gets two separate `ALTER VIEW … SET (...)`
    statements (one per fixer), which is the natural shape — neither
    flag implies the other.
- **`View` dataclass and `Schema.views` field.** Snapshot model now
  carries views and matviews alongside tables. Each `View` has
  `schema`, `name`, `is_materialized`, `security_invoker`,
  `security_barrier`, `references` (set of `(schema, name)` pairs the
  view body reads — populated from `pg_depend`), and
  `security_definer_calls` (set of qualified function names called in
  the view body that are SECURITY DEFINER).
- **`SecdefFunction` dataclass and `Schema.security_definer_functions`
  field.** Captures `pg_proc` rows where `prosecdef = true`, with the
  function body and language so VIEW004 can parse and walk it. Limited
  to functions in the introspected `--schemas` set; functions outside
  that scope are silently skipped by VIEW004.
- **Snapshot v4** — `SNAPSHOT_VERSION` bumped from 3 to 4, additive
  within v4 since v4 hasn't shipped externally. Adds top-level
  `views` and `security_definer_functions` arrays. `Schema.from_snapshot`
  accepts v3 + v4 (v3 baselines roundtrip with empty views /
  security_definer_functions).
- **Introspection of views, matviews, and view → table dependencies
  via `pg_depend`.** The introspector now joins `pg_class` (for
  `relkind IN ('v', 'm')`), `pg_rewrite` (to walk `ev_action`), and
  `pg_depend` (to materialize the view → underlying-table edges). The
  `security_invoker` and `security_barrier` reloptions are pulled
  from `pg_class.reloptions`. Materialized views are tagged via
  `is_materialized = true`. Bare-name canonicalization in SECDEF call
  detection sorts qnames before resolving so the result is
  deterministic across runs.
- **SECURITY DEFINER function-call detection in view bodies.** The
  introspector walks each view body for `FuncCall` nodes whose target
  is a SECURITY DEFINER function in the introspected scope, and
  records the qualified function names on `View.security_definer_calls`.
  This is the substrate VIEW004 walks.
- **Four new demo cases (85–88)** covering one rule each. Each case's
  `setup.sql` deliberately satisfies the *other* VIEW rules so the
  scenario fires only the targeted rule (e.g. case 85 for VIEW001 sets
  `security_barrier = true` so VIEW002 stays silent).
- **`parse_qualified_view_allowlist` helper** in
  `pgrls.rules._allowlist`. Validates `[lint.rules.VIEWnnn].allowlist`
  entries as exactly two parts (`schema.view`); bare-name entries are
  rejected with a clear `TypeError` so two views with the same name
  in different schemas can't both be silenced by a typo.
- **`extract_range_vars` AST walker** in `pgrls.ast_utils`. Walks a
  parsed statement and yields every `(schema, name)` pair that appears
  as a `RangeVar` or `RangeFunction`. Used by VIEW004 to enumerate
  table references inside a SECURITY DEFINER function body.

### Changed
- **Demo case 25 (`view-on-top-of-an-rls-enabled-table`)** updated to
  set both `security_invoker = true` and `security_barrier = true` on
  the view so the case stays clean post-v0.3 instead of newly tripping
  VIEW001 / VIEW002. The case's intent (a clean view example) is
  preserved.
- **README, AGENTS.md, conftest, demo runner, and floor-currency
  fixture** all updated for the PG15 floor (see BREAKING above).
- **AGENTS.md** gains four new rule sections (VIEW001–VIEW004) after
  HYG002, mirroring the existing SEC / PERF / HYG section pattern.
  The "Auto-fix" section's "Currently fixable" list grew to four
  rules. The "Limitations" preamble now reads "twenty rules across
  four categories" and drops the obsolete "no SECURITY DEFINER
  function audit" caveat (VIEW004 covers the view-leak path; a
  free-standing function audit remains on the roadmap).
- **Markdown output for `pgrls lint` (`--format markdown`).** New
  formatter alongside text/json/sarif. Renders cleanly in
  GitHub-flavored Markdown — paste into a PR comment, drop into an
  issue template, or commit as a CI artifact. Pipe table with
  per-violation rows (severity emoji + label, rule_id linked to
  AGENTS.md, location in backticks, message); summary line below.
  Empty findings emit the same `pgrls: no issues found.` line as
  the text formatter so a one-liner that gates on the literal
  string works against either format. Cell escaping (pipe → `\\|`,
  newline → `<br>`) makes the table layout robust to adversarial
  message content.
- **SEC012 — table has only RESTRICTIVE policies (silent
  deny-all).** Postgres composes RLS policies as
  `permissive_or | (restrictive_and & ...)`: a row is visible iff
  at least one PERMISSIVE policy matches AND every RESTRICTIVE
  policy matches. With zero PERMISSIVE policies, the disjunction
  is empty — no row passes. Common shape: a developer adds a
  `AS RESTRICTIVE` policy thinking it "layers on top of" an
  implicit permissive default; there is no implicit default.
  Severity: warning. Allowlist by qualified or unqualified table
  name when the deny-all is intentional. Disjoint by construction
  from SEC009 (zero policies) and SEC010 (`USING (false)`) —
  a table can't trigger more than one of the three deny-all rules.

### Fixed
- **`find_func_calls` and `extract_column_refs` walkers now recurse
  into bare tuples.** The pglast AST exposes
  `RangeFunction.functions` as a tuple-of-tuples shape (each inner
  tuple is `(funccall, coldeflist)`); the walkers were previously
  bailing out at the outer tuple boundary, silently swallowing
  function calls and column refs reachable via that path. Set-
  returning functions used in `FROM` clauses (`FROM unnest(arr)`,
  etc.) were not matched by PERF001 / SEC005 etc. as a result. Both
  walkers now descend through bare tuples; the tuple-of-tuples shape
  is no longer a blind spot.

## [0.2.3] - 2026-05-03

### Changed
- **`[lint].disable` and `[lint.rules.<ID>]` rule IDs are
  case-insensitive.** Lowercase keys (`disable = ["sec001"]`,
  `[lint.rules.sec001]`) are now normalized to canonical
  uppercase, mirroring the case-insensitive contract on
  `--fail-on`, `[lint].fail_on`, and `[diff].fail_on`. Two
  TOML keys that differ only in case (`[lint.rules.SEC001]` and
  `[lint.rules.sec001]`) raise `ConfigError` rather than
  silently keeping one.
- **`pgrls fix --rule` accepts case-insensitive input.** `pgrls
  fix --rule sec002` is equivalent to `--rule SEC002`. Aligns
  with the config surfaces above.
- **`pgrls.testing.assert_silently_dropped` gates on the
  statement verb.** SELECT/INSERT no longer slip past the
  helper as zero-row passes; the helper now raises
  `PgrlsTestError` for any verb other than UPDATE/DELETE,
  closing a false-pass shape where a typo'd assertion silently
  succeeded against a SELECT returning no rows.

### Fixed
- **`[lint].disable` rejects unknown rule IDs.** A typo
  (`disable = ["SEC0001"]`) used to silently leave the rule
  enabled. The validator now lists the unknown id and the
  full rule catalog so the user can spot the typo.
- **`[lint.rules.<ID>]` rejects unknown rule IDs.** Same
  silent-acceptance bug in the per-rule options surface; same
  fix shape with the rule catalog in the error.
- **`pgrls diff` GRANT-to-PUBLIC dangerous classification
  fires when RLS is off, even if stale policies exist.** With
  RLS disabled, Postgres ignores any policies on the table —
  the `policies == ()` guard previously suppressed the
  dangerous classification for tables with dormant policies,
  letting wide-open PUBLIC grants through as
  `requires_review`.
- **SARIF and text formatters use a consistent `(schema-wide)`
  sentinel** for violations with no specific table or policy.
  The previous `<schema>` literal looked like markup in some
  SARIF viewers; real qualified names never contain
  parentheses, so the new sentinel is unambiguous.
- **`pgrls.testing` documentation** in README clarifies that a
  user's `pgrls_test_database_url` fixture *replaces* the
  plugin's env-var resolver (it doesn't compose).

## [0.2.2] - 2026-04-29

### Changed
- **`pgrls.diff.differ` split into focused modules.** The 700-line
  orchestrator has been decomposed by concern:
  `pgrls.diff.differ` keeps the public types (`Change`,
  `ChangeKind`, `Classification`) and the `diff_schemas`
  orchestrator (231 lines); per-table helpers live in sibling
  modules — `pgrls.diff.policies` (`_diff_policies` add/drop +
  `_diff_policy_shapes` permissive/command/roles/predicate),
  `pgrls.diff.columns` (`_diff_columns`), `pgrls.diff.grants`
  (`_diff_grants`). No public API change — these are all
  module-private helpers — but importers of `pgrls.diff` and the
  rest of the public surface (`Change`, `ChangeKind`,
  `Classification`, `diff_schemas`) are unchanged.

## [0.2.1] - 2026-04-29

### Changed
- **`pgrls.diff.formatters`: title field preserves the `RLS`
  acronym.** The JSON / SARIF `title` projection of
  `ChangeKind.name` now keeps `RLS` in its uppercase form
  (`Grant Public No RLS` instead of `Grant Public No Rls`,
  `RLS Flipped` instead of `Rls Flipped`). The `_TITLE_ACRONYMS`
  allowlist is intentionally tight — it covers the acronyms that
  appear in current `ChangeKind` names, not speculative future
  ones. Add entries when a real kind needs them.
- **`Schema.from_snapshot` no longer eagerly parses ASTs.**
  `Policy.using_ast` and `with_check_ast` are left as `None` after
  load; the only in-tree consumer that needs them
  (`pgrls.diff._diff_columns`) lazy-parses on demand. Saves
  meaningful upfront work on large schemas. External callers that
  relied on AST-populated-after-load must parse via
  `pgrls.ast_utils.parse_expr(policy.using_sql)`.

### Added
- **`[diff].fail_on` in `pgrls.toml`.** Default `--fail-on`
  threshold for `pgrls diff` is now configurable. Fallback chain:
  CLI flag → `[diff].fail_on` in TOML → built-in `dangerous`.
  Mirrors the lint command's `[lint].fail_on` precedent.
- **`pgrls diff` accepts `file://` URLs as paths.** Useful when
  shell completions or CI variables emit URL-shaped paths.
  Previously the `://` heuristic mis-classified them as DB URLs
  and surfaced a confusing connection error.
- **`DIFF_SUPPORTED_FORMATS` constant** in `pgrls.diff.formatters`
  is now the source of truth for the `--format` choice list. The
  CLI imports it instead of hard-coding `["text", "json", "sarif"]`,
  matching how the lint command sources `SUPPORTED_FORMATS`.

## [0.2.0] - 2026-04-29

### Added
- **`pgrls snapshot` + `pgrls diff`** — semantic policy diff with
  SAFE / BREAKING / REQUIRES_REVIEW / DANGEROUS classification.
  Compare any two RLS schemas (snapshot files, live DBs, or one of
  each — argument disambiguation: `://` ⇒ URL, else file-must-exist
  ⇒ snapshot). Common-case AST patterns for `USING` / `WITH CHECK`
  text changes (literal-equal, AND-tighten / drop, OR-loosen /
  drop); anything else falls into REQUIRES_REVIEW. `--fail-on
  dangerous` (default) gates CI builds on actual security
  relaxations; `--fail-on requires-review` for a stricter gate.
- **Three-tier exit code** matching `pgrls lint`: 0 clean, 1
  changes meet/exceed `--fail-on`, 2 tool error (bad config,
  unreachable DB, malformed snapshot file, etc.).
- **Reuses the existing `Violation` JSON / SARIF shape** for
  `--format json` and `--format sarif`. CI dashboards that already
  parse `pgrls lint` output handle `pgrls diff` output without
  changes; rule_ids use the `DIFF_*` prefix to avoid collisions
  with lint's `SEC*` / `PERF*` / `HYG*`.
- **Snapshot v3** — bumps `SNAPSHOT_VERSION` from 2 to 3. Adds
  per-table `grants` field. `Schema.from_snapshot` accepts v2 + v3
  and rejects v1 / unknown versions with a clear error. v2
  baselines roundtrip into v3 with empty grants on every table —
  diff against a v2 baseline classifies any grant change as
  REQUIRES_REVIEW (the v2 data didn't capture the prior state).
- **Public Python API** — `from pgrls.diff import Change,
  ChangeKind, Classification, diff_schemas`. Stable for v0.2;
  the formatters (`pgrls.diff.formatters`) and AST helpers
  (`pgrls.diff.ast_compare`) remain internal.
- **Demo cases** — `demo/cases/81-84/` exercise the DANGEROUS
  (dropped RESTRICTIVE policy), SAFE (added RESTRICTIVE policy),
  REQUIRES_REVIEW (column dropped while still referenced), and
  BREAKING (dropped PERMISSIVE policy) classifications end-to-end
  against a live DB. Demo grew to 84 cases / 90 tests.

## [0.1.0] - 2026-04-28

### Added
- **`pgrls.testing` pytest plugin** (and Python client). Code-first
  RLS test DSL: `pgrls_db` fixture opens a per-test transaction,
  `as_role(role, claims=...)` switches the actor for a savepoint-
  scoped block, five RLS-specific assertion helpers (`assert_rows`,
  `assert_visible`, `assert_invisible`, `assert_rejected`,
  `assert_silently_dropped`). Auto-discovered via the `pytest11`
  entrypoint. PG10+ supported, no server-side install required —
  follows PostgREST `request.jwt.claims` GUC conventions. Install
  via `pip install pgrls[testing]` to pull in pytest alongside.
- **Cross-language Layer 1 protocol** (`docs/pgrls-test-protocol.md`,
  `PROTOCOL_VERSION = 1`). Documented Postgres-side wire contract
  so future TypeScript / Go ports can re-implement the client
  against the same conventions. Supports nested `as_role` blocks —
  inner blocks capture the outer role + claims and restore them
  on clean exit.
- **Cross-language conformance fixture** at `tests/protocol/`
  (`schema.sql` + `seed.sql` + `manifest.json` + `manifest.schema.json`
  + Python runner). A future port copies the manifest and is
  v1-conformant iff every case passes.
- **`PgrlsTestError` / `PgrlsTestAssertionError` / `PgrlsTestConfigError`**
  exception hierarchy, exposed alongside `PgrlsTestClient` and
  `PROTOCOL_VERSION` from `pgrls.testing.__all__`. Assertion
  failures subclass `AssertionError` so pytest renders them with
  diff-style output.

### Changed
- **README** gains a "Testing your RLS" section between Configuration
  and Rules with the canonical pytest-plugin example.
- **AGENTS.md** gains a parallel "Testing your RLS" section
  (architecture, configuration, assertion-helper semantics table)
  and cross-references `pgrls.testing` from "When to suggest pgrls".

## [0.0.7] - 2026-04-28

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
    `fixme`, `tmp`, `hack`, `xxx`, `debug`, `placeholder`).
    Identifier tokenizer handles snake_case, camelCase, and
    SCREAMING_SNAKE so `todo_owner`, `TmpReadAll`, `TMP_POLICY`
    all match while `stop_at_midnight` does not. Default
    vocabulary excludes `temp`, `draft`, `wip` — they collide
    with real domain words (temperature sensors, CMS draft state,
    WIP inventory); opt back in via `placeholder_words`.
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
- **HYG002 default vocabulary tightened.** Removed `temp`, `draft`,
  `wip` from the default placeholder words — they collide with real
  domain terms (temperature sensors, CMS draft state, WIP
  inventory). Default set is now `todo, fixme, tmp, hack, xxx,
  debug, placeholder`. Users wanting the broader scaffolding-
  detection set can opt back in via `placeholder_words`.
- **SEC006 message branches on permissive vs restrictive.** Permissive
  write-policy with no `WITH CHECK` keeps the read-write asymmetry
  framing. Restrictive write-policy with no `WITH CHECK` is now
  flagged as a "dead policy" — Postgres defaults the missing clause
  to `true`, so the policy imposes no constraint.
- **SEC010 walks `WITH CHECK` too.** Previously only `USING (false)`
  was caught. `WITH CHECK (false)` (a deny-all-writes anti-pattern)
  now fires with a write-side framing and a `REVOKE INSERT, UPDATE`
  remediation hint.
- **Three-tier exit codes.** Exit 0 = clean, exit 1 = findings met
  threshold, exit 2 = pgrls itself failed (bad TOML, DB unreachable,
  fixer SQL rolled back). CI alerts can now route "schema bug"
  separately from "tool error."

### Fixed
- **Postgres catalog correctness.** Role deduplication for policies
  with `TO r1, r1`. NULL-rolname COALESCE for unprivileged callers.
  Reserved schemas (`pg_catalog`, `information_schema`, `pg_toast`,
  per-session temp) are refused with a clear error instead of
  introspecting thousands of system tables.
- **Identifier handling.** `quote_ident` now quotes Postgres reserved
  keywords (`select`, `from`, `order`, etc.) — fixer SQL no longer
  produces syntax errors on legacy schemas with reserved-word table
  names. All C0 control characters and DEL are rejected (was: only
  null/newline). Empty-string identifiers raise rather than emit
  `""`.
- **Allowlist shape validation.** Per-policy rules (SEC003, SEC005,
  SEC006, SEC008, SEC010, SEC011, PERF001, PERF002, HYG002) now
  validate every entry as `schema.table.policy_name` and surface a
  clear `TypeError` on malformed entries. Previously a typo'd entry
  (e.g. unqualified `users`) was silently never matched. Right-
  anchored split also lets users allowlist policies whose names
  contain `.`.
- **Schema lookup error messages.** "Schemas not found" now lists
  available user schemas and suggests close matches via difflib.
- **Parse-error visibility.** When `pglast` cannot parse a policy's
  USING/WITH CHECK clause, the warning now names the policy and
  lists the AST-based rules (SEC004, SEC005, SEC008, SEC010, SEC011,
  HYG001, PERF001, PERF002) that were skipped — closing a silent
  false-negative path.
- **`pgrls fix --apply` rollback message.** Includes the failing SQL
  (truncated), the underlying psycopg error, and a remediation hint
  pointing at next concrete actions.
- **`pgrls fix` is read-only over Schema.** PERF001 fixer no longer
  mutates the input policy AST; rules running after the fixer in the
  same process now see the original Schema.
- **Severity vocabulary case-insensitivity.** `[lint].fail_on =
  "ERROR"` is now accepted (mirrors Click's `--fail-on ERROR`); both
  paths route through the same validator.
- **Fixer/rule default sync.** `_DEFAULT_AUTH_FUNCTIONS` is now
  imported by the PERF001 fixer from the rule, closing a silent-
  drift path where adding to the rule's defaults would not extend
  the fixer's coverage.

### Security
- **CI workflow least-privilege.** GitHub Actions `GITHUB_TOKEN`
  permissions explicitly set to `contents: read` — defense in depth
  against malicious dependencies in the PyPI install chain.
- **Test fixture DDL via `psycopg.sql.Identifier`.** Conftest no
  longer concatenates DB-controlled identifiers into DDL strings.

### CI / packaging
- Test matrix runs the suite on Postgres 10–17 (was: 16 only).
- `py.typed` marker shipped — downstream `mypy` / `pyright` now see
  pgrls's annotations instead of `Any`. `Typing :: Typed` PyPI
  classifier added.
- `[project.urls]` extended with `Repository`, `Changelog`,
  `Documentation` so PyPI's project sidebar links work.
- `uv.lock` policy: gitignored and excluded from the published
  sdist (each contributor resolves fresh against the dependency
  ranges; CI matrix verifies the resolution).
- AGENTS.md gained stable `<a id="rule-xxx"></a>` anchors for every
  rule heading. SARIF `helpUri` now deep-links via these (instead
  of the GitHub-slugified heading, which broke on title rewording).
  README's rule table links the same anchors.

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
