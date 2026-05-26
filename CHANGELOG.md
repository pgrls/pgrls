# Changelog

All notable changes to pgrls.

The format follows [Keep a Changelog](https://keepachangelog.com/), and
this project adheres to [Semantic Versioning](https://semver.org/).
While in 0.x, the public surface is the CLI, the snapshot JSON shape,
and the `pgrls.toml` configuration schema; minor bumps may include
breaking changes — they will be called out in this file.

## [Unreleased]

## [0.6.7] - 2026-05-26

### Added

- **`pgrls report --format html` — standalone HTML audit page.**
  A self-contained HTML5 document (embedded CSS, no external
  CSS/JS, no `<link>` / `<script>` tags) suitable for archiving as
  an audit artefact, printing to PDF, or emailing to a reviewer
  who doesn't run pgrls. Renders the same per-table posture rows
  as the other formats with severity-coloured status pills, a
  summary band, and an ISO-8601 UTC generation timestamp.
  Identifiers are HTML-escaped — a malicious / quoted-identifier
  table name (`weird<name>&"`) can't break the layout or inject
  markup. Light / dark colour scheme via `prefers-color-scheme`.

## [0.6.6] - 2026-05-26

### Added

- **`pgrls lint --format pr-comment` — GitHub PR-comment formatter.**
  A Markdown variant tuned for the GitHub pull-request review
  reading context: findings group **by rule** (not by violation),
  each rule renders as a collapsible `<details>` block, the summary
  line carries a severity emoji + bold rule ID + count, and per-
  finding locations render as inline-code chips inside the block.
  A reviewer skims the top-line summary, expands the rule blocks
  they care about, and jumps to the rule reference link inline
  without leaving the PR. Existing `markdown` formatter stays the
  recommended choice for runbooks / wikis / non-PR Markdown
  surfaces — see the docstring of
  [`formatters/pr_comment.py`](src/pgrls/formatters/pr_comment.py)
  for when to prefer which.

## [0.6.5] - 2026-05-26

### Added

- **`[lint].extra_rules` — project-specific rules SDK.** A project
  can ship private rules without forking. List Python module dotted
  paths in `[lint].extra_rules`; each module exposes a `RULES`
  sequence of `Rule`-protocol objects. The loader (new
  `pgrls.rules.load_extra_rules`) imports, validates the shape, and
  merges into a per-invocation registry alongside built-ins. ID
  collisions between an extra and a built-in (or two extras) are
  caught at register time with a clear error. New `ExtraRulesError`
  exception type for the load-time failures (missing module,
  missing `RULES` attribute, non-iterable `RULES`, malformed rule
  shape). Documented in [`docs/EXTRA_RULES.md`](docs/EXTRA_RULES.md)
  — full consumer guide with a worked example.

- **Pre-commit recipe documentation
  ([`docs/recipes/precommit.md`](docs/recipes/precommit.md)).**
  `.pre-commit-hooks.yaml` shipped in v0.5.x; the recipe doc now
  makes the wiring discoverable. Covers the minimal config, the
  Supabase-local variant, the CI-only variant, and when to prefer
  the GitHub Action instead.

### Notes

- The `Rule` Protocol and `RuleRegistry` API are now formally
  promised as the public extension surface. Future API breaks
  here will be CHANGELOG-flagged.

## [0.6.4] - 2026-05-25

### Added

- **SEC037 — Policy compares `auth.role()` to an unknown role
  name.** Severity: warning. In the Supabase / PostgREST auth model
  `auth.role()` returns one of a small fixed set (`anon`,
  `authenticated`, `service_role`). A policy that compares
  `auth.role()` to anything outside that set silently denies every
  row — masking the broken policy because tests that seed admin
  data see no rows, devs assume the policy works, the table becomes
  inaccessible in prod. Walks policy USING / WITH CHECK ASTs for
  `=` comparisons between a role-context function (default:
  `auth.role`) and a string literal not in the configured
  known-roles set (default: `{anon, authenticated, service_role}`).
  Handles the `'admin'::text` form that Postgres normalizes
  literals to when storing policy expressions. Recognizes
  `SQLValueFunction` shapes (e.g., bare `current_user`) when
  `role_functions` is extended to include them. Configurable
  `known_roles` / `role_functions` / `allowlist`; no auto-fix
  (the right replacement is application-intent-dependent).

### Changed

- Rule catalog: **46 → 47 rules.**

## [0.6.3] - 2026-05-25

### Added

- **SEC034 — Policy gates on `auth.email()` (silent denial /
  lockout).** Severity: warning. Email-based row scoping has three
  silent failure modes: (1) Supabase email-change flow leaves the
  user locked out of their own data, (2) SQL `=` is case-sensitive
  while emails conventionally aren't, (3) plus-addressing makes
  `user+tag@host` and `user@host` compare unequal despite reaching
  the same inbox. Not a CVE-class exploit — this is denial of
  service to legitimate users — hence warning rather than error.
  Walks policy USING / WITH CHECK ASTs for FuncCall nodes whose
  name matches the configured email-context set (default:
  `auth.email`). Configurable `email_functions` / `allowlist`; no
  auto-fix (the column-key rewrite is application-side).

### Changed

- Rule catalog: **45 → 46 rules.**

## [0.6.2] - 2026-05-24

### Added

- **SEC036 — Policy `EXISTS (SELECT FROM auth.users WHERE …)`
  clause has no caller binding.** Severity: error. Catches the
  common Supabase auth-pattern bug where the per-user admin check
  is missing the `id = auth.uid()` clause, silently degrading to
  "is there ANY admin at all in the system" and passing for every
  authenticated user once a single matching row exists. Detection
  walks policy USING / WITH CHECK ASTs for `EXISTS_SUBLINK` nodes
  whose sub-select reads a configured target table (default:
  `auth.users`) without referencing any caller-binding function
  (`auth.uid`, `current_user`, `current_setting`, etc.).
  Configurable `target_tables` / `binding_functions` / `allowlist`;
  no auto-fix (the inner user-key column varies per schema).
  Same hazard class as SEC033 / SEC004 — deterministic, single-step,
  any authenticated user.

### Changed

- Rule catalog: **44 → 45 rules.**

## [0.6.1] - 2026-05-24

### Added

- **SEC033 — Policy scopes by user-modifiable JWT claim
  (`user_metadata` / `raw_user_meta_data`).** Severity: error. In
  the Supabase / PostgREST auth model `user_metadata` is end-user
  writable via the auth API (`supabase.auth.updateUser`), so a
  policy gating on a value pulled from it is self-bypassable: the
  authenticated user sets the field, the next JWT carries it, the
  policy reads it, the check passes. Same hazard class as SEC004
  (anonymous access via inverted auth check). Detection walks
  policy USING / WITH CHECK ASTs for `user_metadata` JSON keys (any
  of the `->`, `->>`, `#>`, `#>>` operator shapes) and for
  `raw_user_meta_data` column references. Configurable
  `string_keys` / `column_names` / `allowlist`; no auto-fix
  (rewriting to `app_metadata` requires application-side migration).
  Surfaced by the May 2026 PostgREST RLS-with-JWT-claims advisory.

### Changed

- Rule catalog: **43 → 44 rules.** Bumped `pyproject.toml`
  description and the README rule table.

## [0.6.0] - 2026-05-22

Milestone release. **No functional or breaking changes since 0.5.67.**
0.6.0 marks the 0.5.x line as a complete, stable RLS workflow
(find → fix → gate → test → adopt) and serves as the baseline for the
public launch. Pin `0.6.x` for the current CLI, snapshot-JSON, and
`pgrls.toml` surface.

For reference, what the 0.5.x line built up to (each shipped in its own
release listed below — nothing here is new in 0.6.0):
- **43 lint rules**, 12 mechanically auto-fixable.
- `pgrls report` — read-only RLS posture summary for audits and onboarding.
- Semantic `pgrls diff` CI gating (SAFE / BREAKING / REQUIRES_REVIEW /
  DANGEROUS), with optional Z3 predicate analysis and migration-as-input.
- CI-native output: text / JSON / SARIF / Markdown / GitHub annotations /
  JUnit XML.
- JSON Schema for `pgrls.toml`; zero-config `pgrls init` scaffolding.
- The `pgrls.testing` pytest plugin for RLS isolation tests.
- PyPI Trusted Publishing, plus a documented GitHub Actions CI recipe
  (`pgrls lint` with SARIF upload to code scanning).

## [0.5.67] - 2026-05-21

### Added
- **`pgrls report --output FILE`** — write the posture report to a file
  (any `--format`) instead of stdout, byte-for-byte identical to the
  piped output, mirroring `pgrls lint --output`. Handy for saving a
  Markdown posture snapshot into an audit doc. A missing parent
  directory surfaces as a clean error, not a traceback.

## [0.5.66] - 2026-05-21

### Added
- **`pgrls report`** — a new read-only command that summarizes the
  RLS posture of every table: per-table RLS enabled / `FORCE`'d /
  policy counts (permissive + restrictive) plus a coarse status
  (`protected` / `not-forced` / `no-policies` / `covered-by-parent` /
  `rls-off`) — `covered-by-parent` credits a declarative-partition child
  whose RLS-enabled ancestor is among the scanned schemas (rather than
  mislabeling it `rls-off`), and `no-policies` covers both zero-policy
  and restrictive-only (default-deny) tables — plus an aggregate
  summary. The rule-free
  counterpart to `pgrls lint` — a snapshot for audits and onboarding;
  it runs no rules and emits no findings. `--format text` (default) /
  `json` / `markdown`, reading a live database (or `$DATABASE_URL`).

## [0.5.65] - 2026-05-21

### Added
- **SEC031 auto-fix** — `pgrls fix` now remediates SEC031 (restrictive
  policy whose `USING` is constant `true`). It emits `DROP POLICY` for
  the no-op floor: `USING (true)` AND-combines to nothing, so dropping
  it leaves access unchanged (the same reasoning that makes HYG003's
  drop safe). SEC031's other remedy — giving the policy the real
  tenant / ownership predicate — needs human intent and is not
  auto-fixed; the fix description points the operator at it. Brings
  the mechanically-fixable rule count to **12**.

## [0.5.64] - 2026-05-21

### Added
- **JSON Schema for `pgrls.toml`** (`pgrls.schema.json`) — describes
  every config table (`extends`, `[database]`, `[lint]`,
  `[lint.rules.<ID>]` with `severity` + `allowlist`, `[diff]`) with
  descriptions, enums, and strict `additionalProperties` so editors
  autocomplete keys and flag typos / invalid values. `pgrls init` now
  writes a `#:schema` directive on the first line of the generated
  `pgrls.toml` (and `pgrls.example.toml` carries it too), which the
  Even Better TOML VS Code extension applies automatically. Point any
  JSON-Schema-aware TOML tooling at the published schema URL for the
  same validation.

## [0.5.63] - 2026-05-21

### Added
- **PERF004** — new lint rule (severity `warning`). Fires when a
  policy's `USING` / `WITH CHECK` clause wraps an own-table column in
  a function call (`lower(email) = current_setting('app.email')`)
  **and** the table carries an ordinary plain index on that column.
  Postgres can only use an index whose indexed expression matches the
  query expression, so the `lower(...)` wrapper makes the plain index
  unusable and the planner falls back to a sequential scan. The fix
  is an expression index matching the predicate (`CREATE INDEX ON
  users (lower(email))`) or rewriting the policy to compare the bare
  column. Scope is `FuncCall` wrapping only (the textbook
  functional-index case); `COALESCE`/`CASE`, operator expressions,
  and casts are deliberately out of scope. PERF004 is the precise
  complement of **PERF003** and disjoint from it on the index
  condition: PERF003 owns the *no index at all* case, PERF004 owns
  the *plain index exists but a function defeats it* case, so a
  column trips at most one. Allowlist by qualified policy ID under
  `[lint.rules.PERF004]`. Brings the shipped rule count to
  **forty-three**.

## [0.5.62] - 2026-05-21

### Added
- **SEC032** — new lint rule (severity `error`). Fires for a table
  that has policies but has **not** been switched on with `ALTER
  TABLE ... ENABLE ROW LEVEL SECURITY`. Postgres keeps `pg_policy`
  rows independently of the table-level switch, so the policies sit
  **dormant** — they enforce nothing and the table is readable by
  every role with the table-level privilege, despite *looking*
  RLS-managed in code review. The classic "forgot `ENABLE ROW LEVEL
  SECURITY`" footgun, and a high-confidence one (a table carrying
  hand-written policies clearly intends RLS). The fix is `ALTER TABLE
  ... ENABLE ROW LEVEL SECURITY` (add `FORCE` if owner access must be
  governed). Allowlist by table name. No auto-fix. Like SEC001 it
  skips a partition child already covered by an RLS-enabled ancestor.
  Brings the shipped rule count to **forty-two**.

### Changed
- **SEC001 now cedes policy-bearing tables to SEC032.** It previously
  fired on *every* RLS-disabled table; a table with RLS off **and**
  policies is now SEC032's (dormant policies — a higher-confidence,
  more specific finding), while a bare RLS-off table with no policies
  stays SEC001's. The two are disjoint, so a given RLS-off table
  trips exactly one. No detection coverage is lost.

## [0.5.61] - 2026-05-21

### Added
- **SEC031** — new lint rule (severity `warning`). Fires for a
  **RESTRICTIVE** policy whose `USING` is the literal `true`.
  Restrictive policies AND-combine, so `USING (true)` adds `AND true`
  to the conjunction and restricts **nothing** — the policy looks
  like a security floor (someone added it to tighten access) but is
  inert; every row a permissive policy admits sails through. The
  danger is the false sense of security. The fix is to give the
  policy the real predicate it was meant to enforce, or drop it.
  Allowlist by qualified policy ID. No auto-fix. Brings the shipped
  rule count to **forty-one**.

### Changed
- **SEC008 is now scoped to permissive policies.** It previously
  fired on *any* `USING (true)` policy, but its message ("admits
  every row to every caller") is only accurate for a **permissive**
  policy — a restrictive `USING (true)` fails to *restrict* rather
  than admitting everything. The restrictive case now belongs to the
  new SEC031 with an accurate "no-op floor" message; SEC008 and
  SEC031 are disjoint by policy kind, so a given policy still trips
  exactly one. No detection coverage is lost — a restrictive
  `USING (true)` that previously surfaced as SEC008 now surfaces as
  SEC031.

## [0.5.60] - 2026-05-21

### Added
- **`pgrls.toml` `extends`.** A config can layer on top of a shared
  base with a top-level `extends` key — a path, or a list of paths,
  resolved relative to the file that declares it. Useful for a
  monorepo or an org-wide ruleset. Tables deep-merge key-by-key (a
  child can set `[lint.rules.SEC001].severity` while inheriting the
  base's `allowlist`); scalars and arrays are *replaced*, not
  appended (a child `disable` / `allowlist` list wins wholesale, so
  there are no surprise accumulations). For a list, later entries
  override earlier ones, and the declaring file overrides every base.
  Env-var interpolation runs after the merge. A missing target, a
  non-string/list value, and a cycle in the `extends` chain each
  raise a clear config error; a base reached twice through different
  paths (a diamond) is allowed.

## [0.5.59] - 2026-05-21

### Added
- **`pgrls lint --exclude-rule`.** The complement of `--rule`: run
  every rule *except* the named ones (repeatable, case-insensitive).
  Applied after `--rule`, so the two cannot name the same rule (that
  errors), and unknown ids are rejected like `--rule`'s.
- **`pgrls lint --min-severity {error|warning|info}`.** Trims the
  printed report to findings at or above the given severity — useful
  for hiding info-level nudges from CI logs. Display-only: the exit
  code still evaluates *every* finding against `--fail-on`, so a
  hidden finding can never silently flip CI green.
- **`pgrls lint --output FILE` / `-o`.** Write the report (in any
  `--format`) to a file instead of stdout — byte-for-byte what stdout
  would have received. Cannot be combined with `--update-baseline`
  (which prints no report).

## [0.5.58] - 2026-05-21

### Added
- **`pgrls explain --format json`.** A third output format for the
  rule-reference command (alongside `text` and `markdown`), emitting
  machine-readable rule metadata for IDE / tooling integrations. A
  single rule (`pgrls explain SEC023 --format json`) yields
  `{id, severity, title, fixable, reference}` — `fixable` flags
  whether `pgrls fix` can auto-remediate it, and `reference` carries
  the full rule body so a consumer gets everything `--format text`
  shows. The catalog (`pgrls explain --format json`) yields
  `{pgrls_version, count, rules: [{id, severity, title, fixable}]}` —
  compact per-rule entries, mirroring the text and Markdown catalogs.
  Needs no database connection.

## [0.5.57] - 2026-05-21

### Added
- **`pgrls lint --format junit`.** New JUnit XML output so lint
  findings surface in a CI run's test-report UI (GitLab, Jenkins,
  CircleCI, Buildkite, GitHub test-reporter actions). One
  `<testcase>` per finding under a single `pgrls` suite — `classname`
  is the rule id, `name` is `"<rule id> <location>"`, and each is a
  `<failure>` whose `type` is the pgrls severity, `message` the rule
  title, and element text the full finding message. A clean run emits
  a well-formed empty suite (`tests="0"`). Warning- and info-level
  findings are reported as failures too — the report shows everything
  the lint found, and the process exit code (`--fail-on`), not the
  report, gates the build. All values are XML-escaped and run through
  the shared control-char sanitiser, so a crafted Postgres identifier
  can't produce malformed XML.

## [0.5.56] - 2026-05-21

### Added
- **`pgrls init`.** New command that writes a commented starter
  `pgrls.toml` documenting the common knobs — `[database]` url /
  schemas, `[lint]` fail_on / disable, a per-rule `allowlist` and
  `severity` override example, and `[diff]` fail_on. The generated
  file parses as-is and leaves every setting at its default, so
  `pgrls lint` runs unchanged against it; `[database].url` is left
  commented so a fresh file doesn't trip an env-var error before
  `DATABASE_URL` is wired up. Refuses to clobber an existing file
  unless `--force`; `--output` chooses the path (default
  `./pgrls.toml`).

## [0.5.55] - 2026-05-21

### Added
- **SEC030** — new lint rule (severity `info`). Fires when a policy
  scopes row access by a **nullable** discriminator column — a column
  compared with a plain `=` against a per-request auth value
  (`current_setting`, `auth.uid`, `auth.role`, `auth.jwt` by
  default). Under standard `=` semantics a row whose discriminator is
  `NULL` evaluates `NULL = <value>` → `NULL`, so it is silently
  invisible to every tenant (a row that belongs to no one); and it
  becomes a cross-tenant leak the moment any policy uses a
  NULL-tolerant form (`IS NOT DISTINCT FROM`, `… OR col IS NULL`,
  `COALESCE(col, …)`). The remedy is `SET NOT NULL` on the
  discriminator (after backfilling). Detection is conservative: only
  scalar `=` (not `<>`, range operators, or array-membership `=
  ANY`); the column must be a direct operand, but the auth value is
  detected even when wrapped in the `(SELECT current_setting(…))`
  form PERF001 recommends; own-table columns only; tables without
  captured column nullability (pre-v5 snapshots) are skipped.
  Complements SEC018 (wrong discriminator *type*) and SEC027 (no
  discriminator at all) — the three are disjoint. Configure the
  auth-context set via `[lint.rules.SEC030].auth_functions`; allowlist
  intentionally-nullable discriminators by table name. No auto-fix —
  `SET NOT NULL` needs a backfill pgrls can't author. Brings the
  shipped rule count to **forty**.

## [0.5.54] - 2026-05-21

### Added
- **SEC029** — new lint rule (severity `warning`). Fires when a role
  can `SET ROLE` to a `BYPASSRLS` role through membership — an
  RLS-bypass *path* that is invisible from the role's own attributes.
  `BYPASSRLS` is a role attribute, and attributes (unlike object
  privileges) are **never inherited** through membership, even with
  `INHERIT`; SEC016, which flags the *holder* of the attribute, stays
  silent on a mere member. But membership grants `SET ROLE`: a member
  — directly or transitively — of a BYPASSRLS role can switch into it
  and bypass every policy for the rest of the session. SEC029
  computes the transitive `pg_auth_members` closure, skips roles that
  already hold BYPASSRLS (SEC016's surface) and superusers, and names
  the reachable BYPASSRLS target; `LOGIN` members are called out
  specially since an application authenticating as one is a single
  `SET ROLE` from a full bypass. Detection treats every membership
  edge as `SET ROLE`-capable (it can over-report a PG16+ `WITH SET
  FALSE` grant — a deliberate bias toward surfacing the route over
  missing it, and it keeps the introspection query identical across
  PG15-17). Allowlist the *member* role by name in
  `[lint.rules.SEC029]` when the membership is intentional. No
  auto-fix — revoking, narrowing, or accepting the route is an
  operational decision. Brings the shipped rule count to
  **thirty-nine**.

### Changed
- **Snapshot schema → version 11.** Adds a top-level
  `bypassrls_escalation_roles` array (the transitive membership
  closure SEC029 reads). The bump is additive: v3–v10 snapshots load
  unchanged (the new field defaults empty), and a pre-v11 snapshot
  produces no SEC029 findings until it is re-captured against a live
  database.

## [0.5.53] - 2026-05-21

### Added
- **SEC028** — new lint rule (severity `warning`). Fires when a
  **permissive** write policy (`FOR INSERT` / `FOR UPDATE` /
  `FOR ALL`) has a `WITH CHECK` clause of literal `true` and no
  restrictive `USING` to contrast with — the open-write footgun
  the existing rules miss. A `FOR INSERT ... WITH CHECK (true)`
  policy accepts every write the command covers: the `TO` clause
  gates *who* may write, never *what*, so any applicable role can
  insert a row with any tenant id, owner, or value.

  The gap: SEC006 fires on a *missing* `WITH CHECK`; SEC008 flags a
  constant-true `USING` (and never inspects the write side); SEC020
  flags the *asymmetry* of `WITH CHECK (true)` alongside a real
  restrictive `USING`. SEC028 is the complement — there's no
  restrictive `USING` (absent on `FOR INSERT`, or itself
  constant-true), so the write side is open outright. The
  asymmetry case is explicitly ceded to SEC020; restrictive
  policies are out of scope (a restrictive `WITH CHECK (true)` is a
  dead clause, not an exposure). Allowlist by qualified policy ID
  for an intentional open write side (append-only audit/event
  table). No auto-fix — the correct write predicate is the
  application's tenant/ownership key. Brings the shipped rule count
  to **thirty-eight**.

## [0.5.52] - 2026-05-20

### Added
- **`pgrls lint --format github`.** Emit GitHub Actions workflow
  commands — one `::error` / `::warning` / `::notice` per finding —
  so lint results surface as **annotations** on a GitHub Actions
  run. Severity maps error→`::error`, warning→`::warning`,
  info→`::notice` (GitHub has no "info" level). The annotation
  `title` carries the rule id and qualified location; the command
  body is the violation message, escaped per GitHub's
  workflow-command rules (`%`, CR, LF in the message; additionally
  `:` and `,` in the title) so a percent sign, newline, or a
  colon inside a quoted Postgres identifier can't terminate the
  command early.

  The format deliberately omits `file=` / `line=`: pgrls lints a
  live database, not source text, and has no reliable mapping from
  a policy back to the migration file/line that defined it, so the
  annotations render in the run's annotation summary (surfaced on
  the PR's Checks tab) rather than pinned to a diff hunk. A clean
  run emits nothing — no annotations is the correct signal for "no
  findings", and the exit code already distinguishes clean from
  dirty. Lint-only for now (the `pgrls diff` formats are
  unchanged).

## [0.5.51] - 2026-05-20

### Added
- **`pgrls fix` now auto-remediates SEC011** ("policy expression
  has an `OR true` branch"). The fixer emits `ALTER POLICY <name>
  ON <schema>.<table>` with `USING (…)` and/or `WITH CHECK (…)`,
  removing the literal-`true` disjunct from each OR `BoolExpr` and
  unwrapping an OR that collapses to a single remaining arg
  (`owner_id = current_setting('app.user') OR true` →
  `owner_id = current_setting('app.user')`). Nested ORs are handled
  bottom-up; only the clause(s) that actually changed are re-emitted
  (minimal diff); the mutation runs on a deep-copy so the rule's
  `Schema` view stays read-only. `pgrls fix` now covers eleven
  rules: SEC001, SEC002, SEC006, SEC011, SEC019, SEC020, PERF001,
  PERF003, HYG003, VIEW001, VIEW002.

  The strip happens only in *monotone* position — reachable from
  the clause root through AND / OR chains, where `P OR true` is
  absorbing and removing the `true` can only narrow the policy. The
  fixer never descends past a `NOT`, a comparison, an `IS FALSE`
  test, a function call, or a SubLink: under a negation, tightening
  an OR would *broaden* access (`NOT (a OR true)` is deny-all,
  `NOT a` is not), and a security fixer must never widen a policy.
  The rule still flags `OR true` in those positions; the fixer
  declines to rewrite them and leaves the finding for human review.

  Opinionated in the same way the SEC019 fixer is: removing
  `OR true` assumes the disjunct was a leftover debug bypass (the
  case SEC011 targets), not a deliberate "admit every row." A
  policy that genuinely means to admit every row should drop the
  policy or disable RLS rather than bury a constant-true in the
  predicate; an operator who wants to keep the literal allowlists
  the policy in `[lint.rules.SEC011]`. A degenerate predicate that
  is *only* literal-trues (`true OR true`) has no real predicate to
  fall back on, so the fixer skips it and leaves the finding for
  human review rather than emit an empty `USING ()`.

## [0.5.50] - 2026-05-20

### Added
- **SEC027** — new lint rule (severity `info`). RLS isn't only
  about tenant isolation; within a single tenant, rows are often
  per-user (drafts, DMs, private uploads). SEC027 fires when a
  table has RLS enabled, carries at least one policy, has a
  principal-identity column (`owner`, `owner_id`, `user_id` by
  default), and no policy references that column. The canonical
  miss: a table scoped only by `tenant_id` while an `owner_id`
  column goes unreferenced, so every user *within* a tenant reads
  every other user's rows.

  Deliberately conservative: only flags tables that already have a
  policy (no-policy is SEC009's surface); treats a column as scoped
  if any policy references it anywhere, including inside a
  sub-select (under-fires on the legitimate membership-join ACL
  pattern rather than over-firing); and the default principal set
  excludes audit-style columns (`created_by`, `updated_by`,
  `author_id`) since those are usually provenance, not access
  boundaries. Configure via `[lint.rules.SEC027].principal_columns`
  (replaces the default) and allowlist tenant-shared tables via
  `[lint.rules.SEC027].allowlist`. Info severity, so it never fails
  CI by default — it's a "did you mean to scope by user too?"
  prompt, not an assertion. No auto-fix (the remedy is an intent
  decision). Brings the shipped rule count to **thirty-seven**.

### Changed
- **Repositioned from "multi-tenant" to "per-principal" framing.**
  The README hero, the "Real-world bugs" section, and the PyPI
  description led with multi-tenant SaaS, which undersold the tool:
  the same bug class (broken row scoping, missing WITH CHECK,
  inverted auth) bites *within* a single tenant whenever rows are
  per-user. The lede now leads with "broken row scoping (across
  tenants and between users in the same tenant)", the Real-world
  section gains a single-tenant user-leak example next to the
  cross-tenant one, and the PyPI summary reads "tenant and per-user
  row-scoping bugs". No behaviour change in any existing rule — the
  engine was already principal-agnostic (it lints predicate
  structure, not the specific discriminator column); this release
  makes the framing match the coverage and adds SEC027 to catch the
  under-scoping case explicitly.

## [0.5.49] - 2026-05-20

### Changed
- **Project maturity signals.** Several public-facing surfaces were
  under-selling the project's actual state — 5 GitHub stars, an
  "Alpha" classifier, and a "Status: 0.5.48" version-as-label
  combined to read like a weekend hack despite ~2.4k monthly
  PyPI downloads, 1,593 tests, and a stable JSON / SARIF schema
  shipped across 49 releases. This release tightens the read:

  - **`Development Status :: 3 - Alpha` → `4 - Beta`** in
    `pyproject.toml` classifiers — PyPI's project page and search
    listings now reflect the shipped surface.
  - **README hero quick-link bar** under the badges
    (`23-second demo · Rule reference · CHANGELOG · PyPI`) so
    a first-time reader has one click to whatever they came for.
  - **"Status:" blockquote replaced** with a "Beta — actively
    maintained" line that names the version surface (36 rules,
    10 auto-fixable, PG 15-17 tested, stable JSON/SARIF schema)
    rather than a brittle version number.
  - **New `## Real-world bugs pgrls catches` section** in the
    README — opens with the Lovable RLS CVE shape walkthrough
    and shows the actual `pgrls lint --rule SEC004 --explain`
    output. Replaces "trust me, 36 rules" with one concrete
    bug a reviewer can scan in 15 seconds.

### Added
- **`SECURITY.md`** — vulnerability disclosure policy
  (`dmitrymaranik@gmail.com`, 5-business-day acknowledgement),
  scope (rules, fixer output, diff classification, formatters,
  pytest plugin), out-of-scope (upstream PostgreSQL / pglast).
- **`CONTRIBUTING.md`** — local dev setup, rule-number
  conventions (`SEC0NN` append-only, never reuse a deprecated
  rule's number), what reviewers look for (AST traversal
  correctness, `pg_get_expr` round-trip stability, test
  coverage), no-Claude-attribution norm.

No functional changes — schema, AST, rule behaviour, fixer
output, diff classification are all identical to v0.5.48.

## [0.5.48] - 2026-05-20

### Changed
- **Real screencast SVG.** Replaced the static placeholder
  `docs/screencast.svg` with an animated cast generated by
  `termtosvg` from the recipe in `docs/screencast.md`
  (Docker Postgres, five intentional bugs, five-scene demo:
  install / lint / explain / fix / diff). 25-second animation,
  21 KB. The README `<a>` link now points at the raw SVG in
  the repo (clicking opens the animation in a browser; GitHub's
  `<img>` sandbox renders the first frame as a static preview)
  rather than the prior `asciinema.org/REPLACE_AFTER_UPLOAD`
  placeholder. The asciinema-cast recipe in
  `docs/screencast.md` remains the recommended path for a
  polished human-paced re-record after a feature ships.

## [0.5.47] - 2026-05-20

### Changed
- **README hero rewrite (cosmetic).** Replaced the prior
  single-paragraph hero with a tighter four-line lede that leads
  with the value prop, names the diff-classification axis, and
  closes with the framework/output-format range — the four lines
  the reader needs before deciding to scroll. Added a centered
  screencast placeholder (`docs/screencast.svg`) above the
  status blockquote so the hero now reads as *lede → demo →
  release status*. The placeholder links to an asciinema cast ID
  that's filled in after the actual recording lands; see
  `docs/screencast.md` for the recording recipe (Docker fixture,
  asciinema commands, upload-and-embed steps).
- **New: `docs/screencast.md`.** Copy-paste-able recording
  recipe: prereqs, throwaway-Postgres fixture, five scene
  scripts (install / lint / explain / fix / diff), upload and
  embed steps. Target cast length 60–75 seconds. The recipe
  exists in the repo so future re-records (after every major
  feature) follow the same shape.

## [0.5.46] - 2026-05-20

### Changed
- **PyPI / README polish (cosmetic).** Tightened the `description`
  field in `pyproject.toml` so the PyPI search summary and
  `pip show` output read as "Static analyzer for Postgres
  Row-Level Security — 36 lint rules across security,
  performance, and hygiene; 10 mechanically auto-fixable;
  semantic policy-diff command for CI gating; pytest plugin for
  RLS isolation tests." rather than the prior generic
  "Framework-agnostic linter and testing toolkit ..." Added a
  hero badge block to the README (PyPI version, supported Python
  versions, license, CI status, monthly downloads) and a
  punchier one-paragraph lede so the README — which PyPI renders
  as the project description — leads with the value proposition
  before the feature list. No functional changes.

## [0.5.45] - 2026-05-20

### Fixed
- **Docs.** The SEC020 per-rule section in AGENTS.md still
  carried `**Auto-fix:** no (whether an open write side is
  intentional — e.g. an append-only audit table — is a design
  choice; pgrls surfaces the asymmetry but will not rewrite the
  policy)` — wording inherited from the pre-fixer state. SEC020
  has had a fixer since v0.5.33 (the `## Auto-fix: pgrls fix`
  section enumerates it), so the per-rule line directly
  contradicted the rest of the file. Drop the stale sentence so
  the SEC020 header matches the convention every other
  auto-fixable rule uses (`**Severity:** xxx.` only, no Auto-fix
  marker — the canonical roster lives in the dedicated section).

## [0.5.44] - 2026-05-20

### Added
- **SEC026** — new lint rule (severity `warning`). Fires when a
  policy's `USING` or `WITH CHECK` expression combines a
  **pattern-matching operator** — `LIKE`, `ILIKE`, `SIMILAR TO`,
  or POSIX regex (`~`, `~*`, `!~`, `!~*`) — with an
  **auth-context function** (`current_setting`, `auth.uid`,
  `current_user`, ...) on either operand. Pattern wildcards in
  an attacker-controllable value make the predicate degenerate:
  a GUC set to `%` (the empty LIKE pattern) or `.*` (regex
  match-everything) matches every row, defeating per-row
  isolation entirely.

  Detection matches by **operator name** rather than
  `A_Expr.kind`, so a literal `LIKE` source and a
  `pg_get_expr`-deparsed policy (which renders `LIKE` as `~~`)
  trip the rule the same way — pgrls introspects via
  `pg_get_expr`, so name-based detection is the round-trip-stable
  path. Both operand directions fire (`col LIKE auth`,
  `auth LIKE col`). SubLink-wrapped auth values fire too —
  `col LIKE (SELECT current_setting('app.email', true))` is
  semantically identical to the un-wrapped form, and the PERF001
  wrap pattern does not close this hole. Each policy is reported
  once even when both clauses or both operand directions match.

  The default auth-function set mirrors PERF001's
  (`auth.uid`, `auth.role`, `auth.jwt`, `current_setting`) plus
  the role-identity grammar-specials (`current_user`,
  `current_role`, `user`, `session_user`). Replace via
  `[lint.rules.SEC026].auth_functions`. Allowlist by qualified
  policy ID via `[lint.rules.SEC026].allowlist`. No auto-fix —
  the remedy (`lower(col) = lower(current_setting(...))` or
  plain `=`) is a design choice, not mechanical.

  Brings the shipped rule count to **thirty-six**.

## [0.5.43] - 2026-05-19

### Added
- **`pgrls diff --explain`.** Append a one-paragraph rationale
  beneath each classified Change in the text output, explaining
  why the kind carries the classification it does — why dropping
  a PERMISSIVE policy is BREAKING (access narrows) rather than
  DANGEROUS, why disabling RLS is the single most dangerous diff
  signal pgrls reports, why a column drop while still referenced
  is REQUIRES_REVIEW. Each rationale is one sentence to one short
  paragraph — long enough to stand alone in a CI log without
  burying the diff payload.

  The rationale table lives in
  `src/pgrls/diff/formatters.py` keyed by
  `(ChangeKind, Classification)` — RLS_FLIPPED and
  FORCE_RLS_FLIPPED reuse one kind for both directions (on→off
  DANGEROUS, off→on SAFE), but the two directions get different
  rationales. An import-time check verifies every `ChangeKind`
  the differ can emit has at least one rationale entry, so a
  future kind added without a rationale fails at module import
  rather than silently degrading `--explain`.

  Text format only — JSON / SARIF already carry the
  classification tag as a structured field, so the flag is a
  silent no-op for those formats (mirrors how
  `pgrls lint --explain` behaves). A `(kind, classification)`
  pair with no rationale entry degrades silently in the same
  way `pgrls lint --explain` degrades for rules whose docstring
  is missing.

## [0.5.42] - 2026-05-19

### Added
- **`pgrls fix` now auto-remediates SEC019** ("policy calls
  current_setting() without the missing_ok argument"). The
  fixer emits `ALTER POLICY <name> ON <schema>.<table>` with
  `USING (…)` and/or `WITH CHECK (…)`, rewriting each
  one-argument `current_setting('x')` call to `current_setting
  ('x', true)`. The two-argument overload returns NULL on an
  unset GUC instead of erroring; the rewrite picks the
  quiet-NULL side, matching the overload most policy sets
  converge on. `pgrls fix` now covers SEC001, SEC002, SEC006,
  SEC019, SEC020, PERF001, PERF003, HYG003, VIEW001, and
  VIEW002 — ten fixers.

  Only the clause(s) that actually contained a one-argument
  call are re-emitted in the `ALTER POLICY`, so the produced
  migration is the minimal diff (USING-only when only USING
  changed; WITH CHECK-only when only that side changed; both
  when both changed). The pg_catalog-qualified
  `pg_catalog.current_setting(...)` form is matched too. The
  AST mutation happens on a deep-copy of the policy's AST so
  the rule's `Schema` view stays read-only — fixer invariant.

  SEC019 is **info** severity precisely because the choice
  between overloads is judgement: the loud raise surfaces a
  missing-context bug immediately, while the quiet empty
  result is friendlier but can mask it. The Fix description
  spells out that the rewrite picks the quiet-NULL side and
  points operators who genuinely want raise-on-unset at
  `[lint.rules.SEC019].allowlist`. Run `pgrls fix --check
  --rule SEC019` first to preview the affected policies.

## [0.5.41] - 2026-05-19

### Added
- **`pgrls lint --update-baseline`.** Refresh the baseline file
  in place with the current findings — accept every current
  finding as the new baseline, without the "delete the file and
  re-run" two-step dance the previous workflow required. Pair
  with `--baseline FILE` to name the target. Suppresses normal
  lint output, prints a `pgrls: updated baseline at <file> with
  N finding(s).` status line to stderr, and exits 0 on success.

  Semantics are **replace, not merge**: the baseline reflects
  the current state of the database, so entries for findings
  that no longer fire (a rule fixed, a table renamed, an
  allowlist added in config) naturally drop. That makes the
  flag suitable as the pre-commit / CI gesture for "I've
  audited the new findings and accept them all" — one
  invocation that's idempotent against a clean DB and a
  full-rewrite against a stale baseline. Without `--baseline`
  to name the file, `--update-baseline` is a tool error.

## [0.5.40] - 2026-05-19

### Added
- **`pgrls explain --format markdown`.** Emit the rule reference
  (or the catalog) as a Markdown document instead of plain text,
  so the output is paste-ready for a project runbook, wiki, or
  generated docs site. Per-rule: `## <ID> — <title>` heading,
  a `**Severity:**` line, then the rule's reference body
  (docstring minus its title line — already in the heading).
  Catalog: an `# pgrls rule catalog` header, a one-line
  description naming the pgrls version and rule count, then a
  Markdown table with ID / Severity / Title columns.

  Rule docstrings already use Markdown-friendly conventions
  (fenced ``` blocks, `**bold**`, `*` bullets), so they render
  cleanly without further transformation. Default remains
  `text`; `--format` accepts `text` or `markdown`, anything else
  is a Click usage error.

## [0.5.39] - 2026-05-19

### Added
- **`pgrls lint --explain`.** Appends each rule's reference
  paragraph beneath its finding in the text output, so a CI log
  carries the *why* next to the *where* without a separate
  `pgrls explain <RULE>` lookup. The rationale is the first
  paragraph of the rule's module docstring (the same source
  `pgrls explain` uses), indented to align with the finding's
  message so the block reads as one continuous note.

  Text format only. JSON / SARIF / Markdown keep their schemas
  stable — `--explain` is a no-op there. A rule whose docstring
  is absent (e.g. `python -OO` stripped them) or doesn't follow
  the two-paragraph convention degrades gracefully: the finding
  renders without an added block.

  The implementation extends `format_violations` with an
  optional `rationale_map: dict[str, str]` kwarg; the lint
  command builds the map only for rule IDs that produced a
  finding, so the work scales with the output, not the catalog.

## [0.5.38] - 2026-05-19

### Added
- **SEC025 — policy predicate references a table that has RLS
  disabled** (severity: warning). Flags a policy whose `USING`
  / `WITH CHECK` references another table — typically through
  a sub-select — whose `rls_enabled` is false within the
  introspected schema set. The row-level isolation on the
  policy's own table is only as strong as the referenced
  table's isolation: every column of it is freely readable
  (and, if the role has INSERT, freely writable), so an
  attacker who can write to the referenced table can grant
  themselves access through the policy.

  Detection is a structural cross-reference rather than an AST
  pattern: walk the parsed policy expression for `RangeVar`
  nodes, resolve each against the introspected schema, and fire
  when the resolved table has `rls_enabled = false`.
  Self-references (a policy on `T` reading `T`) are skipped —
  they inherit the same RLS gate. Views are skipped — that is
  VIEW001 / VIEW002's surface. Out-of-scope references (tables
  outside `--schemas`, `pg_catalog.*`) are skipped — pgrls
  cannot know their RLS state. The pattern is sometimes
  intentional (a read-only reference table such as countries,
  plan types, feature flags), so severity is **warning** and
  allowlistable by qualified policy ID.

### Changed
- **Rule count: thirty-four → thirty-five** (`SEC001`–`SEC025`,
  `PERF001`–`PERF003`, `HYG001`–`HYG003`, `VIEW001`–`VIEW004`). No
  snapshot-format change — SEC025 reads the policy's `USING` /
  `WITH CHECK` SQL text (re-parsed on demand) and the captured
  `rls_enabled` flag, both part of the snapshot format since
  v1, so `SNAPSHOT_VERSION` stays at 10.

## [0.5.37] - 2026-05-19

### Added
- **`pgrls fix --check`.** A CI gate: exits 1 if any auto-fixable
  violations would be emitted, 0 otherwise. No SQL is emitted
  and the database is unchanged — the run is read-only. The
  pattern mirrors `ruff format --check` and `prettier --check`:
  drop the flag into a pre-commit hook or a CI step and the
  build fails when an auto-fixable violation creeps in, prompting
  the author to run `pgrls fix --apply` (or `--output
  migration.sql`) themselves.

  The offending `(rule_id, location)` pairs go to **stdout** so
  `pgrls fix --check > violations.log` captures them as a CI
  artefact; the summary count and next-step hint go to stderr.
  The same split `pgrls lint` (and `ruff --check`) use.

  `--check` cannot be combined with `--apply` (which applies
  the fixes) or `--output` (which writes a migration file) —
  one gates, the others mutate. The flag composes with `--rule`
  to gate on a subset of fixers and with `--config` and
  `--schemas` like every other `fix` flag.

## [0.5.36] - 2026-05-19

### Added
- **`pgrls explain` (no argument) lists the rule catalog.** A
  one-line-per-rule view of the shipping rule set — ID,
  severity, and title, padded into columns — handy for scanning
  what pgrls covers at a glance. The per-rule reference is one
  argument away (`pgrls explain SEC023`). Both forms read only
  pgrls's built-in rule catalog, so they work offline anywhere.

  Previously bare `pgrls explain` was a usage error (the RULE
  argument was required); the argument is now optional and
  defaults to "list the catalog".

## [0.5.35] - 2026-05-19

### Added
- **`pgrls lint --rule <ID>`.** A repeatable flag that scopes a
  lint run to specific rule IDs (case-insensitive). Handy when
  scoping a SARIF report in CI to a subset of the catalog, or
  while investigating one rule in isolation. The flag mirrors
  `pgrls fix --rule` for CLI consistency:

  ```bash
  pgrls lint --rule SEC001 --rule SEC003
  ```

  `--rule` is an explicit "run only these" — it **overrides**
  `[lint] disable` in the config, so an operator can pull a
  disabled rule back in for one run without editing the config.
  Per-rule allowlists and severity overrides still apply. An
  unknown rule ID is a tool error (exit 2) with the list of
  every known rule, matching the validation `pgrls fix --rule`
  already does.

## [0.5.34] - 2026-05-19

### Added
- **SEC024 — policy calls current_setting() with an unqualified
  parameter name** (severity: info). Flags a policy whose
  `USING` / `WITH CHECK` calls `current_setting()` with a
  string-literal parameter name containing no `.`. A customized
  run-time parameter (the per-request context an RLS policy
  reads) must be **qualified** — `prefix.name` — to namespace it
  away from Postgres's own settings; an unqualified name cannot
  be `SET` as a customized parameter at all. So the policy reads
  either a built-in server setting or a name that can never be
  set, and the predicate quietly matches no rows (two-argument
  form) or errors on every query (one-argument, which SEC019
  separately flags). This is almost always a dropped prefix:
  the application sets `app.tenant_id` but the policy reads
  `tenant_id`.

  Detection walks the parsed policy expression for
  `current_setting` calls (including those wrapped in `(SELECT
  current_setting(...))`) and inspects the first argument.
  Postgres deparses a string-literal argument with an explicit
  `::text` cast, so the introspected node is a `TypeCast`
  wrapping the `A_Const`; SEC024 unwraps it before reading the
  literal. Dynamic names — a column reference, a concatenation
  — are not inspected. Severity is **info**: a policy may key
  off a built-in parameter (e.g. `application_name`), which is
  unqualified by definition, so SEC024 surfaces the unqualified
  shape as a review nudge rather than a hard finding. Allowlist
  by qualified policy ID (`schema.table.policy_name`). SEC019
  (arity) and SEC024 (name shape) are orthogonal; a single
  policy can carry one without the other or trip both.

### Changed
- **Rule count: thirty-three → thirty-four** (`SEC001`–`SEC024`,
  `PERF001`–`PERF003`, `HYG001`–`HYG003`, `VIEW001`–`VIEW004`). No
  snapshot-format change — SEC024 reads the policy's `USING` /
  `WITH CHECK` SQL text (part of the snapshot format since v1)
  and re-parses it on demand, so `SNAPSHOT_VERSION` stays at 10.

## [0.5.33] - 2026-05-19

### Added
- **`pgrls fix` now auto-remediates SEC020** ("policy WITH CHECK
  is constant true but USING is not"). The fixer emits `ALTER
  POLICY <name> ON <schema>.<table> WITH CHECK (<the USING
  predicate>);`, replacing a wide-open `WITH CHECK (true)` with
  the policy's own read predicate so writes are constrained the
  same way reads are. `pgrls fix` now covers SEC001, SEC002,
  SEC006, SEC020, PERF001, PERF003, HYG003, VIEW001, and VIEW002.

  Unlike the SEC006 fixer, the SEC020 fixer also remediates
  restrictive policies: a SEC020 finding always carries an
  explicit `WITH CHECK (true)` and a real `USING`, so mirroring
  USING is a meaningful tightening either way — a permissive
  policy's open write side becomes scoped, and a restrictive
  policy's no-op `… AND true` write check becomes a real
  constraint. SEC006 (missing `WITH CHECK`) and SEC020 (`WITH
  CHECK` present and constant-true) never fire on the same
  policy. Detection is shared with the SEC020 rule via
  `_is_open_write_asymmetry`, so the fixer remediates exactly
  what the rule reports.

## [0.5.32] - 2026-05-19

### Added
- **`pgrls explain <RULE>`.** A new subcommand that prints a lint
  rule's full reference — its severity, what it flags, why that is
  a problem, how detection works, what is deliberately out of
  scope, and how to allowlist an intentional case — straight to
  the terminal. `pgrls explain SEC023`, `pgrls explain perf001`;
  the rule ID is matched case-insensitively.

  The explanation is the rule's own in-tree documentation, so it
  cannot drift from the implementation. `explain` reads only
  pgrls's built-in rule catalog — no database connection and no
  config file — so it works offline, anywhere. An unrecognized
  rule ID is a tool error (exit 2) and the message lists every
  known rule.

## [0.5.31] - 2026-05-19

### Added
- **SEC023 — policy applies to a role that bypasses RLS**
  (severity: warning). Flags a policy whose `TO` clause names a
  role carrying the `BYPASSRLS` attribute. A `BYPASSRLS` role
  skips every row-level security policy on every table, so the
  policy's `USING` / `WITH CHECK` predicate is never evaluated for
  it — the `TO` clause is inert. The policy looks like it scopes
  that role's access; it does not constrain it at all, a quiet
  false sense of security.

  Detection is a cross-reference between each policy's `TO` list
  and the schema's set of `BYPASSRLS` roles — no predicate
  analysis. `TO PUBLIC` is not flagged: `PUBLIC` is the
  pseudo-role meaning "every role", not a bypassing role, and
  firing on every public policy in a schema that contains a
  `BYPASSRLS` role would be noise — SEC023 fires only when a
  policy names the bypassing role outright. Superuser roles are
  skipped, mirroring SEC016. Allowlist by qualified policy ID
  (`schema.table.policy_name`) when naming a bypassing role is
  intentional. SEC016 flags the role itself; SEC023 flags each
  policy that names it.

### Changed
- **Rule count: thirty-two → thirty-three** (`SEC001`–`SEC023`,
  `PERF001`–`PERF003`, `HYG001`–`HYG003`, `VIEW001`–`VIEW004`). No
  snapshot-format change — SEC023 reads the policy `roles` list
  and the top-level `bypassrls_roles` set, both already part of
  the snapshot format (`bypassrls_roles` since v9, added with
  SEC016), so `SNAPSHOT_VERSION` stays at 10.

## [0.5.30] - 2026-05-18

### Added
- **`pgrls fix` now auto-remediates PERF003** ("policy predicate
  column without a leading-column index"). The fixer emits
  `CREATE INDEX ON <schema>.<table> (<column>);` for each policy-
  predicate column the rule flags as unindexed. `pgrls fix` now
  covers SEC001, SEC002, SEC006, PERF001, PERF003, HYG003,
  VIEW001, and VIEW002.

  One index on a table resolves the finding for every policy on
  that table that filters on that column, so the fixer
  deduplicates per table + column: two policies on one table
  filtering the same unindexed column produce two PERF003
  violations but a single `CREATE INDEX`. The same column on two
  different tables is two distinct findings and yields one index
  each. The statement is a plain `CREATE INDEX`,
  not `CREATE INDEX CONCURRENTLY` — a plain build composes with
  `pgrls fix --apply`'s single all-or-nothing transaction, which
  `CONCURRENTLY` cannot run inside. A plain build locks writes on
  the table while the index builds; each Fix's description says
  so and points at `CREATE INDEX CONCURRENTLY` (via `pgrls fix
  --output`) as the production-safe path for a large, busy table.

## [0.5.29] - 2026-05-18

### Changed
- **`pgrls fix` now validates an `allowlist` exactly as `pgrls
  lint` does.** Each fixer parsed its `[lint.rules.<ID>].allowlist`
  with a lenient local helper that silently dropped a malformed
  entry and fell back to "nothing exempt" — so a typo such as a
  stray-whitespace entry (`" public.t.p "`) or a bare-string
  `allowlist` made `pgrls lint` hard-error but let `pgrls fix`
  proceed, emitting (or `--apply`-ing) remediation SQL for an
  object the user believed was exempt.

  The seven fixers (SEC001, SEC002, SEC006, PERF001, HYG003,
  VIEW001, VIEW002) now parse the allowlist with the same strict
  parser their rule uses. A malformed allowlist raises, and
  `pgrls fix` surfaces it as a clear tool error (exit code 2) —
  identical to `pgrls lint`. A well-formed allowlist behaves
  exactly as before; only malformed config is affected.

## [0.5.28] - 2026-05-18

### Added
- **`pgrls fix --output <file>`.** Writes the remediation SQL to
  a migration-ready `.sql` script — a header naming the
  generating pgrls version and the fix count, followed by one
  `-- [rule] description` comment per statement — instead of
  printing it to stdout. Hand the file to your migration tool,
  or review it and run it with `psql -f`.

  The file is deterministic: the header carries no timestamp, so
  regenerating `pgrls fix --output` against an unchanged schema
  produces a byte-identical file — a committed migration diffs
  cleanly. `--output` cannot be combined with `--apply` (one
  writes a migration to apply later, the other executes
  immediately); pgrls rejects the pair with a clear error. When
  there are no auto-fixable findings, no file is written.

## [0.5.27] - 2026-05-18

### Added
- **SEC022 — RLS-enabled table has no write-side policy**
  (severity: info). Flags a table with RLS enabled whose every
  policy is `FOR SELECT`: the table has working read coverage but
  no policy covering INSERT, UPDATE, or DELETE, so for every
  non-owner role `INSERT` raises a row-violates-policy error
  while `UPDATE` and `DELETE` silently affect zero rows — an
  asymmetry that makes a forgotten write policy easy to miss.

  This is often a genuine mistake, but a read-only table (writes
  performed by a table-owning or `BYPASSRLS` role) is a valid
  intentional design pgrls cannot distinguish — so SEC022 is info
  severity. It fires only when the table has at least one
  *permissive* policy: a restrictive-only table denies reads too
  and is SEC012's "restrictive-only policy set" surface, not a
  read-only one. A `FOR ALL` policy counts as write coverage and
  silences the rule. Allowlist the table by name or
  `schema.table` when the read-only surface is intentional.

### Changed
- **Rule count: thirty-one → thirty-two** (`SEC001`–`SEC022`,
  `PERF001`–`PERF003`, `HYG001`–`HYG003`, `VIEW001`–`VIEW004`). No
  snapshot-format change — SEC022 reads table and policy metadata
  already captured since v1, so `SNAPSHOT_VERSION` stays at 10.

## [0.5.26] - 2026-05-18

### Added
- **`pgrls fix` now auto-remediates HYG003** ("policy duplicates
  another policy on the same table"). The fixer emits `DROP
  POLICY <redundant> ON <schema>.<table>;` for a policy that is
  an exact duplicate of another on the same table. Because the
  two are identical, dropping one leaves the table's effective
  RLS unchanged — permissive policies are OR-combined (`p OR p`
  is `p`) and restrictive ones AND-combined. `pgrls fix` now
  covers SEC001, SEC002, SEC006, PERF001, HYG003, VIEW001, and
  VIEW002.

  This is the first `pgrls fix` statement that DROPs an object
  rather than adding or altering one. It is safe — the dropped
  policy has an exact twin that remains — but, like every fixer,
  it is dry-run by default; review the SQL before `--apply`. The
  fixer mirrors HYG003's detection exactly (it reuses the rule's
  duplicate-signature function), keeps the name-sorted-first
  policy of each duplicate group and drops the rest, and honors
  the same `allowlist` of qualified policy IDs.

## [0.5.25] - 2026-05-18

### Added
- **`pgrls lint --baseline <file>`.** A baseline file lets a
  project adopt pgrls on a legacy database without fixing every
  pre-existing finding first. On the first run (file absent)
  pgrls records the current findings into the file and exits
  `0`; on every later run it suppresses findings already in the
  baseline and reports — and exit-codes — only on findings
  absent from it. A new RLS issue fails CI; the grandfathered
  backlog does not.

  A finding is keyed by `(rule_id, location)` — the message text
  is deliberately excluded, so a harmless wording change between
  releases doesn't spuriously un-baseline a finding. The baseline
  is JSON (commit it to the repo). The model is
  auto-create-on-first-run: to re-baseline after deliberately
  accepting new findings, delete the file and run again.
  `--baseline` is applied before formatting and the exit-code
  decision, so it composes with `--format` and `--fail-on`.

## [0.5.24] - 2026-05-18

### Added
- **HYG003 — policy duplicates another policy on the same
  table** (severity: info). Flags two policies on one table that
  are identical in everything but their name — same command,
  role set, permissive / restrictive kind, and `USING` /
  `WITH CHECK` predicates.

  Such a duplicate is redundant: permissive policies are
  OR-combined and restrictive ones AND-combined, so a second
  identical policy changes nothing. It is almost always a
  copy-paste leftover or a migration that re-created a policy it
  never dropped — and a maintenance hazard, since editing one of
  the pair leaves the other silently stale.

  Detection is an exact match (the `USING` / `WITH CHECK`
  comparison uses Postgres's canonical `pg_get_expr` text;
  semantic equivalence is out of scope) with the role list
  compared as a set. For each duplicate group HYG003 keeps the
  name-sorted-first policy and flags the rest; allowlist a
  redundant policy's qualified ID if keeping both is intended.

### Changed
- **Rule count: thirty → thirty-one** (`SEC001`–`SEC021`,
  `PERF001`–`PERF003`, `HYG001`–`HYG003`, `VIEW001`–`VIEW004`). No
  snapshot-format change — HYG003 reads policy metadata already
  captured since v1, so `SNAPSHOT_VERSION` stays at 10.

## [0.5.23] - 2026-05-18

### Added
- **`pgrls fix` now auto-remediates SEC006** ("write-side policy
  missing WITH CHECK"). The fixer emits `ALTER POLICY <name> ON
  <schema>.<table> WITH CHECK (<the USING predicate>);` — copying
  the policy's `USING` clause into a `WITH CHECK` so the write
  side enforces the same predicate as the read side, the
  remediation SEC006 recommends for a permissive policy. `pgrls
  fix` now covers SEC001, SEC002, SEC006, PERF001, VIEW001, and
  VIEW002.

  The fixer is deliberately narrow — it emits only for a
  **permissive** policy that has a `USING` clause to mirror. A
  restrictive write-side policy with no `WITH CHECK` is a dead
  policy whose remediation ("express the intended predicate, or
  remove the policy") needs human intent, and a `FOR INSERT`
  policy — or any write policy written without a `USING` — has
  no predicate to copy. In those cases the fixer skips and leaves
  the SEC006 finding for the operator. The `USING` predicate is
  round-tripped through pglast (not echoed verbatim), consistent
  with the PERF001 fixer.

## [0.5.22] - 2026-05-18

### Changed
- **Internal: shared the literal-boolean AST detector.** The
  narrow "is this node the literal `true` / `false`" check was
  copy-pasted across four rule modules — `SEC008` (`USING
  (true)`), `SEC010` (`USING`/`WITH CHECK (false)`), `SEC011`
  (`OR true` branch), and `SEC020` (`WITH CHECK (true)`). It now
  lives once in `pgrls.ast_utils` as `is_literal_true` /
  `is_literal_false`, and the four rules import it. No behavior
  change — detection stays exactly as narrow as before (only the
  literal constant matches, never `1 = 1` or other semantic
  tautologies). `pgrls.ast_utils` is an internal module with no
  API-stability promise.

## [0.5.21] - 2026-05-18

### Added
- **SEC021 — policy compares an identity column against a
  hardcoded literal** (severity: info). Flags an `=` comparison
  between an identity-named column (`tenant_id`, `org_id`,
  `account_id`, `user_id`, `owner`, …) and a literal constant —
  `USING (tenant_id = 1)`.

  A literal pins the policy to one specific tenant: every session
  is handed the same fixed slice of rows instead of being scoped
  to its own tenant. It is almost always a scaffolding value left
  in place of the per-request session lookup
  (`current_setting('app.tenant_id')`, a JWT claim).

  Detection is a name heuristic — the identity-ish column name is
  what separates the anti-pattern from a legitimate `column =
  literal` policy such as `is_public = true` or `status =
  'published'`. Because the heuristic cannot know a project's
  column conventions, SEC021 is **info** severity. Override the
  column set with `[lint.rules.SEC021].identity_columns` (the list
  replaces the default); allowlist by qualified policy ID when the
  fixed comparison is intentional.

### Changed
- **Rule count: twenty-nine → thirty** (`SEC001`–`SEC021`,
  `PERF001`–`PERF003`, `HYG001`–`HYG002`, `VIEW001`–`VIEW004`). No
  snapshot-format change — SEC021 reads policy expressions already
  captured since v1, so `SNAPSHOT_VERSION` stays at 10.

## [0.5.20] - 2026-05-17

### Added
- **`pgrls fix` now auto-remediates SEC001** ("RLS not enabled").
  The fixer emits `ALTER TABLE <schema>.<table> ENABLE ROW LEVEL
  SECURITY;` for every table SEC001 flags. `pgrls fix` is dry-run
  by default (prints the SQL); `--apply` executes it. `pgrls fix`
  now covers SEC001, SEC002, PERF001, VIEW001, and VIEW002.

  Partition children are skipped: SEC001 flags a child only
  because an ancestor lacks RLS — or, when the parent is in an
  unscanned schema, has RLS pgrls cannot verify. Neither case has
  one mechanical fix (enable RLS on an in-scope parent; or widen
  `--schemas` / design a child policy when the parent is out of
  scan), so the fixer emits only the unambiguous standalone-table
  and partitioned-parent cases (`partition_of is None`) and leaves
  every child for human review.

  A table with RLS enabled and no policy denies all rows to
  non-owner roles — the generated `Fix.description` says so, so an
  operator reviewing the dry-run output knows to add policies
  next. The fixer honours `[lint.rules.SEC001].allowlist`, the
  same allowlist the rule reads.

## [0.5.19] - 2026-05-17

### Added
- **SEC020 — policy `WITH CHECK` clause is constant `true` but
  `USING` is not** (severity: warning). Flags a policy that has
  both clauses present, a real `USING` predicate, and a `WITH
  CHECK` clause that is the literal `true`.

  `USING` filters the rows a caller may read; `WITH CHECK`
  validates the rows it may write. An explicit `WITH CHECK (true)`
  alongside a restrictive `USING` means the read side is locked
  down while the write side is wide open — the caller can INSERT a
  row stamped with another tenant's id, or UPDATE one of its own
  rows to reassign it, even though it can only read its own. The
  fix is to mirror the `USING` predicate into `WITH CHECK`, or to
  drop the `WITH CHECK` clause so Postgres reuses `USING` for it.

  Detection matches the literal `true` only — the same
  deliberately narrow scope as SEC008, so `1 = 1` and other
  semantic tautologies are out of scope. A policy with no `WITH
  CHECK` at all is SEC006's concern, not SEC020's. Allowlist by
  qualified policy ID when an intentionally open write side is the
  design (e.g. an append-only audit table).

### Changed
- **Rule count: twenty-eight → twenty-nine** (`SEC001`–`SEC020`,
  `PERF001`–`PERF003`, `HYG001`–`HYG002`, `VIEW001`–`VIEW004`). No
  snapshot-format change — SEC020 reads policy expressions already
  captured since v1, so `SNAPSHOT_VERSION` stays at 10.

## [0.5.18] - 2026-05-17

### Added
- **Per-rule severity override in `pgrls.toml`.** Each
  `[lint.rules.<ID>]` table now accepts a reserved `severity` key —
  `"error"`, `"warning"`, or `"info"` — that remaps the reported
  severity of every violation that rule emits:

  ```toml
  [lint.rules.SEC019]
  severity = "error"   # promote info-level SEC019 — now fails CI
  ```

  An operator can promote an advisory rule so it gates CI, or
  demote a noisy one below the `fail_on` threshold, without
  disabling it (`disable` silences the rule entirely; the
  allowlist exempts specific objects; this re-tiers the rule
  while keeping all of its findings visible). The remap is
  applied in the lint pipeline before the exit-code decision and
  before output, so the `fail_on` gate, the severity counts, and
  the printed label all reflect the override.

  `severity` is case-insensitive (matching `[lint].fail_on` and
  `--fail-on`) and is validated at config load — an invalid value
  or a non-string raises a clear `ConfigError`. It is a reserved
  key: it sits in the same `[lint.rules.<ID>]` table as
  `allowlist` and other options but is consumed by pgrls itself,
  not passed to the rule's `check()`.

## [0.5.17] - 2026-05-17

### Added
- **SEC019 — policy calls `current_setting()` without the
  `missing_ok` argument** (severity: info). Flags every policy
  whose `USING` or `WITH CHECK` expression contains a
  `current_setting` call with exactly one argument.

  `current_setting(name)` raises `unrecognized configuration
  parameter` when the GUC is unset; `current_setting(name, true)`
  (passing the `missing_ok` argument) returns NULL instead. RLS
  policies read the per-request tenant context from a custom GUC,
  so with the one-argument form a request that reaches the
  database before its session context is set makes *every* query
  against the table error. The two-argument form yields NULL,
  which in a `column = current_setting(...)` predicate simply
  matches no rows — the query succeeds, empty.

  Neither is a security hole: the one-argument form fails closed
  (it raises, never silently widens). SEC019 is therefore
  **info**-level — a robustness nudge so the choice between
  "raise" and "return NULL on an unset GUC" is deliberate, not an
  accident of which overload was reached for. It is unrelated to
  SEC004, which catches the genuinely dangerous *fail-open*
  `current_setting(...) IS NULL OR …` shape. Detection is
  structural (the parsed policy AST, including sub-selects);
  allowlist by qualified policy ID when raise-on-unset is the
  intended behaviour.

### Changed
- **Rule count: twenty-seven → twenty-eight** (`SEC001`–`SEC019`,
  `PERF001`–`PERF003`, `HYG001`–`HYG002`, `VIEW001`–`VIEW004`). No
  snapshot-format change — SEC019 reads policy expressions already
  captured since v1, so `SNAPSHOT_VERSION` stays at 10.

## [0.5.16] - 2026-05-16

### Added
- **SEC018 — policy compares a column against `current_user` /
  `session_user`** (severity: warning). Flags every policy whose
  `USING` or `WITH CHECK` expression compares one of its own
  table's columns against `current_user` (or its `current_role` /
  `user` aliases) or `session_user` — `owner_role = current_user`,
  `current_user = ANY(member_roles)`, and so on.

  These identify the Postgres role the session runs as. Using one
  as a row-matching key isolates tenants only when every tenant
  connects as — or `SET ROLE`s to — a distinct Postgres role.
  Application code almost always serves every tenant over one
  shared connection-pool role; `current_user` is then a constant,
  and a policy like `USING (owner_role = current_user)` matches
  the same way for every tenant — no per-tenant isolation, while
  still looking like access control. `session_user` is the same
  trap and worse — it stays pinned to the pool's login role even
  when the application does `SET ROLE` per request.

  The rule deliberately leaves three legitimate uses alone: a
  `current_user` *function argument* (`pg_has_role(current_user,
  …)` — the standard admin escape, not a comparison operand);
  `current_user` compared only to a *literal* (`current_user =
  'postgres'` — a superuser check, no column operand); and
  `current_user` compared to a column of *another* table (a
  `pg_roles` catalog lookup — also an admin escape). Firing
  requires a column of the policy's own table on the other side of
  the comparison (the same own-column scoping SEC005 uses).

  The correct discriminator for pooled application code is a
  per-request session value: a GUC read with
  `current_setting('app.tenant_id')`, or a JWT claim. SEC018 is a
  warning, not an error, because the role-per-tenant RLS pattern
  (one Postgres role per tenant, `SET ROLE` per request) is a
  legitimate design where `current_user` is the right
  discriminator — pgrls cannot tell which deployment model is in
  use. Detection is structural (the rule walks the parsed policy
  AST for the comparison, including sub-selects); allowlist by
  qualified policy ID after confirming a role-per-tenant
  deployment.

### Changed
- **Rule count: twenty-six → twenty-seven** (`SEC001`–`SEC018`,
  `PERF001`–`PERF003`, `HYG001`–`HYG002`, `VIEW001`–`VIEW004`). No
  snapshot-format change — SEC018 reads the policy expressions
  already captured since v1, so `SNAPSHOT_VERSION` stays at 10.

## [0.5.15] - 2026-05-15

### Added
- **SEC017 — function with the `LEAKPROOF` attribute is evaluated
  below the RLS barrier** (severity: warning). Flags every
  function in the introspected schemas carrying the `LEAKPROOF`
  attribute.

  A `LEAKPROOF` function promises the planner it has no side
  channels — no information about its arguments escapes via error
  messages, timing, or any other observable behaviour. On that
  promise the planner may evaluate the function *below* a security
  barrier: ahead of a table's row-level security qual, ahead of a
  `security_barrier` view's `WHERE`. A non-leakproof function is
  held above the barrier and only ever sees rows the caller is
  entitled to.

  A function *marked* `LEAKPROOF` but not actually leak-free is a
  data-leak vector. Applied to a column of an RLS-protected table
  it runs on every row — including rows the caller's policy would
  hide — and an error it raises (or argument-dependent timing) can
  disclose those rows. The classic shape:
  `SELECT * FROM rls_table WHERE leaky_fn(secret_col) = 'probe'` —
  the planner pushes `leaky_fn` below the RLS qual and the attacker
  reads `secret_col` from the error text or response time.

  Marking a function `LEAKPROOF` requires superuser, so it is
  always deliberate. SEC017 surfaces every such function for an
  explicit audit decision: confirm no error path and no timing
  channel exposes an argument, or remove the marking with
  `ALTER FUNCTION name(argtypes) NOT LEAKPROOF`. pgrls does not
  parse the body to prove leakproofness (the brittle analysis the
  rule deliberately avoids). Postgres's built-in leakproof
  functions live in `pg_catalog`, outside the linted schemas, so
  they never surface. Allowlist by qualified function name
  (`schema.function`); overloads collapse to one finding.

  SEC017 is the fourth attribute-level audit rule: SEC014/SEC015
  flag `SECURITY DEFINER` functions, SEC016 flags `BYPASSRLS`
  roles, and SEC017 flags `LEAKPROOF` functions.

### Changed
- **Snapshot format v9 → v10.** Snapshots gain a top-level
  `leakproof_functions` array — the qualified names of functions
  carrying the `LEAKPROOF` attribute, introspected from
  `pg_proc.proleakproof` (only functions `WHERE proleakproof` in
  the introspected schemas are captured; overloads are collapsed).
  `Schema.from_snapshot` still accepts versions 3–10. A v3–v9
  snapshot loads with `leakproof_functions = []` (the field did
  not exist), so SEC017 finds nothing to flag against it —
  re-snapshot against a live database to capture the functions.
- **Rule count: twenty-five → twenty-six** (`SEC001`–`SEC017`,
  `PERF001`–`PERF003`, `HYG001`–`HYG002`, `VIEW001`–`VIEW004`).

## [0.5.14] - 2026-05-15

### Added
- **SEC016 — role with the `BYPASSRLS` attribute bypasses all
  RLS** (severity: warning). Flags every non-superuser role
  carrying the `BYPASSRLS` attribute.

  A role granted `BYPASSRLS` skips *every* row-level security
  policy on *every* table — RLS is not weakened for it, it is
  simply off. The bypass is invisible: nothing in a table, a
  policy, or a `GRANT` reveals that a particular role ignores
  all of them, so an application connecting as a `BYPASSRLS`
  role gets zero tenant isolation while every policy in the
  schema still reads as airtight.

  `BYPASSRLS` is unconditional and cluster-wide. It is not the
  table-owner bypass SEC002 covers — `FORCE ROW LEVEL SECURITY`
  does not touch a `BYPASSRLS` role. And it is not the
  code-mediated bypass SEC013/SEC014/SEC015 cover — a trigger
  firing as the table owner, or a `SECURITY DEFINER` function
  running as the function owner. The role itself is exempt; no
  code or ownership is involved.

  SEC016 skips superuser roles: a superuser bypasses RLS via
  `rolsuper` regardless, so the attribute is redundant noise on
  one. The rule flags only the non-superuser roles, where an
  RLS bypass is genuinely surprising. The fix is one
  statement — `ALTER ROLE <name> NOBYPASSRLS` — but it is not
  auto-applied: pgrls cannot tell a misconfigured application
  role from a backup / logical-replication / ETL role that
  legitimately needs the attribute. Allowlist by bare role
  name (roles have no schema component) once the bypass is
  confirmed intentional.

  Roles are cluster-global, so SEC016 — unlike the
  schema-scoped rules — has no out-of-scope blind spot: it sees
  every `BYPASSRLS` role in the cluster regardless of the
  introspected `--schemas` set.

### Changed
- **Snapshot format v8 → v9.** Snapshots gain a top-level
  `bypassrls_roles` array — the roles carrying the `BYPASSRLS`
  attribute, each with its `superuser` / `can_login` flags,
  introspected from `pg_roles` (only roles `WHERE rolbypassrls`
  are captured). `Schema.from_snapshot` still accepts versions
  3–9. A v3–v8 snapshot loads with `bypassrls_roles = []` (the
  field did not exist), so SEC016 finds nothing to flag against
  it — re-snapshot against a live database to capture the
  roles.
- **Rule count: twenty-four → twenty-five** (`SEC001`–`SEC016`,
  `PERF001`–`PERF003`, `HYG001`–`HYG002`, `VIEW001`–`VIEW004`).

## [0.5.13] - 2026-05-15

### Added
- **SEC015 — SECURITY DEFINER function exposed to `pg_temp`
  search-path shadowing** (severity: warning). Flags every
  SECDEF function whose effective `search_path` lets the
  per-session temporary schema (`pg_temp`) be searched before
  the legitimate schemas.

  A SECDEF function runs as its owner. When the body references
  an object by an *unqualified* name, Postgres resolves it
  against the function's `search_path`. Postgres searches
  `pg_temp` **first** — ahead of even `pg_catalog` — for
  relation and type names *unless* `pg_temp` is named
  explicitly in `search_path`. An attacker creates a same-named
  table/view/type in their session's `pg_temp`; the privileged
  function silently resolves to the attacker's object and runs
  attacker-controlled SQL with the owner's privileges. This is
  the CVE-2018-1058 search-path privilege-escalation class.

  The rule fires when the effective search_path does not end
  with an explicit `pg_temp` token:
  - **No `SET search_path` clause** — the function inherits the
    caller's (attacker-controlled, `pg_temp`-first) path.
  - **`SET search_path` present but `pg_temp` absent** — e.g.
    the common `SET search_path = pg_catalog, public`; `pg_temp`
    is still implicitly first because it isn't named.
  - **`pg_temp` named but not last** — searched at the written
    (early) position.

  The only structurally-safe shape — `pg_temp` named as the
  **last** entry — passes. The fix is mechanical (`ALTER
  FUNCTION … SET search_path = …, pg_temp`) but not auto-applied:
  rewriting the clause needs the function's full argument
  signature, which introspection doesn't capture. Allowlist by
  qualified function name (`schema.function`) after confirming
  the body fully-qualifies every object reference.

  SEC015 is the sharp companion to SEC014: where SEC014 says
  "audit this SECDEF function," SEC015 says "this specific
  function has an exploitable search_path, here's the one-line
  fix." VIEW004 and SEC013 cover the view- and trigger-mediated
  SECDEF bypass paths respectively.

### Changed
- **Snapshot format v7 → v8.** `SecdefFunction` snapshot entries
  gain a `search_path` field (the value of the function's
  `SET search_path` clause, decoded from `pg_proc.proconfig`,
  or `null` when no clause is pinned). `Schema.from_snapshot`
  still accepts versions 3–8. A v4–v7 snapshot's SECDEF
  functions load with `search_path = null` (v3 snapshots have
  no SECDEF functions — `security_definer_functions` is a v4+
  field). SEC015 treats `null` as unsafe, so it conservatively
  flags every SECDEF function loaded from a pre-v8 snapshot;
  re-snapshot against a live database to capture real
  `search_path` values.
- **Rule count: twenty-three → twenty-four** (`SEC001`–`SEC015`,
  `PERF001`–`PERF003`, `HYG001`–`HYG002`, `VIEW001`–`VIEW004`).

## [0.5.12] - 2026-05-15

### Added
- **SEC014 — SECURITY DEFINER function audit (free-standing)**
  (severity: warning). Flags every SECDEF function in the
  introspected schemas. SECDEF functions run with the function
  owner's privileges, so any SELECT/INSERT/UPDATE/DELETE inside
  the body bypasses the caller's RLS policies, GRANT/REVOKE
  differences, and other privilege checks. A role with EXECUTE
  on the function effectively inherits the owner's reach into
  RLS-protected tables.

  Two existing rules already cover the SECDEF risk for
  *indirect* paths: **VIEW004** flags views whose body calls a
  SECDEF function that reads an RLS-protected table (view-
  mediated bypass); **SEC013** flags triggers on RLS-protected
  tables (which fire as the table owner regardless of the
  trigger function's `prosecdef` flag). SEC014 closes the gap
  for SECDEF functions called *directly* from application code
  (`SELECT my_secdef(...)`, JDBC, etc.) — the audit surface
  neither VIEW004 nor SEC013 reaches.

  Detection is structural: walk
  `Schema.security_definer_functions` (captured by
  introspection from `pg_proc.prosecdef = TRUE` since snapshot
  v4). Allowlist by qualified function name (`schema.function`)
  once the operator has audited the function body and confirmed
  it doesn't expose data the caller couldn't read directly.
  Bare function name is rejected — two same-named functions in
  different schemas would otherwise both be silenced.

  Out of scope (intentional): per-overload signatures (a
  function with two overloads is flagged + allowlisted once);
  body-reachability of RLS tables (VIEW004 already does that
  for the view-mediated path; SEC014 is "audit every SECDEF
  surface" not "prove leak").

  Severity: warning. No auto-fix — the choice between rewriting
  as `SECURITY INVOKER` (RLS applies to caller) or documented
  allowlist needs human intent.

## [0.5.11] - 2026-05-15

### Fixed
- **`pgrls diff --format text` now applies the same hostile-input
  hardening to `Change.location` that v0.5.10's lint formatters
  apply to `Violation.location`.** Extends the v0.5.10 "Text and
  Markdown formatters harden `Violation.location` rendering"
  fix: `_render_stanza` in `pgrls.diff.formatters` now routes
  `change.location` through `safe_location` before emitting the
  stanza header marker line (`+ <loc>`, `- <loc>`, `~ <loc>`,
  `! <loc>`). Without this, a Postgres identifier containing
  `\n` / `\r` / `\t` / zero-width chars splits the stanza header
  into multiple lines that a `^- (\S+)$` CI grep can't
  distinguish from a legitimate second stanza. The `before_sql` /
  `after_sql` predicate blocks are deliberately NOT sanitized —
  those are operator-supplied SQL text and multi-line clauses
  (e.g. `USING (\n  tenant_id = …\n)`) are legitimate diff
  output. JSON and SARIF diff paths were already safe — they
  route through `format_violations` / `format_sarif` which
  serialize via `json.dumps`.

## [0.7.6] - 2026-05-14

Go port step 7 of 7 — CI hardening (`golangci-lint`,
`govulncheck`) and release plumbing
(`.github/workflows/go-release.yml` fires on `go/v*` tag push,
re-runs the PR-branch gates against the tag commit —
tidy + gofmt + vet + race tests + golangci-lint + govulncheck
— plus a CHANGELOG-stanza cross-check, warms the public Go
module proxy via `go list -m`, and cuts a GitHub Release from
the changelog stanza via `--notes-file` so backtick-bearing
CHANGELOG content survives the shell intact). Closes out the
v0.7.x staged rollout. The Python core (`pgrls` package) stays
at 0.5.10 and the TypeScript port stays at 0.6.2. Per-port
details in [`go/CHANGELOG.md`](go/CHANGELOG.md).

## [0.7.5] - 2026-05-14

Go port step 6 of 7 — cross-language conformance suite. Both
adapter packages (pgx and lib/pq) now run against a real
Postgres container via testcontainers-go, exercising the four
Layer 1 protocol criteria from `docs/pgrls-test-protocol.md`
plus end-to-end public-API tests, against the same
`tests/protocol/{schema,seed}.sql` SQL fixture the Python
conformance suite consumes (Python ↔ Go fixture sharing; the
TS port hand-rolls its own equivalent fixture). The Python
core (`pgrls` package) stays at 0.5.10 and the TypeScript port
stays at 0.6.2. Per-port details in [`go/CHANGELOG.md`](go/CHANGELOG.md).

## [0.7.4] - 2026-05-14

Go port step 5 of 7 — five RLS assertion helpers (`AssertRows`,
`AssertVisible`, `AssertInvisible`, `AssertRejected`,
`AssertSilentlyDropped`) on `Client` and at package level.
The Python core (`pgrls` package) stays at 0.5.10 and the
TypeScript port stays at 0.6.2. Per-port details in
[`go/CHANGELOG.md`](go/CHANGELOG.md).

## [0.7.3] - 2026-05-14

Go port step 4 of 7 — Client API (`Transaction`, `AsRole`, `Exec`,
`FetchAll`, `Seed`, `Close`) plus `QuoteIdent` / `QuoteQualified` /
`NewSavepointName` helpers. The Python core (`pgrls` package) stays
at 0.5.10 and the TypeScript port stays at 0.6.2. Per-port details
in [`go/CHANGELOG.md`](go/CHANGELOG.md).

## [0.7.2] - 2026-05-13

Go port step 3 of 7 — pgx + lib/pq driver adapters. Python core stays at
0.5.10, TS port stays at 0.6.2. Per-port details in
[`go/CHANGELOG.md`](go/CHANGELOG.md).

## [0.7.1] - 2026-05-13

Go port step 2 of 7 — `Driver` interface, `Closer` optional interface,
`QueryResult` struct. The Python core (`pgrls` package) stays at 0.5.10
and the TypeScript port stays at 0.6.2. Per-port details live in
[`go/CHANGELOG.md`](go/CHANGELOG.md).

## [0.7.0] - 2026-05-13

The Python core (`pgrls` package) version stays at 0.5.10 — v0.7.0 is
the **first release of the Go port** (`pgrls-test-go`), shipping the
module scaffold + Layer 1 protocol-version constant + error types at
[`go/`](go/) in this monorepo. The Go port follows a staged release
plan (step 1 of 7); per-port details and the planned v0.7.1–v0.7.6
roadmap live in [`go/CHANGELOG.md`](go/CHANGELOG.md). Module path
`github.com/pgrls/pgrls/go`; tag convention `go/v0.7.0`. See
[`go/README.md`](go/README.md) for usage.

## [0.5.10] - 2026-05-13

### Added
- **PERF003 — Policy predicate column without leading-column
  index** (severity: warning). Detects RLS policy predicates that
  filter on a column with no leading-column index. Postgres
  evaluates the policy predicate per row, so without an index the
  planner does a sequential scan — fine for small tables,
  catastrophic on multi-tenant tables with millions of rows. The
  rule treats any access method as "indexed" (B-tree, hash, GIN,
  GiST, BRIN) and considers a leading-column match sufficient.
  Partial indexes are accepted on trust (pgrls can't statically
  verify the partial predicate matches the policy predicate);
  expression indexes (`CREATE INDEX ON tbl (lower(email))`) are
  not matched in v0.5.10 — allowlist the policy when a matching
  expression index exists. Allowlist by qualified policy ID
  (`schema.table.policy_name`):

  ```toml
  [lint.rules.PERF003]
  allowlist = ["public.invoices.tenant_read"]
  ```

### Changed
- **Snapshot version 6 → 7.** Each `tables[i]` entry now carries
  an `indexes` array with one entry per valid + ready index
  (`name`, `access_method`, `columns`, `is_unique`, `is_partial`).
  v3 / v4 / v5 / v6 baselines still load via
  `Schema.from_snapshot` with `indexes=()` on every table; the
  loaded Schema re-emits as v7. PERF003 simply finds nothing to
  flag against older snapshots until they're re-captured.

  Existing snapshots remain forward-compatible: `pgrls diff`
  continues to work against v3+ baselines without re-snapshotting.
  `pgrls fix` operates against a live DB only (not a baseline) and
  is unaffected. Only PERF003 needs v7 to surface findings.

- **Allowlist entries with leading/trailing whitespace now raise**
  (rolled in from PR #44 — was Unreleased prior to v0.5.10).
  `[lint.rules.X].allowlist` entries are compared with byte-exact
  equality against location strings built by introspection (which
  never carry surrounding whitespace), so a typo like
  `" public.users.evil "` in `pgrls.toml` previously silently
  failed to match — the rule kept firing with no signal to the
  operator. `pgrls` now raises `TypeError` at config-load time
  with the stripped form shown in the message. Affects every
  allowlist parser:
  `parse_policy_id_allowlist` (SEC003, SEC005, SEC006, SEC008,
  SEC010, SEC011, SEC013, PERF001, PERF002, PERF003, HYG002),
  `parse_table_ref_allowlist` (SEC001, SEC002, SEC009, SEC012),
  `parse_qualified_table_allowlist` (SEC007),
  `parse_qualified_view_allowlist` (VIEW001-VIEW004). Internal
  whitespace (Postgres quoted identifier with a space in the name,
  e.g. `"my table"`) is still allowed — that's a real identifier
  shape the rule can legitimately allowlist.

  **Migration**: if upgrading from v0.5.9 or earlier with a
  whitespaced entry in `pgrls.toml`, the `TypeError` message
  names the offending entry and the stripped form. One-keystroke
  fix; no behavior change for well-formed configs.

### Fixed
- **Text and Markdown formatters harden `Violation.location`
  rendering against newlines, tabs, and zero-width chars.**
  Postgres allows any character inside a quoted identifier
  (`"weird\nname"`), so operator-supplied names that flow into
  `Violation.location` (table, policy, trigger, etc.) could
  previously break line-oriented CI grep patterns and GFM pipe-
  table layouts. The new `safe_location` helper rewrites these
  chars with visible escape text (`\n` / `\r` / `\t` text,
  `\xHH` hex for other control chars) and drops zero-width
  formatting chars (U+200B, U+200C, U+200D, U+FEFF). JSON and
  SARIF output is unchanged — `json.dumps` already escapes safely.
  The Markdown formatter additionally switches to a double-
  backtick code-span wrap when the location contains a literal
  backtick, and surfaces a `(empty-or-zero-width)` sentinel when
  sanitization empties a non-`None` location.

## [0.5.9] - 2026-05-12

### Added
- **Top-level diff API.** `diff_schemas`, `Change`, `ChangeKind`,
  and `Classification` are now re-exported from the top-level
  `pgrls` package. Both import paths resolve to the same object
  identities:

  ```python
  from pgrls import diff_schemas, Change            # new in v0.5.9
  from pgrls.diff import diff_schemas, Change       # still works
  ```

  `pgrls.diff` remains the canonical submodule; the top-level
  binding is a re-export, not a copy. `isinstance(c, pgrls.Change)`
  and `isinstance(c, pgrls.diff.Change)` both work on the same
  object, and class identity (`pgrls.Change is pgrls.diff.Change`)
  holds — so callers comparing classes across the public surface
  don't see two separate identities.

  No behavior change for callers who keep importing from
  `pgrls.diff`. The promotion is additive — existing code paths
  are unaffected.

## [0.5.8] - 2026-05-12

### Added
- **SEC013 — Trigger on RLS-protected table can bypass policies**
  (severity: warning). Triggers fire as the table OWNER, not as
  the role that ran the statement, so any SELECT / INSERT /
  UPDATE / DELETE inside the trigger function body bypasses the
  invoking role's RLS policies — a quiet privilege-escalation
  vector that's silent in the absence of static analysis. The
  rule flags every user-authored, enabled trigger on a table
  with `rls_enabled = true` and prompts the operator to audit
  the function body for cross-tenant reads, writes the caller
  couldn't issue directly, and owner-visible data echoed back
  through derived columns or RAISE messages. Internal triggers
  (foreign-key check helpers, RI plumbing, partition-routing
  triggers) are filtered out at the introspection layer via
  `pg_trigger.tgisinternal = false`. Disabled triggers
  (`tgenabled = 'D'`) are captured but skipped by the rule —
  they can't fire under any `session_replication_role`.

  Allowlist by qualified trigger ID
  (`schema.table.trigger_name`) once the function body has
  been audited and the bypass is documented intentional:

  ```toml
  [lint.rules.SEC013]
  allowlist = ["public.invoices.audit_writes"]
  ```

  Bare `trigger_name` is rejected — Postgres scopes trigger
  names per table, so two tables can carry identically-named
  triggers and a name-only allowlist would silence both.

### Changed
- **Snapshot version 5 → 6.** Each `tables[i]` entry now carries
  a `triggers` array with one entry per user-authored trigger
  (`name`, `function_schema`, `function_name`, `event`, `timing`,
  `enabled`). Triggers don't carry their own `schema` field —
  Postgres scopes triggers per table (`pg_trigger` has no
  `tgnamespace` column), so a trigger's schema is always its
  table's. v3 / v4 / v5 baselines still **load** via
  `Schema.from_snapshot` with `triggers=()` on every table; the
  loaded Schema re-emits as v6 (matching the v4→v5 bump's load
  semantics). SEC013 simply finds nothing to flag against older
  snapshots until they're re-captured.

  Existing snapshots remain forward-compatible: `pgrls diff` and
  `pgrls fix` continue to work against v3+ baselines without
  re-snapshotting. Only SEC013 needs v6 to surface findings.

## [0.5.7] - 2026-05-08

### Changed
- **Issue #11 closed.** All remaining demo case fixtures
  rewritten from RESTRICTIVE-only to the canonical
  PERMISSIVE+RESTRICTIVE pattern. SEC012 allowlist in
  `demo/pgrls.toml` removed entirely — the demo fixture is
  now self-consistent: every RLS-enabled table has at least
  one PERMISSIVE policy. Each case still demonstrates the
  rule (or AST-walk invariant) it pins.

  This release:
  - **Single-table** (14 cases): uc32 case_policy, uc37
    partial_orphan, uc40 admin_audit, uc46 gen_cols, uc49
    gdpr_records, uc55 not_false_table, uc56 booltest_orphan,
    uc64 MixedCase Table, uc66 json_access, uc67 recent_only,
    uc74 deny_via_false, uc76 or_true_table, uc77
    placeholder_named, uc78 volatile_predicate.
  - **Partitioned families** (5 cases): uc13 events, uc15
    team_documents+team_members, uc23 deep_events, uc24
    leaf_metrics_2026, uc45 region_metrics. PERMISSIVE
    policies on the partitioned root (or leaf, where uc24
    deliberately pushes RLS down) so children inherit.
  - **FK-tenant + diff/view fixtures**: uc48 ec_orders+
    ec_order_items (correlated EXISTS mirrored on PERMISSIVE);
    uc81/83 uc8X_invoices (diff fixtures); uc85-88 uc8X_users
    (view-related — VIEW001/002/003/004 still pin on the
    overlying view, table-level policies don't change the
    test).

  Cumulative across the chip-away:
  - v0.3.1: 1 case (uc01)
  - v0.5.4: 9 cases (batch 1)
  - v0.5.5: 10 cases (batch 2)
  - v0.5.6: 10 cases (batch 3)
  - v0.5.7: 22 cases (final batch — closes the issue)
  - **Total: 52 of 52** ✓

### Notable subtleties
- **uc77** (placeholder_named): the new PERMISSIVE policy is
  named `pn_user_access` — deliberately avoids HYG002's
  placeholder vocabulary (todo / fixme / tmp / hack / xxx /
  debug / placeholder) so the new policy doesn't itself trip
  the rule the case is built to demonstrate.
- **uc46** (gen_cols): PERMISSIVE is FOR SELECT only — the
  table has a generated column, so a FOR ALL PERMISSIVE
  with WITH CHECK on the generated column would be misleading
  (callers can't write the generated value).
- **uc64** (MixedCase Table): the new PERMISSIVE policy uses a
  quoted identifier name (`"MixedCase authenticated access"`)
  to keep the case's mixed-case round-trip pinned for the
  PERMISSIVE side too.
- **uc81/83** (diff fixtures): the new PERMISSIVE doesn't
  reference any column the diff tests drop, so
  `DIFF_POLICY_DROPPED_RESTRICTIVE` and
  `DIFF_COLUMN_DROPPED_REFERENCED` still fire on the
  intended RESTRICTIVE policies only.

## [0.5.6] - 2026-05-08

### Changed
- **Demo cases batch 3: issue #11 chip-away.** Ten more demo
  case fixtures rewritten from RESTRICTIVE-only to the canonical
  PERMISSIVE+RESTRICTIVE pattern. Each case still demonstrates
  the rule (or AST-walk invariant) it pins; SEC012 stops firing.

  Rewritten:
  - **uc35** `app.always_open` (SEC005 — `USING (1=1)`)
  - **uc38** `app.jwt_unwrapped` (PERF001 — auth.jwt unwrapped through `->>`)
  - **uc39** `app.user_workspaces` (config-driven custom auth function)
  - **uc44** `app.current_user_check` (CLEAN — `current_user` cheap SQLValueFunction)
  - **uc47** `app.array_tags` (CLEAN — array column with ANY)
  - **uc51** `app.row_comparison` (CLEAN — RowCompareExpr walking)
  - **uc53** `app.nested_or_check` (false-negative pin — SEC004 only top-level OR)
  - **uc54** `app.typecast_email` (CLEAN — TypeCast over column ref)
  - **uc57** `app.typecast_auth` (PERF001 — auth in TypeCast)
  - **uc58** `app.coalesce_auth` (PERF001 — auth in COALESCE)

  Same pattern as v0.5.4 / v0.5.5: PERMISSIVE policy targeting
  `app_authenticated` with wrapped predicates so the new policy
  doesn't itself trip any rule. Original RESTRICTIVE policy
  preserved verbatim.

  10 entries removed from `[lint.rules.SEC012].allowlist` in
  `demo/pgrls.toml`. ~22 entries remain.

  Cumulative issue #11 progress: **30 of 62 (~48%)**.

## [0.5.5] - 2026-05-08

### Changed
- **Demo cases batch 2: issue #11 chip-away.** Ten more demo
  case fixtures rewritten from RESTRICTIVE-only to the canonical
  PERMISSIVE+RESTRICTIVE pattern. Each case still demonstrates
  the rule it was written for; SEC012 stops firing on the
  now-clean shape.

  Rewritten:
  - **uc10** `app.feature_flags` (SEC008 — USING true)
  - **uc12** `app.comments` (HYG001 — orphan column)
  - **uc17** `app.tickets` (CLEAN — asymmetric USING/WITH CHECK)
  - **uc21** `app.audit_inserts` (PERF001-silent-on-WITH-CHECK contract)
  - **uc27** `app.todos_archive` (CLEAN — DELETE-exempt SEC006)
  - **uc28** `app.jwt_documents` (CLEAN — JWT tenant claim)
  - **uc29** `app.kb_articles` (CLEAN — public-or-tenant mix)
  - **uc30** `app.composite_tenant` (CLEAN — composite key)
  - **uc34** `app.flags_table` (CLEAN — SEC004 nested IS NULL under AND)
  - **uc36** `app.admin_overrides` (CLEAN — pg_has_role admin escape)

  Same approach as v0.5.4: PERMISSIVE policy targeting
  `app_authenticated` with wrapped predicates so the new
  policy itself doesn't trip SEC003/SEC005/SEC008/PERF001.
  The original RESTRICTIVE policy is preserved verbatim.

  10 entries removed from `[lint.rules.SEC012].allowlist` in
  `demo/pgrls.toml`. ~32 entries remain for future batches.

## [0.5.4] - 2026-05-08

### Changed
- **Demo cases batch 1: issue #11 chip-away.** Nine demo case
  fixtures rewritten from RESTRICTIVE-only to the canonical
  PERMISSIVE+RESTRICTIVE pattern (same shape as uc01
  `app.documents`). The rule each case demonstrates still
  fires; SEC012 stops firing on the now-clean shape.

  Rewritten:
  - **uc04** `app.notes` (SEC002)
  - **uc06** `app.accounts` (SEC004)
  - **uc07** `app.singletons` (SEC005)
  - **uc08** `app.invoices` (SEC006)
  - **uc11** `app.messages` (PERF001)
  - **uc18** `app.users_v2` (CLEAN — was masked by SEC012 allowlist;
    now genuinely clean)
  - **uc19** `app.profiles` (SEC004 Supabase)
  - **uc20** `app.todos` (PERF001 Supabase)
  - **uc22** `app.posts_v2` (HYG001)

  Each rewrite adds a PERMISSIVE policy targeting `app_authenticated`
  that grants per-user or per-tenant access via wrapped
  `(SELECT current_setting('app.user', true))` /
  `(SELECT auth.uid())` / `(SELECT current_setting('app.tenant', true)::UUID)`
  expressions, so the new policy doesn't itself trip SEC003,
  SEC005, SEC008, or PERF001. The original RESTRICTIVE policy
  is preserved verbatim — that's where the per-case rule
  demonstration lives.

  Removed from `[lint.rules.SEC012].allowlist` in `demo/pgrls.toml`:
  9 entries above. ~50 entries remain for future batches.

- **Shared `app_authenticated` role** in `demo/cases/_shared.sql`.
  Created idempotently up front so per-case `setup.sql` files
  can `CREATE POLICY … TO app_authenticated` directly without
  repeating the role-creation block.

## [0.5.3] - 2026-05-08

### Added
- **`pgrls diff -v / --verbose`**. With `--apply`, emits cache
  hit/miss state, the cache image tag, and per-step timings
  (boot, baseline restore, migration apply, introspect) on
  stderr. Stdout (the diff text/JSON/SARIF payload) stays
  machine-parsable. On the snapshot-vs-snapshot path the flag
  is a silent no-op (nothing to time).

  ```sh
  pgrls diff base.json --apply migration.sql -v
  # pgrls: cache: miss pgrls-baseline:abcdef0123456789; booting postgres:17-alpine and will commit after baseline restore
  # pgrls: booted in 1.34s
  # pgrls: created 2 role(s): ['app_user', 'tenant_admin']
  # pgrls: baseline restored in 0.12s
  # pgrls: committed baseline cache pgrls-baseline:abcdef0123456789 in 0.45s
  # pgrls: migration applied in 0.08s
  # pgrls: introspected in 0.21s
  ```

- **`pgrls cache` subcommand group** (`list` and `prune`). Thin
  wrappers around `docker images` / `docker image rm` that
  filter by the `org.pgrls.cache=baseline` label so user-tagged
  images aren't touched.

  ```sh
  pgrls cache list
  # pgrls-baseline:abcdef0123456789  437.0MB
  # pgrls-baseline:fedcba9876543210  437.0MB
  # -- 2 image(s), 874.0MB total

  pgrls cache prune          # interactive (y/N prompt)
  pgrls cache prune --yes    # CI-friendly, no prompt
  ```

### Internal
- Refactored `_apply_migration_for_diff` to thread a `verbose`
  flag through to a small `vlog()` closure. Output goes to
  stderr; never pollutes stdout.
- New `_human_bytes()` helper for the cache list output. Uses
  decimal (1000-based) units to match `docker images`.

## [0.5.2] - 2026-05-08

### Added
- **Baseline cache for `pgrls diff --apply`**. The first `--apply`
  run for a given (PG image, baseline DDL, role list, extension
  list) tuple commits the post-restore container into a tagged
  Docker image (`pgrls-baseline:<HASH>`); subsequent runs with
  the same inputs boot directly from that image, skipping role
  pre-creation, extension install, and baseline DDL execution.
  Migration apply + introspection still run on every invocation
  — only the deterministic setup is cached.

  Cache hit / miss is decided by a SHA-256 over the four inputs;
  any change to baseline DDL, roles, extensions, or the source
  PG image invalidates the entry. Cached images carry the
  `org.pgrls.cache=baseline` label, so users can prune them
  with:

  ```sh
  docker image prune --filter label=org.pgrls.cache=baseline
  ```

  Set `PGRLS_DIFF_APPLY_NO_CACHE=1` to disable the cache (useful
  when debugging or when the baseline genuinely changes every
  run and the commit overhead is pure waste).

- **`PGDATA=/var/lib/postgresql/pgrls-data` override** in the
  testcontainer. The official Postgres image declares
  `VOLUME /var/lib/postgresql/data`, so data written there
  doesn't end up in the container's filesystem layer and isn't
  captured by `docker commit`. Pointing PGDATA elsewhere puts
  the data in the container layer where the cache can capture
  it.

### Internal
- New helper module `pgrls.diff._apply_cache`:
  - `compute_cache_key(pg_image, baseline_sql, roles, extensions)`
    — deterministic SHA-256 truncated to 16 hex chars.
  - `image_exists(tag)` — best-effort lookup; degrades to False
    on any docker daemon error so the diff command stays robust.
  - `commit_baseline(container_id, tag)` — wraps
    `docker.containers.get().commit()` with the cache label.
- Added `docker` mypy override to silence missing-stub warnings.

## [0.5.1] - 2026-05-08

### Added
- **Auto-detect extensions in migration SQL** (issue #13 Phase 3).
  `pgrls diff --apply migration.sql` now walks the migration's
  pglast AST for `CREATE EXTENSION` statements and pre-installs
  each named extension in the ephemeral testcontainer (via
  `CREATE EXTENSION IF NOT EXISTS <name>`) before restoring the
  baseline. A migration that declares its own extensions just
  works — no extra flags needed.

- **`--extension <name>` flag** (repeatable). Use this when the
  *baseline* assumes an extension is already present (e.g. a
  `citext` column or `gen_random_uuid()` default that the
  migration doesn't redeclare). Without it, restoring the
  baseline DDL inside the testcontainer would fail at the
  `CREATE TABLE ... CITEXT` line.

  ```sh
  # Auto-detect: nothing extra needed.
  pgrls diff base.json --apply migration_with_create_extension.sql

  # Baseline uses citext that migration never touches:
  pgrls diff base.json --apply migration.sql --extension citext

  # Combine multiple:
  pgrls diff base.json --apply m.sql --extension citext --extension pgcrypto
  ```

  The flag is meaningful only with `--apply`; passing it without
  `--apply` emits a warning and is otherwise a no-op.

### Internal
- New helper module `pgrls.diff._migration_extensions` exposes
  `detect_extensions(migration_sql) -> list[str]` — pglast-AST
  walk for `CreateExtensionStmt`, deduplicated and sorted.
  Degrades gracefully on unparseable SQL (returns `[]` so the
  real psycopg error surfaces from `cur.execute(migration_sql)`).

## [0.5.0] - 2026-05-08

### Added
- **Migration-as-input for `pgrls diff`** (issue #13). New
  `--apply migration.sql` flag spins up an ephemeral Postgres
  testcontainer, restores the captured baseline via
  `Schema.to_sql()`, applies the migration SQL, introspects the
  result, and uses that as the diff's head. Lets CI gate
  deployments against the *post-migration* schema without
  applying the migration to a real database.

  ```sh
  pgrls diff base.json --apply migration.sql
  ```

  Mutually exclusive with `<head>`. Requires
  `pip install pgrls[diff-apply]` (testcontainers + Docker).
  The default install stays slim — testcontainers is heavy and
  most users don't need this path.

- **Snapshot v5** — adds per-column type info via the new
  `column_details` array on each table. v3 / v4 baselines still
  round-trip (`Schema.from_snapshot` accepts 3, 4, 5). The
  `Column` dataclass captures `name`, `data_type` (the canonical
  Postgres `format_type` rendering — `numeric(10,2)`, `timestamp
  with time zone`, etc.), and `is_nullable`. Required by the
  `--apply` flow's `Schema.to_sql()` emitter; v3 / v4 snapshots
  raise `ValueError` when used with `to_sql()`, with a clear
  "re-capture against v0.5+" message.

- **`Schema.to_sql()`** — emit DDL that re-creates the captured
  schema in an empty Postgres. Covers `CREATE SCHEMA IF NOT
  EXISTS`, `CREATE TABLE` with column types and nullability,
  `ALTER TABLE … ENABLE / FORCE ROW LEVEL SECURITY`, `CREATE
  POLICY`, and `GRANT`. Indexes, constraints, defaults, and
  generated columns are deliberately NOT emitted — the diff
  target is RLS-state changes, not data integrity, and the
  migration applies on top of the bare-minimum DDL. Roles
  referenced by policies / grants are NOT created — that's the
  `--apply` caller's responsibility (it pre-creates roles
  idempotently in the testcontainer before applying the DDL).

- **`pgrls[diff-apply]` extra** — pulls in
  `testcontainers[postgres]>=4.0` for the `--apply` path.
  Without it, `--apply` raises a clear "install
  pgrls[diff-apply]" error and the snapshot-vs-snapshot /
  snapshot-vs-DB paths continue working unchanged.

### Test coverage
- 22 new unit tests in `tests/test_schema_to_sql.py` covering the
  emitter's output shape (CREATE SCHEMA per distinct schema,
  CREATE TABLE column rendering, RLS toggles, policy clause
  composition, GRANT-per-role-pair, PUBLIC vs named role
  rendering, deterministic byte-identical output), plus a real-
  Postgres round-trip that captures a complex schema, emits SQL
  via `to_sql()`, applies it to a fresh container, re-introspects,
  and asserts `diff_schemas(...) == []`.
- 5 new integration tests in `tests/diff/test_cli_apply.py`
  covering the end-to-end `pgrls diff --apply` path: SAFE
  migration classification, DANGEROUS migration triggering exit 1,
  `--apply` + `<head>` mutual exclusion, migration SQL error
  surfacing as a clean ToolError, and the v3 / v4 baseline reject
  path with the "re-capture against v0.5+" message.

### Deprecations
- None. v0.5.0 is purely additive on top of v0.4.x.

### Phase plan (issue #13)
- Phase 1+2 (this release): snapshot v5, `Schema.to_sql()`,
  `--apply` CLI flag, end-to-end tests.
- Phase 3 (v0.5.x): extension auto-detect from migration SQL,
  cached intermediate state to avoid re-applying the baseline
  for repeated invocations.

## [0.4.2] - 2026-05-08

### Added
- **Z3 Phase 4 — TypeCast and arithmetic operators** (issue #12
  phase 4). Closes the v0.4.x roadmap's "still pending" items.
- **`TypeCast`** (`'a'::text`, `col::int`, etc.) translates against
  a small target-type → Z3-sort table:
  - `text`, `varchar`, `char`, `character`, `bpchar`, `uuid`,
    `name`, `citext` → Z3 String
  - `int`, `int2`, `int4`, `int8`, `integer`, `smallint`,
    `bigint`, `oid` → Z3 Int
  - `float4`, `float8`, `real`, `double`, `numeric`, `decimal`
    → Z3 Real
  - `bool`, `boolean` → Z3 Bool
  When the cast doesn't change the Z3 sort (e.g. `int8 → integer`,
  `text → varchar`), the inner expression's translation is
  returned unchanged. Sort-changing casts (`id::text` for an Int
  column) are modeled as opaque Z3 variables under the target
  sort — identical casts on base and head reuse the same variable;
  differing casts produce unrelated variables and the predicate
  falls through to `requires_review`.
- **Arithmetic operators** (`+`, `-`, `*`, `/`, `%`) on Int and
  Real operands. A typical RLS predicate like `score > col + 5`
  now translates faithfully. Type inference flows through the
  non-column operand (same shape as comparisons). Two-column
  arithmetic (`col_a + col_b`) defaults both columns to String,
  which Z3 then refuses, so the translator falls through to None
  for that shape — fine in practice because real RLS predicates
  use `col + literal`, not `col + col`.

### Cases this reclassifies (vs v0.4.1)

| Predicate change | v0.4.1 | v0.4.2 |
|---|---|---|
| `col = 'a'::text` ↔ `col = 'a'` | `requires_review` | `semantic_equivalent` |
| `col + 1 > 0` ↔ `col > -1` | `requires_review` | `semantic_equivalent` |
| `col - 3 > 0` ↔ `col > 3` | `requires_review` | `semantic_equivalent` |
| `col + 1 > 0` → `col + 5 > 0` (col > -5) | `requires_review` | `semantic_loosened` |
| `id::text = 'a'` (both sides) | `requires_review` | `semantic_equivalent` |

### Phase 4 closes issue #12

With Phase 4 shipped, [issue #12](https://github.com/pgrls/pgrls/issues/12)
covers the planned scope. Subquery-RHS `IN` remains a deliberate
non-goal — proper variable scoping is out of scope for the
predicate-implication contract; teams using subquery RLS
patterns continue to hit `requires_review` (the v0.3.x behavior).

### Test coverage
- 6 new tests in `tests/diff/test_z3_compare.py` (TypeCast
  no-op + sort-changing-opaque, arithmetic equivalence /
  widening / subtraction).
- 2 existing "unsupported → None" tests updated to assert
  Phase 4's new positive classifications.

## [0.4.1] - 2026-05-08

### Added
- **Z3 Phase 3 — function calls, COALESCE, CASE, BETWEEN** (issue
  #12 phase 3). Extends the AST → Z3 translator with the most-
  common predicate shapes that Phase 1 didn't cover.
  - **`FuncCall`** is modeled as a Z3 free variable (sort:
    String) keyed by the call's canonical RawStream rendering.
    The same call on base and head sides reuses the same Z3 var,
    so two predicates that reference the identical function call
    (e.g. `auth.uid()`, `current_setting('app.tenant')`) are
    comparable via implication. Aggregates, window functions,
    `FILTER (WHERE ...)`, and `WITHIN GROUP` aborts.
  - **`A_Expr` with `BETWEEN` / `NOT BETWEEN`** translates to the
    equivalent `lo <= expr AND expr <= hi` (or its negation).
    Symmetric variants (`BETWEEN SYMMETRIC`) abort. Type
    inference flows through the lo/hi literals to the bare
    ColumnRef on the lexpr side via the new
    `_resolve_binop_operands` helper.
  - **`CoalesceExpr` and `CaseExpr`** are translated as opaque Z3
    String constants keyed by canonical shape. Two identical
    `COALESCE` / `CASE` expressions on base and head reuse the
    same Z3 var; bodies that differ are seen as unrelated vars
    and the predicate falls through to `requires_review`.
- Reuse-friendly **`_resolve_binop_operands`** helper handles
  the bare-ColumnRef-on-one-side type inference for both
  comparisons and BETWEEN. `_binop_to_z3` now accepts ColumnRef,
  literal, FuncCall, COALESCE, CASE on either side.

### Cases this reclassifies (vs v0.4.0)

| Predicate change | v0.4.0 | v0.4.1 |
|---|---|---|
| `tenant = auth.uid()` → `tenant = auth.uid() AND deleted_at IS NULL` | `requires_review` | `semantic_tightened` |
| `x BETWEEN 1 AND 5` → `x BETWEEN 1 AND 10` | `requires_review` | `semantic_loosened` |
| `x BETWEEN 1 AND 10` ↔ `x >= 1 AND x <= 10` | `requires_review` | `semantic_equivalent` |
| `COALESCE(x, 'd') = 'foo'` → same with added AND clause | `requires_review` | `semantic_tightened` |

### Test coverage
- 8 new tests in `tests/diff/test_z3_compare.py` covering the
  Phase 3 nodes (function calls — identical / different args,
  BETWEEN / NOT BETWEEN, COALESCE, CASE, AND-tightening through
  function calls).
- 1 existing test renamed and re-asserted: the previous
  "function calls unsupported → None" pin is now Phase 3's
  "identical function calls → semantic_equivalent" pin.

### Phase 4 (still pending)
Packaging polish, optional-import fallback documentation, and
Type cast (`'a'::text`) / arithmetic in predicates remain on the
v0.4.x roadmap. Subquery-RHS `IN` is deferred — it requires
proper variable scoping which is out of scope for the simple
predicate-implication contract.

## [0.4.0] - 2026-05-08

### Added
- **Z3-based semantic predicate analysis** for `pgrls diff` (Phase
  1+2 of [issue #12](https://github.com/pgrls/pgrls/issues/12)).
  Predicate edits that don't match a syntactic pattern
  (`tightened_and`, `loosened_and_drop`, `loosened_or`,
  `tightened_or_drop`) now get a second-chance check via Z3
  implication: a predicate-pair is `semantic_equivalent` when both
  implications hold; `semantic_tightened` when head → base only
  (head admits a strict subset of base's row set — SAFE);
  `semantic_loosened` when base → head only (head admits a strict
  superset — DANGEROUS); falls through to `requires_review` when
  Z3 is incomparable, the AST uses an unsupported node, or
  `pgrls[diff-z3]` isn't installed.
- **`pgrls[diff-z3]` optional extra** — installs `z3-solver`
  alongside pgrls. Without it, `pgrls diff` uses only the syntactic
  patterns and falls through to `requires_review` for everything
  else (the v0.3.x behavior).
- **Phase 1 supported subset** in the AST → Z3 translator: bool/int/
  text columns, comparison operators (`=`, `!=`, `<`, `>`, `<=`,
  `>=`), boolean connectives (`AND`, `OR`, `NOT`), `IS NULL`/`IS
  NOT NULL` (modeled as opaque markers — sound but coarse), and
  `IN (literal-list)`. Real-world RLS predicate transformations
  outside this subset (function calls, type casts, arithmetic,
  subqueries) return `None` from the translator and fall through
  to `requires_review`. Phase 3 (function calls, COALESCE, CASE,
  BETWEEN) lands in v0.4.x patches.
- Three new `compare_predicates` result Literals
  (`semantic_equivalent`, `semantic_tightened`, `semantic_loosened`)
  routed through `_USING_RESULT_TO_CHANGE` and
  `_WITH_CHECK_RESULT_TO_CHANGE` in `pgrls.diff.policies`. Existing
  ChangeKind enum values reused — the new results map to
  `*_TIGHTENED`/`*_LOOSENED` with a Z3-flavored message variant
  in `_PREDICATE_RESULT_MESSAGES`.

### Test coverage
- 27 new unit tests in `tests/diff/test_z3_compare.py` covering
  every operator in the supported subset + the four
  classification quadrants (equivalent / tightened / loosened /
  incomparable) + the unsupported-node fallthrough paths +
  type-conflict abort.
- 5 existing `tests/diff/test_ast_compare.py` tests updated:
  cases that previously returned `requires_review` for shapes Z3
  can decide now correctly assert the `semantic_*` classification.
  Each test's docstring notes the v0.3- vs v0.4+ behavior so the
  intent of the change is visible in the diff.

## [0.3.1] - 2026-05-05

### Changed
- **Demo case 01 (`app.documents` — canonical clean tenant table)
  rewritten to use a proper PERMISSIVE + RESTRICTIVE pair.** v0.3.0
  added SEC012 (table has only RESTRICTIVE policies — silent
  deny-all). The demo's flagship "canonical clean shape" was using
  RESTRICTIVE-only and was therefore silently deny-all in real
  Postgres (verified empirically). uc01 now demonstrates the
  correct pattern: a PERMISSIVE policy grants tenant-scoped access,
  and a RESTRICTIVE policy enforces tenant scoping. `app.documents`
  is removed from `[lint.rules.SEC012].allowlist`. The first
  installment of [issue #11](https://github.com/pgrls/pgrls/issues/11);
  remaining cases land in v0.3.2+.

## [0.3.0] - 2026-05-04

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
