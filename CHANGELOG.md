# Changelog

All notable changes to pgrls.

The format follows [Keep a Changelog](https://keepachangelog.com/), and
this project adheres to [Semantic Versioning](https://semver.org/).
While in 0.x, the public surface is the CLI, the snapshot JSON shape,
and the `pgrls.toml` configuration schema; minor bumps may include
breaking changes — they will be called out in this file.

## [Unreleased]

### Added
- **`pgrls pr BASE HEAD` — one PR verdict combining lint + diff.** Runs the
  regression check (`pgrls diff` — did this change loosen an existing policy?)
  and the new-issue check (`pgrls lint` on the head — does the changed schema
  have RLS problems?) against two `pgrls snapshot` artifacts, and emits a single
  Markdown report (a policy-changes section + a findings section + a pass/fail
  verdict) with a single exit code — the payload a CI PR check posts. `--fail-on`
  gates the diff (default `dangerous`); `--lint-fail-on` gates the lint (default
  `warning`); either crossing its threshold exits 1. Pair it with offline
  snapshots (`pgrls snapshot --sql-file`/`--migrations`) to gate a PR on a
  Z3-verified RLS regression **without ever touching the target database**.
  The head's policy predicates are re-parsed so predicate rules (SEC004/SEC038/
  PERF001) run on a snapshot head just as they do on a live one; and when the
  head is an offline snapshot the report notes the catalog-dependent rules that
  could not be evaluated, so a clean verdict is never mistaken for full
  coverage. `--format text` for a plain-text verdict.
- **`pgrls snapshot --sql-file` — build a snapshot from raw DDL, offline.** The
  `snapshot` command now takes the same offline sources as `lint`/`fix`
  (`--sql-file`, repeatable, `-` for stdin; `--snapshot` to re-emit/upgrade an
  existing artifact), so a schema snapshot can be captured with **no database
  and no Docker**. `--migrations <dir>` resolves a project's layout-ordered
  migration files (Supabase / Prisma / Flyway / sqitch, auto-detected) and reads
  them **statically** — distinct from `lint --migrations`, which provisions an
  ephemeral Postgres. This unblocks the DB-free migration-review pipeline the
  GitHub PR checker is built on: snapshot each revision's migrations, then
  `pgrls diff base.json head.json --fail-on dangerous` gates a PR on a
  Z3-verified RLS regression **without ever connecting to the target database**.
  An offline snapshot carries only what CREATE/ALTER/GRANT DDL expresses (RLS
  flags, policies, columns, grants); a soundness caveat noting the absent
  catalog-only state is printed to stderr, and diffing an offline snapshot
  against a live-database one may show spurious differences. The snapshot also
  records its offline provenance (a `"source": "sql"` marker, preserved across a
  `--snapshot` re-emit), so a later `lint --snapshot` / `pgrls pr` treats every
  catalog-dependent rule as inert on it — the same rules `lint --sql-file`
  skips — rather than firing them on absent inputs (a false positive) or reading
  their silent no-op as coverage (a false clear). An explicit `--database-url`
  alongside an offline source is rejected (ambient `$DATABASE_URL` is ignored
  when an offline source is given), mirroring `lint`/`fix`.

### Fixed
- **Offline DDL analysis now replays `ALTER POLICY` / `DROP POLICY` / `DROP
  TABLE`.** `schema_from_sql` (the `--sql-file` / `sql=` engine behind
  `lint`, `fix`, `snapshot`, the MCP server, and the LSP) previously honored a
  policy's `CREATE` but silently discarded a later `ALTER POLICY` that loosened
  it or a `DROP POLICY` / `DROP TABLE` that removed it. On a migration script
  (`cat migrations/*.sql`) that meant a policy loosened after creation was
  modeled as its **pre-`ALTER`** form — a silent false-negative, and a
  false-SAFE for the DB-free `pgrls diff` gate (base and head snapshots came out
  identical). The builder now applies these in source order, so a mid-migration
  loosening or a dropped RLS guard is faithfully reflected; the diff gate exits
  nonzero on it. (Unfaithful only for a `DROP TABLE` immediately followed by a
  re-`CREATE TABLE` of the same name in one input — rare, and matching the
  existing two-pass limitation.)

## [0.49.0] - 2026-07-14

### Added
- **SEC052 (error) — Auth user table exposed through an API-schema view.** A
  view (or matview) in a PostgREST-exposed schema (default `public`) that reads
  `auth.users` as a FROM-clause source **without** scoping to the calling user
  runs with the view owner's privileges, so a REST caller reads every user's
  email / metadata at `GET /rest/v1/<view>` — Supabase advisor
  `0002_auth_users_exposed`. A regular view with `security_invoker` is safe (it
  runs as the caller, who cannot read `auth.users`); a view filtered to
  `id = auth.uid()` is a legitimate "my account" view and is not flagged (the
  caller-binding analysis is shared verbatim with SEC036). Like SEC049, it
  gates on the view actually granting a low-trust role a table-level SELECT — a
  view REVOKE'd from `anon`/`authenticated` (readable only by a backend role) is
  not API-reachable and is not flagged (a view exposed *only* via a column-level
  grant is a conservative miss — view column grants are not modeled).
  Unparseable bodies and transitive re-exposers abstain (soundness over
  recall). Distinct from VIEW001, which
  requires the referenced table to have RLS enabled; `auth.users` is
  grant-protected, not RLS-protected. Configurable (`schemas` / `grantees` /
  `tables` / `binding_functions` / `allowlist`); no auto-fix. This brings the
  catalog to **65 rules**.
- **Snapshot v22 → v23**: adds per-view `View.grants` (from `pg_class.relacl`)
  so SEC052 can confirm API-reachability. Additive and fail-closed — a pre-v23
  snapshot round-trips with `grants=()`. SEC052 is registered as a
  catalog-dependent rule, so on a pre-v23 snapshot (or a view-less SQL-file
  source) it is reported as **skipped** rather than silently passing — it does
  not slip past `--require-full-coverage`.
- Extracted SEC036's caller-binding AST analysis into
  `pgrls.rules._auth_binding` so SEC036 (policy `EXISTS` sub-selects) and SEC052
  (view bodies) share one implementation — the "reads `auth.users` without
  binding the caller" primitive is now defined once.
- **SEC053 (error) — Foreign table exposed in an API schema.** A foreign table
  (`pg_class.relkind = 'f'` — a `postgres_fdw` / `file_fdw` table or a Supabase
  *Wrapper* over Stripe / S3 / an external database) in a PostgREST-exposed
  schema (default `public`) that grants a table-level `SELECT` to a low-trust
  role (`anon` / `authenticated` / `PUBLIC`) is directly readable at
  `GET /rest/v1/<ft>` — Supabase advisor `0017_foreign_table_in_api`. A foreign
  table **cannot carry RLS** (Postgres rejects `ENABLE ROW LEVEL SECURITY` on
  it), so the read is unfilterable and every remote row is returned. The
  foreign-table sibling of SEC049 (table) and SEC052 (view): the same "exposed
  schema + low-trust grant = HTTP-reachable" conjunction, for the one relation
  type that *structurally* cannot be row-filtered. Conservative — only a direct
  table-level SELECT grant to a role in `grantees` counts (foreign-table column
  grants are not modeled). Configurable (`schemas` / `grantees` / `allowlist`);
  no auto-fix — `REVOKE` the grant, move the table out of the exposed schema, or
  front it with a `security_invoker` view. This brings the catalog to
  **66 rules**.
- **Snapshot v23 → v24**: adds the top-level `foreign_tables` array (relkind
  `'f'` relations and their grants) so SEC053 can see foreign tables — modeled
  separately from `Schema.tables` so the table rules (SEC001, SEC049, …) never
  fire on them. Additive and fail-closed — a pre-v24 snapshot round-trips with
  `foreign_tables=()`. SEC053 is registered as a catalog-dependent rule, so on a
  pre-v24 snapshot (or a foreign-table-less SQL-file source) it is reported as
  **skipped** rather than silently passing — it does not slip past
  `--require-full-coverage`.
- **SEC054 (error) — Materialized view exposed in an API schema.** A
  materialized view in a PostgREST-exposed schema (default `public`) that grants
  a table-level `SELECT` to a low-trust role (`anon` / `authenticated` /
  `PUBLIC`) and whose body reads an RLS-enabled table serves every captured row
  at `GET /rest/v1/<matview>` — Supabase advisor `0016_materialized_view_in_api`.
  A matview stores its rows physically and is read without re-evaluating its
  body, so RLS on the source tables is never applied, and there is no
  `security_invoker` hook to scope the read. The matview sibling of SEC049
  (table) / SEC052 (auth-users view) / SEC053 (foreign table). It is the
  **confirmed-exposure sharpening of VIEW003** — which warns (`warning`) on *any*
  matview over an RLS table, an architectural caution that may be fine for an
  internal, un-exposed matview: the two intentionally co-fire on an anon-exposed
  matview (the SEC049↔SEC001 precedent), with SEC054 flagging the API-reachable
  subset at `error`. A matview reading only non-RLS tables (public reference
  data) is not flagged (the zero-FP gate). Like SEC049, only a direct table-level
  SELECT grant to a low-trust role counts (a matview column grant is a
  conservative miss). Configurable (`schemas` / `grantees` / `allowlist`); no
  auto-fix. No snapshot change — matviews are already captured as views with
  their grants (v23). This brings the catalog to **67 rules**.
- **`pgrls lsp`** — a stdio Language Server (optional `pgrls[lsp]` extra, via
  `pygls`) that lints the `.sql` buffer you are editing **in real time**, in any
  LSP client (VS Code, Neovim, Helix, JetBrains). It runs the same offline
  `schema_from_sql` engine as `pgrls lint --sql-file` on each change and
  publishes findings as diagnostics **pinned to the exact `CREATE TABLE` /
  `CREATE POLICY` / `GRANT` line** (mapping each finding's
  `schema.table[.policy|.column]` back to its statement's
  `stmt_location`/`stmt_len` span — a sensitive-column-grant finding underlines
  its `GRANT`, not the table) — the precise source ranges a live-database lint
  can't produce. It reads the project's `pgrls.toml` (from the workspace root,
  or the opened file's own directory when there is no workspace folder), so
  `disable`, per-rule `allowlist`s, `severity_overrides`, and `extra_rules`
  match the CLI/CI gate; an invalid config is surfaced once and linting falls
  back to defaults. Diagnostic-only: it never connects to a
  database and never edits files. Rules that need live catalog state are skipped
  exactly as in `--sql-file` (quiet diagnostics are not a proof of safety — run
  `pgrls lint` in CI for full coverage). `pygls` is an optional extra; the CLI
  never imports it, and `pgrls lsp` raises a clear "install pgrls[lsp]" error if
  it is absent — the same lazy-import contract as `pgrls mcp`. Implements #227.

## [0.48.2] - 2026-07-10

### Fixed
- **`pgrls verify --probe` no longer manufactures a false `LEAK CONFIRMED` /
  `MISMATCH`.** To reach a policy's `TO <role>`, the probe grants its throwaway
  role membership in that role — but if the role is (or inherits) the table
  owner, then on a table with RLS enabled **but not `FORCE`'d** (the Postgres
  default) the probe role acquires the owner's RLS exemption and reads every
  row, so a *genuinely-isolated* policy (`FOR ALL TO app USING (tenant_id =
  auth.uid())` on an `app`-owned table) was reported as a live-reproduced leak.
  The probe now gates every observation on `row_security_active()` for the probe
  session and **abstains** when RLS isn't actually enforced, rather than
  crediting a fabricated bypass.
- **`pgrls verify --probe` is no longer *weaker* than plain `pgrls verify`.** A
  soundly proven static `LEAK` the live probe couldn't reproduce (e.g. it
  abstained on an un-seedable `NOT NULL bytea` column) flipped the exit code
  1 → 0 — a CI job that added `--probe` for extra rigor silently green-lit a
  schema `verify` fails. The probe gate now also fails on any proven static
  leak (text/JSON/SARIF and exit code), so `--probe` is always at least as
  strict as `verify`; a static leak the probe can't reproduce appears as a
  SARIF `error` (no more empty red check).
- **`pgrls verify --mode escalation` no longer over-abstains on a benign
  built-in call.** 0.48.1's scalar-`FuncCall` abstention only recognized a
  built-in when it was `pg_catalog`-qualified, but an introspected function
  body (raw `pg_proc.prosrc`) stores builtins **unqualified** — so a harmless
  `SELECT count(*) FROM app_config` (a non-RLS table) was wrongly reported
  `UNVERIFIED` with a note claiming it "reads via a view/function". Bare calls
  to a recognized built-in (`count`, `now`, `lower`, …) are now treated as
  reading no user data; only a call to an *unknown* (likely user-defined)
  function forces abstention. A built-in missing from the set merely abstains
  (sound); the set holds only genuine `pg_catalog` builtins.
- **`pgrls verify --against` no longer reports a leak as "fixed" when it only
  became *unprovable*.** A base table proven `LEAK` whose head verdict is
  `UNVERIFIED` (e.g. the change added an opaque construct) was counted under
  "Leaks fixed by this change" — falsely reassuring. A leak now counts as fixed
  only when head proves it `ISOLATED` (or the table was dropped), the symmetric
  counterpart of never crediting an unprovable *base* with a new leak.
- **`pgrls verify --against --format sarif --strict`** now includes
  newly-`UNVERIFIED` tables (as `note` results) — previously `--strict` could
  exit non-zero on them while emitting an empty SARIF file (a red check with no
  alerts). The text label for those tables was also corrected (they may have
  been isolated *or absent* in the baseline).
- **Docs**: refreshed the pre-commit example `rev` (`v0.47.0` → `v0.48.1`; the
  `pgrls-lint-sql` hook it demonstrates only exists since 0.48.0), corrected two
  stale `pgrls fix` auto-fix rule lists in `AGENTS.md` (now the full 20), and
  added the `escalation` mode to the MCP `verify`-tool description in the
  README.

## [0.48.1] - 2026-07-08

### Fixed
- **`pgrls verify --mode escalation` — soundness fix for the SEC042 SECDEF-body
  check (a false-clear).** A `SECURITY DEFINER` function that reads a protected
  table through a **scalar function call** (`SELECT get_secret()`, `SELECT 1
  WHERE leaks()`) was silently reported clean: the abstention gate only looked
  for a set-returning function in `FROM`, so a scalar `FuncCall` in the target
  list / `WHERE` slipped through and the body was cleared — exit 0, empty SARIF —
  while an unauthenticated `POST /rpc/fn` could read RLS-protected rows via the
  owner's bypass. The body is now treated as opaque (`UNVERIFIED`) when it
  contains any scalar call to a function that is not a known auth/session
  function or a `pg_catalog` / `information_schema` builtin. Auth calls
  (`auth.uid()`) and builtins do not read user tables, so a direct read filtered
  by `auth.uid()` is still a proven `LEAK` (recall preserved). No snapshot or
  configuration change.
- **`pgrls verify` — soundness fix for restrictive-floor composition (a false
  `PROVEN`).** When a leaking permissive policy shared a table with a
  `RESTRICTIVE` floor (0.48.0's composition feature), the floor was AND-ed into
  the proof without checking that it actually applies to the same **role** and
  **write operation** — so two shapes were wrongly proven `ISOLATED`: (1) a
  floor scoped `TO authenticated` composed into an **anon** proof it doesn't
  govern (e.g. permissive `TO public USING (is_public)` + restrictive
  `TO authenticated USING (tenant_id = auth.uid())`); and (2) in `--mode write`,
  a `FOR UPDATE` floor composed into a `FOR INSERT` leak proof (a `FOR UPDATE`
  policy never gates an `INSERT`). A floor is now composed only when it covers
  **every** role and write-operation the permissive admits (`p.roles ⊆ r.roles`
  or the floor is `TO PUBLIC`; and `ops(p) ⊆ ops(r)`); otherwise the leak stands
  rather than risk a false `ISOLATED`. Soundness-preserving — legitimately
  covering floors still upgrade to `ISOLATED`. No snapshot or configuration
  change.
- **SEC049** now honors an **unqualified (bare) table name** in
  `[lint.rules.SEC049].allowlist`. The allowlist validator accepts both `table`
  and `schema.table`, but the match compared only against the qualified name, so
  a bare entry (e.g. `allowlist = ["countries"]`) validated fine yet silently
  failed to exempt the table — SEC049 kept flagging a table the user had
  explicitly allowlisted. It now uses the shared `table_in_allowlist` helper
  (bare name **or** `schema.table`), consistent with the other table-scoped
  rules (SEC001/SEC002/SEC030/…). No snapshot or configuration-schema change.

## [0.48.0] - 2026-07-04

### Added
- **`pgrls verify --against BASE`** — the "no new provable leak" PR gate. Verify
  the live schema, then compare against a baseline (`BASE` is a committed `pgrls
  snapshot` JSON or a DB URL) and report only the leaks *this change introduced*:
  a table proven `ISOLATED` in `BASE` (or absent from it) that the head now
  proves `LEAK`. Exits non-zero **only** on a newly-introduced leak — pre-existing
  leaks don't fail the gate — so a team can adopt `verify` in CI without first
  clearing its whole backlog. A `BASE` table that was `UNVERIFIED` is never
  counted as newly-leaking (soundness: a leak is attributed to the change only
  when the base *proved* isolation). Works with every `--mode`; `--format
  text`/`json`/`sarif` (SARIF carries only the new leaks). The text/JSON report
  also lists leaks the change *fixed*.
- **`pgrls verify --mode write --emit-repro`** now emits a runnable
  reproduction (previously write-mode was rejected as a follow-on). For a
  cross-tenant *write* leak the generated `.sql` + pytest authenticate as tenant
  A and **INSERT a row stamped for tenant B**, asserting the write is *admitted*
  — the leaking `WITH CHECK` let a cross-tenant row through; a fixed check
  rejects it (SQLSTATE 42501), turning the test red. The leak signal is
  admission, not a returned row (RLS hides `RETURNING` even for an admitted
  write). Runs as a `NOSUPERUSER`/`NOBYPASSRLS` runner, so a fixed policy
  provably rejects the INSERT (live-validated). Covers `FOR INSERT` / `FOR ALL`
  leaks; a `FOR UPDATE`-only leak is skipped (not mis-reproduced by an INSERT).
  `--mode escalation --emit-repro` now points to `--probe` (the SET-ROLE chain
  has no static reproduction).
- **pre-commit**: a second published hook, **`pgrls-lint-sql`**, lints raw DDL
  **offline** (`--sql-file` / `--snapshot`) — so pgrls now runs as a *commit-time*
  pre-commit hook with no Docker and no database, not only the live-DB
  `pgrls-lint` (which stays for `pre-push`). Both are whole-schema
  (`pass_filenames: false`). Refreshed the stale README example (bumped `rev`,
  dropped the non-expanding `--database-url=$DATABASE_URL` arg — `$DATABASE_URL`
  is read from the environment).

### Changed
- **`pgrls verify` now composes restrictive floors into the proof.** A leaking
  permissive policy on a table that also carries a `RESTRICTIVE` policy was
  previously reported `UNVERIFIED` ("floors not combined in v1"). The prover now
  re-proves `permissive ∧ (all restrictive)` — a row is visible only if it
  satisfies *some* permissive **and** *all* restrictive policies — and returns a
  real verdict: `ISOLATED` when the floor provably blocks the leaking row,
  `LEAK` when it doesn't (only a floor predicate outside the decidable fragment,
  or a `cross-tenant`/`write` floor the prover can't reduce to a scoping
  equality, stays `UNVERIFIED`). Live-validated against real Postgres RLS. No
  new false PROVEN/LEAK — soundness unchanged; strictly fewer abstains.
- **PERF001** now also flags — and `pgrls fix` wraps — an auth-function call
  nested inside a **correlated** subquery, the common RLS membership pattern
  `EXISTS (SELECT 1 FROM members m WHERE m.org_id = t.org_id AND m.user_id =
  auth.uid())`. A correlated subselect is re-executed once per outer row, so a
  bare `auth.uid()` / `current_setting(…)` inside it is evaluated per row
  exactly like a top-level call; the `(SELECT …)` wrap collapses it to one
  InitPlan call. An **uncorrelated** subquery (`user_id IN (SELECT auth.uid())`)
  runs once regardless of the outer row and is left alone, so detection is
  scoped to where the rewrite helps. An already-wrapped call inside a
  correlated subquery stays silent — no false positive — pinned by the corpus
  `sec004-is-null-in-subquery-safe` case; the new correlated detection is
  covered by unit tests and verified end-to-end on a live Postgres
  introspection. Closes a recall gap that AI code reviewers repeatedly flagged
  on `pgrls fix` output. No snapshot or configuration-schema change.

## [0.47.0] - 2026-06-29

### Added
- **`pgrls verify --mode escalation`** — a fourth threat model that proves or
  refutes the static **SEC048** reachability finding. A low-trust role that is a
  member of a table's owner (and the owner is not superuser / `BYPASSRLS`) can
  `SET ROLE` to it and, on the owner's RLS-enabled-but-not-`FORCE`'d tables,
  bypass RLS entirely. The mode composes the role-reachability closure
  (`Schema.owner_reachable_members`) with the cross-tenant prover: **LEAK** when
  the table's RLS provably isolates tenants (the reachable bypass defeats it) or
  only *partially* leaks cross-tenant (the bypass additionally exposes the other
  tenants' rows the partial leak hides — witnessing every row), **ISOLATED** only
  when the table already leaks every row cross-tenant anyway (the bypass adds
  nothing — ceded to `--mode cross-tenant`), **UNVERIFIED** when the predicate is
  unprovable. Turns a noisy SEC048 warning
  into an evidenced leak — or clears it. No snapshot change. It also proves the
  **SEC042** case — an anon / `PUBLIC`-EXECUTE-able SECURITY DEFINER function
  owned by an RLS-exempt role whose SQL body reads an RLS table — against that
  table's `anon` verdict (same total-vs-partial witness discrimination). It
  abstains (UNVERIFIED) on anything it cannot see through — an opaque PL/pgSQL or
  dynamic-SQL body, or a body that reads via a view, a function call, or a
  relation outside the analyzed schema — and honors the same
  `[lint.rules.SEC042].anon_roles` exposure set the lint rule uses (default
  `{anon, PUBLIC}`). `--probe` **confirms the SEC048 owner-bypass live**: it
  seeds a tenant-B row, authenticates the session as a different tenant A, then
  `SET ROLE`s to the reaching member and on to the owner — a correctly-scoped
  tenant-A session is denied B's row, so the member reading it (directly when it
  `INHERIT`s the owner, else via the `SET ROLE` to the owner) is a
  `leak_confirmed`; it abstains on any permission error and never commits (one
  rolled-back transaction). The VIEW004 *caller* case (needs the view's grants,
  which the model does not capture), the SEC042 SECDEF `--probe`, and
  `--emit-repro` for this mode remain follow-ons. (#232)
- `pgrls diff` now detects a **renamed RLS policy** and reports it as a single
  `POLICY_RENAMED` change instead of an independent drop + add (the long-reserved
  `ChangeKind.POLICY_RENAMED` is now produced). Configurable via
  `[diff].rename_detection` (`off` | `strict` (default) | `relaxed`) and
  `[diff].rename_classification` (`safe` (default) | `requires-review`), with
  matching `--rename-detection` / `--rename-classification` CLI flags.
  Matching is sound: only a unique 1:1 policy pair identical on
  (permissive, command, roles) with predicate-equal USING/WITH CHECK is treated
  as a rename; ambiguous cases fall back to drop+add.
- **Offline schema source for `lint` / `fix` / `generate`.** New `--sql-file`
  (raw DDL; repeatable; `-` for stdin) and `--snapshot` flags analyze a schema
  with no live Postgres and no Docker — promoting the engine the MCP server
  already ships. Offline runs can only under-report: catalog-only rules are
  explicitly skipped and surfaced (`skipped_rules` in `--format json`;
  `lint --require-full-coverage` fails a partial run). `--apply` is rejected
  offline (emit-only). (#225)
- **SEC049 (warning) — PostgREST-exposed table readable by a low-trust role.**
  Flags a table in an API-exposed schema (default `public`) that grants SELECT
  (table- or column-level) to `anon` / `authenticated` / `PUBLIC` **and** has no
  effective row filter — RLS off, or RLS on with only a permissive `USING (true)`
  `SELECT`/`ALL` policy that **applies to the granted role** and nothing
  restrictive to constrain it — so it is directly readable at
  `GET /rest/v1/<table>`. (Evaluated per grantee, so a `USING (true)` policy
  scoped to a different role — the `TO service_role` backend bypass — does not
  trip it on the granted `anon`/`authenticated`.)
- **SEC050 (warning) — Supabase Storage policy not scoped to a bucket.** In
  `storage.objects` (where all object access is RLS-enforced), flags a permissive
  policy whose row-reach clause (`USING` for SELECT/UPDATE/DELETE/ALL, `WITH
  CHECK` for INSERT) authorizes by owner or path but references no `bucket_id`
  condition — so it applies to **every** bucket, letting a caller authorized for
  one bucket reach objects in another (Supabase's own guidance: *"your RLS
  policy must explicitly specify the `bucket_id` condition"*). Literal
  `USING (true)` is ceded to SEC008/SEC006; a restrictive `bucket_id` floor keeps
  it silent; only `storage.objects` is examined (no `storage` schema → no
  findings). Allowlist by policy id; no auto-fix. Pure rule logic — no
  introspection or snapshot change. Catalog now **63 rules**. (#233) The *conjunction* that SEC001 /
  SEC003 / SEC008 each report a precondition of in isolation; fires once, naming
  the HTTP-reachable consequence. Conservative by construction: a real policy, or
  any restrictive policy not provably `true`, is treated as protection, so the
  normal RLS-gated Supabase grant is **not** flagged. Configurable `schemas` /
  `grantees` / `allowlist`; no auto-fix. Catalog now **62 rules**. (#234)
- **SEC051 (warning) — Realtime-published table has RLS disabled.** Flags a
  table in the Supabase `supabase_realtime` publication (membership resolved via
  `pg_publication_tables`, so `FOR ALL TABLES` / schema publications are
  expanded) with row level security off — Supabase Realtime then broadcasts every
  row change to all subscribed clients without policy filtering, a side channel
  past the table's REST-API row filtering. The Realtime-channel analog of SEC001,
  sharpened to the broadcast consequence; co-fires with SEC001. RLS-enabled
  members are filtered by Realtime per-policy and not flagged; only the
  configured `publications` set (default `supabase_realtime`) counts. Needs new
  publication introspection (snapshot **v22**); inert on the offline `--sql-file`
  source. Configurable `publications` / `allowlist`; no auto-fix. Catalog now
  **64 rules**. (#233)

### Changed
- **Snapshot format → v22.** Adds a per-table `in_publications` array (the
  publications a table belongs to, resolved via `pg_publication_tables`) for
  SEC051. Additive and fail-closed: a pre-v22 snapshot loads with
  `in_publications = ()`, so SEC051 finds nothing until the snapshot is
  re-captured.
- In `relaxed` mode, a rename whose predicate also changed is graded by predicate
  direction (loosen → DANGEROUS, tighten → SAFE, otherwise REQUIRES_REVIEW) rather
  than a blanket REQUIRES_REVIEW, so a loosening still trips `--fail-on dangerous`.
  Note: relaxed pairing is a coarse heuristic (unique match on permissive/command/roles);
  an unrelated drop+add sharing those attributes can be treated as a rename and a
  coincidental pairing could grade a real restrictive drop as `safe`. For security-gating
  CI keep the default `strict` mode — relaxed mode trades this soundness for fewer
  findings and has no reliable `--fail-on` threshold that catches only the coincidental-
  pairing case.
- **PERF001 now flags unwrapped auth-function calls in `WITH CHECK`, not just
  `USING`.** A bare `auth.uid()` / `current_setting(…)` in a policy's `WITH CHECK`
  is re-evaluated once per written row — a 1000-row `INSERT` or `UPDATE` calls it
  1000 times; wrapping it as `(SELECT …)` collapses that to a single InitPlan
  call, exactly as for `USING` (verified empirically with a call-counting
  function — the earlier "Postgres optimizes `WITH CHECK` differently" assumption
  was wrong). The rule emits one finding per policy, naming the clause(s)
  involved, and `pgrls fix --rule PERF001` now wraps `WITH CHECK` too, emitting
  only the clause(s) it changes. This raises PERF001's recall on
  `INSERT` / `UPDATE` / `ALL` policies; allowlist a policy or scope
  `auth_functions` to tune.

### Fixed

- **`pgrls diff` no longer crashes on a policy predicate that OR/AND-combines a
  column comparison with a bare boolean function call** (e.g. `tenant_id = 1 OR
  is_admin()`). The Z3 comparator translated the function call as an opaque
  String marker, so building `z3.Or` / `z3.And` over the mismatched sorts raised
  an uncaught `z3.Z3Exception: sort mismatch` and aborted the diff. The
  boolean-connective translator now catches it at its source and degrades the
  predicate to `requires_review` — the safe direction — exactly like every other
  untranslatable operator. (A genuine loosening is still detected; only the
  un-encodable case degrades.)

## [0.41.0] - 2026-06-21

### Added

- **`pgrls verify --probe --format sarif`** — the live runtime probe now emits a
  SARIF v2.1.0 document for GitHub Code Scanning, alongside `text` and `json`. A
  **MISMATCH** (the static proof and the live database disagree) and a **LEAK
  CONFIRMED** (a live-reproduced leak) each become an `error`-level result —
  located at `schema.table` and `schema.table.policy` respectively; AGREE /
  skipped produce no result; under `--strict` an abstain becomes a `note`. One
  rule per `--mode` (`pgrls-probe-anon` / `-cross-tenant` / `-write`), kept
  distinct from the static `verify` SARIF rules. Reuses lint's `format_sarif`
  projection, so the SARIF schema and driver block stay in one place.
- **`pgrls fix` now auto-remediates SEC044** (default privileges grant future
  tables to a low-trust role) — the **20th** auto-fixable rule. It emits the
  matching `ALTER DEFAULT PRIVILEGES [FOR ROLE <grantor>] [IN SCHEMA <s>] REVOKE
  <row-access privs> ON TABLES FROM <grantee>`, a strictly *narrowing* fix that
  never widens access and — because default privileges are not retroactive —
  changes no existing table (only the standing future-facing grant). Only the
  row-access privileges the rule flags are revoked; a co-granted
  REFERENCES/TRIGGER/TRUNCATE default is left alone. The `FOR ROLE <grantor>`
  clause is emitted whenever the grantor is known (a bare REVOKE clears only the
  running role's own default). Auto-fixable count → **20 of 61** rules.
- **MCP server — two emit-only remediation tools (`fix`, `generate`).** The
  `pgrls mcp` server now exposes **six** tools (was four). `fix` returns the
  auto-fix SQL for the mechanically-fixable findings — the remediation
  counterpart of `lint`; `generate` scaffolds gold-standard RLS (ENABLE +
  FORCE + tenant/owner policy + restrictive floor + index) for unprotected
  tables. Both accept the same schema sources as `lint` (`sql` / `database_url`
  / `snapshot`) and return structured statements plus a copy-pasteable
  `migration`. They are **emit-only**: like the rest of the server they never
  mutate a database (only read-only introspection on the live path) and never
  apply the SQL they return — `fix --apply` / `generate --apply` /
  `diff --apply` / `verify --probe` remain unexposed.
- **SEC048 (61st rule, warning)** — *low-trust role can reach an RLS table's
  owner that is not FORCE'd*. A role that OWNS a table bypasses that table's RLS
  unless `FORCE ROW LEVEL SECURITY` is set, and owner privileges (unlike the
  `BYPASSRLS` attribute SEC029 covers) ARE reachable through role membership: a
  member of the owning role inherits its ownership — automatically with
  `INHERIT`, or after a `SET ROLE` with `NOINHERIT` — and so bypasses RLS on the
  owner's enabled-but-not-`FORCE`'d tables (live-proven on PG16; `FORCE` is the
  exact non-leak boundary). The table-owner analog of SEC029, it fires once per
  reachable member role (location = the member name), restricted to owners and
  members that are NOT superuser/`BYPASSRLS` (which keeps it disjoint from
  SEC016/SEC029), and co-fires with SEC002 — which reports the table — on the
  same missing-`FORCE` misconfiguration by design. Configurable via
  `[lint.rules.SEC048]` `allowlist` (trusted member roles) and
  `trusted_owner_roles` (expected shared owners); no auto-fix. Snapshot v21 adds
  per-table `owner` and the top-level `owner_reachable_members` closure
  (additive, fail-closed: a pre-v21 snapshot abstains until re-captured).

## [0.40.1] - 2026-06-20

### Fixed

- **`pgrls verify --mode anon` no longer reports a false `leak` on a never-NULL
  `current_setting(...) IS NULL` disjunct.** A predicate like
  `current_setting('app.x') IS NULL OR tenant_id = auth.uid()` is genuinely safe
  under anon — the one-arg (and two-arg `missing_ok=false`) `current_setting`
  raises on an unset GUC and is otherwise non-NULL, so the disjunct is dead. The
  Z3 satisfiability path was assigning it a free null-flag and manufacturing a
  leak, disagreeing with SEC038 (which correctly stayed silent); the anon
  encoder now pins these never-NULL calls to non-NULL, matching the linter.
- **`pgrls verify --probe` now confirms `(SELECT auth.uid())`-wrapped policies.**
  The dominant Supabase / PERF001 idiom wraps the auth call in a scalar
  sub-select; the probe treated *any* sub-select as "references other tables" and
  abstained, neutering it on most real schemas. A bare scalar `(SELECT <expr>)`
  is now unwrapped (mirroring the Z3 encoder), so the probe runs; genuine
  subqueries (`EXISTS`, `IN`, FROM-bearing) still abstain.
- **`pgrls verify --probe` now applies role-scoped policies.** The throwaway
  probe role is best-effort granted each policy's named `TO` roles (e.g.
  `authenticated`), so a `TO authenticated` policy actually applies to it instead
  of being default-denied and mis-reported; the role stays
  `NOSUPERUSER`/`NOBYPASSRLS` so RLS still decides visibility.

### Docs

- Corrected stale rule counts in `README.md` and `AGENTS.md` (fifty-seven →
  sixty; `SEC001–SEC044` → `SEC001–SEC047`) and added `SEC010` to the README
  auto-fixable rule list.

## [0.40.0] - 2026-06-19

### Added

- **`pgrls mcp`** — an optional Model Context Protocol server (stdio) that
  exposes pgrls's analysis to AI coding agents. The headline is **offline**
  analysis of the raw DDL an agent just wrote: pass the `CREATE TABLE` /
  `CREATE POLICY` SQL as `sql=` and pgrls lints it and runs the full Z3
  isolation prover with **no database** — `pglast` builds a `Schema` with
  populated policy ASTs straight from the DDL. Four read-only tools:
  - `lint(sql= | database_url= | snapshot=, …)` → the lint findings (same JSON
    violation shape as `pgrls lint --format json`), plus `schema_source` and a
    `warnings` list.
  - `verify(sql= | database_url= | snapshot=, mode=anon|cross-tenant|write, …)`
    → the per-table/per-policy verdicts and leak witnesses (`pgrls verify
    --format json`'s payload).
  - `explain_rule(rule_id)` and `list_rules()` → the rule catalog / a single
    rule's reference (same payloads as `pgrls explain --format json`).
- The three schema sources are mutually exclusive (exactly one per call), and
  each tool returns a **structured error object** (`{"error": {"kind", …}}`,
  kinds: `bad_sql` / `db_unreachable` / `unknown_rule` / `no_schema_source` /
  `multiple_schema_sources` / `z3_unavailable`) instead of raising, so a bad
  input never breaks the stdio loop.
- The server is **read-only / diagnostic-only**: it never mutates a database and
  never auto-applies SQL (`fix` / `generate` / `diff --apply` / `verify
  --probe` are deliberately not exposed). `database_url` is treated as a
  credential — it is never logged and database errors are sanitized so the DSN
  can't leak. Introspection issues only SELECTs over a short-lived connection.
- **Caveat surfaced in the response, not hidden:** on the `sql=` path the
  `warnings` list notes that catalog-only rules (those needing pg_catalog state
  not expressible in DDL — BYPASSRLS roles, `pg_default_acl`, SECDEF owners,
  FKs, indexes, triggers) cannot fire, so an empty `violations` list is **not**
  a proof of safety. A `snapshot=` schema's policy ASTs are re-parsed on load so
  `verify` returns real verdicts rather than all-`unverified`.
- Requires the optional `pgrls[mcp]` extra (`pip install 'pgrls[mcp]'`, which
  adds FastMCP). FastMCP is **not** a core dependency — the normal CLI path
  never imports it; `pgrls mcp` imports the server lazily and prints a clear
  install hint when the extra is absent. Point an MCP client at it with
  `{"mcpServers": {"pgrls": {"command": "pgrls", "args": ["mcp"]}}}`.

## [0.39.0] - 2026-06-19

### Added

- **`pgrls verify --probe`** — a live runtime probe that confirms the static Z3
  proof against the real database. It connects as the threat-model session
  (anonymous, or authenticated as one tenant), seeds a throwaway row, runs the
  actual query the proof reasons about, and diffs the **observed** behavior
  against the verdict — all inside a transaction that is **rolled back**, so
  nothing is committed (the probe role it creates does not survive the rollback
  either). Per table × `--mode` it reports **AGREE** (proof and reality concur),
  **MISMATCH** (proof↔reality broken — a soundness break, or schema drift since
  the proof was computed), or **LEAK CONFIRMED**. The headline: an **UNVERIFIED**
  policy that turns out to leak live (e.g. reads scoped but `INSERT … WITH CHECK
  (true)`) is upgraded to a reproduced, exit-non-zero leak — the verifier's
  honest "no claim" turned into a live witness. Works in all three modes
  (`anon` / `cross-tenant` / `write`). It reuses `pgrls verify --emit-repro`'s
  GUC / identity / tenant-value synthesis verbatim, so the session it
  establishes is identical to the one the emitted reproduction would.
- With `--probe`, `pgrls verify` **exits non-zero on any proof↔reality mismatch
  or live-confirmed leak** (and, under `--strict`, on any table the probe had to
  abstain on). It needs a live `--database-url` and a connection that can create
  a role (CREATEROLE / superuser); anything it cannot reproduce live — no
  CREATEROLE, no INSERT path, no tenant-scoping axis, a conditional witness, a
  cross-table predicate, an exotic column type — it **abstains** on cleanly,
  per table, with a one-line reason (never a crash). `--probe` output supports
  `--format text` (the static proof stacked above the live AGREE/MISMATCH/LEAK
  CONFIRMED table) and `--format json`; **SARIF for the probe is deferred** and
  `--probe --format sarif` / `--probe --emit-repro` are rejected (run them
  separately).

## [0.38.0] - 2026-06-19

### Added

- **`pgrls fix` now auto-remediates SEC010** (policy clause is constant
  `false`) — the **19th** auto-fixable rule and the dual of the SEC031 fixer. A
  **permissive** policy whose access is constant-`false` grants nothing
  (permissive policies OR-combine, so `… OR false` adds no row, and `WITH CHECK
  (false)` admits no write; with RLS on it is the same default-deny as no
  policy), so the fixer emits `DROP POLICY` — a behavior-preserving cleanup. It
  is a strict subset of what the rule reports and **never broadens access**: a
  **restrictive** constant-`false` policy is a hard deny floor and is never
  dropped, and the fixer abstains on any permissive policy still granting on
  another axis (e.g. `FOR ALL USING (false) WITH CHECK (true)` still admits
  inserts). Brings the auto-fixable count to **19 of 60** rules.

## [0.37.0] - 2026-06-19

### Added

- **SEC047** (warning) — a **foreign key whose parent (referenced) table has RLS
  enabled** is a cross-tenant *existence* covert channel when a low-trust role
  can write the child. Postgres validates a foreign key as a **system integrity
  check** that runs with RLS suspended, so a low-trust caller inserting or
  updating a child row that references a *guessed* parent key learns whether that
  parent row exists (the write **succeeds**) or not (a **foreign-key-violation
  error**) — even though RLS hides that parent row from the caller's own
  `SELECT`. The caller cannot read the other tenant's row but can enumerate which
  parent keys exist across the isolation boundary (verified live on PG16 via both
  `INSERT` and `UPDATE`). This completes SEC035's arc: SEC035 is the UNIQUE-index
  existence oracle (same table), SEC047 is the FK-validation existence oracle
  (across tables, child → parent) — same mechanism, different catalog object. The
  detection is deliberately narrow (FKs to RLS parents are ubiquitous): it fires
  only when the parent has RLS enabled (plain `ENABLE` suffices — `FORCE` is not
  required) **and** the child is writable by a configured low-trust role (default
  `anon` / `PUBLIC`) — an `INSERT`/`UPDATE`/`ALL` table grant to that role, plus
  either RLS off or a permissive `INSERT`/`UPDATE`/`ALL` policy literally listing
  it. A deliberate posture over-approximation (like SEC044/SEC045): it does
  **not** prove the role's RLS visibility on the parent is narrower than all rows
  — that is unsound, since a role with plain table `SELECT` still leaks RLS-scoped
  rows via the FK (live-proven) — so narrowing by parent-visibility would *miss*
  real oracles. Abstains (fail-closed) when the parent can't be resolved in the
  snapshot (e.g. outside `--schemas`). Configurable `low_trust_roles` and
  `allowlist` (child `schema.table` or FK constraint name); no auto-fix (drop the
  FK, mediate via a SECURITY DEFINER existence check, or accept the leak — a
  design decision). Brings the catalog to **60 rules**.

### Changed

- **Snapshot format → v20.** Adds a per-table `foreign_keys` array (the
  `pg_constraint` `contype='f'` constraints on the child table — each with its
  child columns, referenced schema/table, and parent columns), the capture
  SEC047 reads. Emitted only when non-empty, so a table with no foreign keys
  round-trips byte-identically apart from the version bump. Additive and
  fail-closed: a v3–v19 snapshot has no key and loads with `foreign_keys=()`, so
  SEC047 finds nothing until the snapshot is re-captured against a live database.

## [0.36.0] - 2026-06-19

### Added

- **SEC046** (error) — a policy's `USING` / `WITH CHECK` calls a **user-defined
  function declared `IMMUTABLE`** whose body reads session/identity state
  (`current_setting(...)`, an `auth.*` helper, `current_user` / `session_user`)
  or a table. `IMMUTABLE` lets Postgres **constant-fold** the call at plan time,
  so under any reused or cached plan — a connection pooler reusing a backend
  (Supavisor / PgBouncer), PostgREST, a prepared statement, a PL/pgSQL plan
  cache — the value frozen for the connection that first planned the query is
  served to every later caller. Used in a row policy that is a silent
  cross-user wrong-row leak: the first user's tenant/identity value scopes
  another user's rows (verified live on PG16 — a second connection on the same
  backend sees the first's rows; the same body marked `STABLE` does not). The
  fix is to declare the function `STABLE`. A *correctness* finding distinct from
  SEC024 (policy reads a GUC) and PERF004 (function-wrapped discriminator
  defeats an index). False-positive boundary (all live-validated): an inline
  `current_setting` used directly in a policy is **safe** (a `STABLE` built-in
  that does not fold — only user-defined `IMMUTABLE` wrappers are flagged); a
  pure `IMMUTABLE` function (no session/table read) is **not** flagged; `STABLE`
  / `VOLATILE` functions never reach the rule (only `provolatile='i'` is
  captured). Abstains (fail-closed) on a PL/pgSQL / empty / unparseable body and
  on a pre-v19 snapshot. Configurable `allowlist` (`schema.function`); no
  auto-fix (pgrls cannot prove a function is meant to be volatility-downgraded
  vs. genuinely pure). Brings the catalog to **59 rules**.

### Changed

- **Snapshot format → v19.** Adds a top-level `immutable_functions` array (the
  user-defined functions with `pg_proc.provolatile='i'` in the introspected
  schemas, each with its `body` and `language`), the capture SEC046 reads.
  Additive and fail-closed: a v3–v18 snapshot has no key and loads with
  `immutable_functions=()`, so SEC046 finds nothing until the snapshot is
  re-captured against a live database.

## [0.35.0] - 2026-06-19

### Added

- **SEC045** (warning) — a **column-level** `GRANT` of a content privilege
  (`SELECT`/`INSERT`/`UPDATE`) on a PII / secret-named column (`email`, `ssn`,
  `phone`, `date_of_birth`, `credit_card`, `password`, `api_key`, …) to a
  **low-trust** role (`PUBLIC` / `anon`). A column grant is a deliberate,
  targeted act — nobody column-grants by accident — so handing the most
  sensitive field in a table to the least-trusted role is almost always an
  over-share. It is the column-grant + PII-sensitivity finding the other rules
  miss: SEC003 flags a PUBLIC *policy*, SEC001 a no-RLS *table*, SEC004/SEC038
  an anonymous-readable *policy* — none inspect column-level grants
  (`pg_attribute.attacl` → `Table.column_grants`) or weigh column sensitivity. A
  least-privilege / defense-in-depth posture finding (fires on the grant itself,
  like SEC044), so column grants only, content privileges only (a column-level
  `REFERENCES` exposes no content), default grantee set `{PUBLIC, anon}`, and a
  curated case-insensitive PII pattern set. Configurable `grantees` / `patterns`
  / `allowlist`; no auto-fix (whether a sensitively-named column is a deliberate
  public field is a product decision). Brings the catalog to **58 rules** (no
  snapshot bump — column grants are already captured).

## [0.34.0] - 2026-06-19

### Added

- **`pgrls verify --mode write`** — a Z3 proof that a session authenticated as
  one tenant cannot **write** (INSERT/UPDATE) a row stamped for a *different*
  tenant. The write side is the most CVE-adjacent RLS footgun (CVE-2025-48757):
  a policy that scopes reads but leaves its `WITH CHECK` unbound lets a caller
  stamp data for another tenant, and no other tool proves it. Write-isolation
  is the same satisfiability question as `--mode cross-tenant`, so it reuses the
  cross-tenant prover verbatim — applied to each write policy's **effective
  write-check**: its `WITH CHECK` when present (which fully overrides `USING`
  for the new row), else the `USING` that Postgres reuses as the new-row check
  for `FOR UPDATE` / `FOR ALL`. `FOR SELECT` / `FOR DELETE` policies (no
  write-check) and bare `FOR INSERT` policies (default-denied) are excluded.
  Verdicts mirror the read modes: `isolated` (proven — no cross-tenant row can
  be written), `leak` (a row stamped for another tenant can be written, with a
  witness), `unverified` (no provable scoping equality — e.g. an unscoped
  `WITH CHECK (true)`; run `pgrls lint` for SEC006 / SEC020 / SEC028 / SEC040,
  the write-check rules). Sound by construction: every Postgres write-check
  fallback is encoded so any modeling error degrades toward `unverified` /
  `leak`, never a false `isolated`. `--format json` / `sarif` carry the new mode
  (`pgrls-write-isolation` SARIF rule). `--emit-repro` is not yet supported with
  `--mode write`.

## [0.33.0] - 2026-06-19

### Added

- **`pgrls verify` now proves policies that use `= ANY(ARRAY[…])` / `IN (…)`
  membership.** The Z3 anonymous-read and cross-tenant provers previously
  abstained (returned `unverified`) on any policy whose `USING` contained a
  membership test — even though `IN (…)` is one of the most common predicate
  shapes, and every `IN` list normalizes to `= ANY (ARRAY[…])` on
  introspection. The 3VL encoder now models `col = ANY(ARRAY[<literals>])` as
  the exact desugaring `col = lit₁ OR col = lit₂ OR …`, so such policies get a
  definitive `isolated` / `leak` verdict (with a row witness) instead of
  `unverified`. This is a recall improvement only — it is an *exact* desugaring
  onto the existing, trusted Kleene comparison machinery, never an
  approximation, so it cannot produce a false `isolated`. The encoder
  deliberately still abstains (soundness over recall) on `<> ALL(…)` (the
  `NOT IN` normalization, the complement of membership), on `= ANY(<array
  column>)` / `= ANY(<function>)` (which need array-containment reasoning), and
  on any element it cannot translate.

## [0.32.0] - 2026-06-16

### Added

- **`pgrls fix` now auto-remediates SEC004** (the flagship inverted-auth
  anonymous-read leak — the Lovable-CVE `auth_func() IS NULL OR <check>`
  pattern). The fixer strips the `auth_func() IS NULL` disjunct from the
  policy's `USING`, restoring the real check (`a OR (auth.uid() IS NULL OR b)`
  → `a OR b`). It is a **security-narrowing** rewrite: SEC004 only ever fires
  on a top-level `OR` disjunct (the rule never flattens through `AND`/`NOT`),
  so the fixer descends only through `OR` and removing the disjunct can only
  narrow the policy, never broaden it. It abstains — leaving the finding for
  human review — when no real check would survive the strip (the `IS NULL`
  was the whole clause, or only a literal `true` remains). The
  semantically-disguised variants (`NOT … IS NOT NULL`, `COALESCE`) remain
  SEC038's domain and are not auto-fixed. Brings the auto-fixable count to
  **18 of 57** rules.

## [0.31.0] - 2026-06-15

### Added

- **SEC044** (warning) — a `pg_default_acl` entry for **tables** that grants a
  **row-access** privilege (`SELECT`/`INSERT`/`UPDATE`/`DELETE`) to a
  **low-trust grantee** (default set `{PUBLIC}`). `ALTER DEFAULT PRIVILEGES [IN
  SCHEMA s] [FOR ROLE r] GRANT … ON TABLES TO PUBLIC` does not touch any
  existing table — it records a standing rule that **every table created after
  it** (in scope) is automatically granted the privilege, so a developer who
  later adds a table and forgets `ENABLE ROW LEVEL SECURITY` silently exposes
  it to every role (including `anon` in a PostgREST/Supabase deployment).
  Default privileges are **not retroactive** — they affect only future tables —
  so SEC044 fires on the `pg_default_acl` entry itself, whether or not a table
  has been created under it yet: it is the standing config posture that is the
  footgun. A least-privilege / defense-in-depth finding that complements
  **SEC003** (PUBLIC policy) and **SEC001** (RLS-off table, after the fact).
  The grantee set is configurable via `[lint.rules.SEC044].grantees` (default
  `["PUBLIC"]`; a `"public"` entry is normalized case-insensitively to the
  PUBLIC pseudo-role) — `anon` / `authenticated` are **excluded by default**
  because granting future tables to those is the deliberate, RLS-gated Supabase
  pattern (flagging it would fire on every Supabase project). A schema-scoped
  entry is reported at its schema name; a cluster-wide entry (set without `IN
  SCHEMA`) at the sentinel location `(cluster-wide)` — and, because a
  cluster-wide default applies in every schema, it is reported on every
  `--schemas`-scoped run (not leakage; revoke or allowlist it to silence).
  Allowlist a deliberate default by schema name (or `(cluster-wide)`) in
  `[lint.rules.SEC044]`. The remediation names the entry's **grantor** in a
  `FOR ROLE <grantor>` REVOKE (`pg_default_acl` is keyed on the creating role,
  so a bare REVOKE clears only the running role's own default and silently
  no-ops against another's; two same-grantee defaults from different grantors
  are reported separately). No auto-fix: whether to revoke the default or scope
  it to a role is a deployment decision. Brings the catalog to **57 rules**.

### Changed

- **Snapshot format v18.** Adds a top-level `default_privileges` array (from
  `pg_default_acl`, `defaclobjtype='r'`) for SEC044, always emitted like the
  other top-level arrays. Each entry carries `schema` (null for a cluster-wide
  default), `grantee`, `privileges`, and `grantor` (the `defaclrole` whose
  table creation triggers the default — part of the entry's identity, so
  same-grantee defaults from different grantors stay distinct). Additive and
  fail-closed: snapshots from v3–v17 load with `default_privileges=()` (SEC044
  abstains on them until re-captured), and `Schema.from_snapshot` still accepts
  versions 3 through 18.

## [0.30.0] - 2026-06-15

### Added

- **SEC043** (warning) — a classic-`INHERITS` child (`CREATE TABLE child ()
  INHERITS (parent)`, **not** a declarative partition) whose row-level
  security is **disabled** while an ancestor in its inheritance DAG has RLS
  **enabled**, *and* which carries a direct **row-access** grant (table- or
  column-level `SELECT`/`INSERT`/`UPDATE`/`DELETE`) to a non-owner role.
  Postgres does not inherit RLS (or privileges) to inheritance children, so a
  query naming the granted child directly (e.g. a PostgREST `GET /child`, or a
  direct `SELECT`) bypasses the parent's policies and returns every row, while
  queries routed through the parent stay scoped. This is the classic-`INHERITS`
  analogue of **SEC041** (declarative partitions) — the two are mutually
  exclusive (a table is a partition child XOR a classic-inheritance child) and
  never double-report. Unlike a partition's single parent, an inheritance child
  may have multiple parents (a DAG); SEC043 fires if any ancestor enforces RLS.
  Note: unlike the partition case, SEC001 (and SEC032 for a dormant-policy
  child) also fires on the same child, because SEC001/SEC032 do not walk
  classic inheritance — a deliberate over-report; both findings point to the
  same fix (enable RLS on the child). Configurable via
  `[lint.rules.SEC043].allowlist`. No auto-fix. Catalog is now **56 rules**.
- **Snapshot v17** — `Table` gains `inherits` (the classic-`INHERITS` parents,
  as `(schema, name)` pairs), captured from `pg_inherits` rows whose child has
  `relispartition = false`, for SEC043. Emitted only when non-empty, so a table
  with no classic inheritance round-trips byte-identically apart from the
  version bump. Additive: v3–v16 snapshots load with `inherits=()` (SEC043
  finds no classic-inheritance ancestor until re-captured).

## [0.29.0] - 2026-06-15

### Added

- **SEC042** (error) — a `SECURITY DEFINER` function that is **executable by a
  low-trust role** (`anon` or `PUBLIC`) **and** whose **owner bypasses RLS** (a
  superuser or `BYPASSRLS` role). The function runs as its owner, so when the
  owner is RLS-exempt its body skips every policy; exposed to `anon`/`PUBLIC`
  it is an unauthenticated privilege-escalation endpoint — a PostgREST/Supabase
  `POST /rpc/<fn>` with the anon key runs owner-privileged, RLS-exempt code.
  Critically, a function's `EXECUTE` privilege **defaults to `PUBLIC`**, so a
  SECDEF function with no explicit `REVOKE EXECUTE ... FROM PUBLIC` fires even
  with no `GRANT` — the common silent mistake. Both conditions are required:
  SECURITY DEFINER alone is not a bypass (an ordinary owner under `FORCE ROW
  LEVEL SECURITY` is still subject to RLS — verified empirically), so SEC042
  stays high-confidence rather than re-flagging every SECDEF function. It is
  the anon-exposure sharpening of SEC014 (which audits all SECDEF functions),
  exactly as SEC039 sharpens SEC003. Configurable via
  `[lint.rules.SEC042].anon_roles` (default `["anon", "PUBLIC"]`) and
  `.allowlist`. No auto-fix (REVOKE vs re-own vs rewrite is architectural).
  Catalog is now **55 rules**.
- **Snapshot v16** — `SecdefFunction` gains `execute_roles` (the non-owner
  `EXECUTE` grantees, with the `PUBLIC`-default expanded) and
  `owner_bypasses_rls` (`rolsuper OR rolbypassrls` of the function owner), both
  for SEC042. Additive: v3–v15 snapshots load with `()` / `False` (SEC042
  abstains, fail-closed, until re-captured).

## [0.28.0] - 2026-06-15

### Added

- **SEC041** (warning) — a declarative partition **child** whose row-level
  security is disabled while an ancestor in its partition chain has RLS
  enabled, *and* which is granted directly to a non-owner role. Postgres
  inherits neither `relrowsecurity` nor privilege grants to partitions, so a
  query that names the granted child directly (PostgREST `GET /child`, a
  direct `SELECT`, an ORM/job targeting a partition) bypasses the parent's
  policies and returns every row — verified Postgres behaviour. The direct
  grant is what makes the bypass reachable: an un-granted child can only be
  reached *through* the parent (a parent grant does not cascade), where the
  parent's RLS applies — which is also why `pgrls generate` lints clean. It is
  the complement of SEC001/SEC032, which deliberately *skip* a parent-covered
  partition child (to avoid a false "enable RLS" finding on the common
  parent-only pattern) and document the direct-access caveat; SEC041 promotes
  that caveat to a checkable finding — including a child carrying its own
  **dormant** policies, which SEC032 also skips (RLS ancestor) and SEC001
  skips (it has policies), so without SEC041 it would fall through both even
  though the dormant policies enforce nothing. The three are mutually
  exclusive (SEC041 fires iff an ancestor has RLS; SEC001/SEC032 iff none
  does). Configurable via `[lint.rules.SEC041].allowlist` for children never
  reached directly.
  Catalog is now **54 rules**. No auto-fix — the right policy is the
  application's own scoping predicate (usually the parent's).

## [0.27.0] - 2026-06-15

### Added

- **SEC040** (warning) — a permissive `FOR ALL` policy whose `USING` scopes
  rows by a tenant/owner discriminator equality (`col = <auth value>`) but
  whose **explicit** `WITH CHECK` binds **no** identity/discriminator column at
  all (it validates only non-identity columns like `status`). An explicit
  `WITH CHECK` replaces the implicit reuse of `USING`, so the write side
  carries no ownership binding. The reliable consequence is on **INSERT**: a
  `FOR ALL` insert is governed by `WITH CHECK` alone, so a caller can `INSERT`
  a row **stamped with another tenant's id** — a cross-tenant write (a
  column-free blind `UPDATE` migrates an existing row too). Bare `FOR UPDATE`
  is intentionally **not** flagged: Postgres re-checks the new row against the
  SELECT-applicable `USING` on any column-reading update (every PostgREST/ORM
  update), so UPDATE row-migration is blocked in practice. It is the asymmetry
  the other write-side rules miss — SEC006 fires on an *absent* `WITH CHECK`
  (there `USING` is reused), and SEC028 / SEC020 on a *constant-true* one
  (SEC040 cedes constant-`true`/`false` to them). The common, legitimate "read
  your team (`USING team_id = …`), write your own (`WITH CHECK user_id = …`)"
  asymmetry — where the write side binds a *different* identity column — is
  **not** flagged. Detection reuses SEC030's scoping-equality extraction
  (recognizing `=`, `IS NOT DISTINCT FROM`, and `= ANY` membership as
  bindings) over `USING` and `WITH CHECK` separately: it fires when `USING`
  yields a scope and `WITH CHECK` yields none. Configurable via
  `[lint.rules.SEC040]` (`auth_functions`, `identity_columns`, `allowlist`).
  Catalog is now **53 rules**. No auto-fix.

## [0.26.0] - 2026-06-10

### Added

- **`pgrls verify --format sarif`** — SARIF v2.1.0 output for GitHub Code
  Scanning, sharing the schema, version, and `tool.driver` block with `pgrls
  lint`'s SARIF formatter (the document is produced by the same
  `format_sarif`, so the two can never drift). Each LEAK becomes an
  `error`-level result located at `schema.table.policy` with the witness phrase
  as its message; PROVEN tables emit no result; UNVERIFIED tables are omitted
  unless `--strict`, where each becomes a `note`-level result — so the SARIF
  result-set is non-empty exactly when the run would fail the gate. The prover
  is one SARIF rule per `--mode` (`pgrls-anon-isolation` /
  `pgrls-cross-tenant-isolation`), whose `helpUri` points at the README verify
  section (verify rules are a *proof*, not the lint catalog).

## [0.25.0] - 2026-06-09

### Added

- **SEC039** (error) — a permissive write policy (INSERT / UPDATE / DELETE /
  ALL) that grants the unauthenticated `anon` role. In Supabase / PostgREST,
  `anon` serves requests carrying no JWT, so such a policy lets anonymous
  clients modify rows. It is the write-side analog of SEC003 for the named
  `anon` role (which SEC003's `PUBLIC`-pseudo-role check never sees);
  anonymous **read** (`FOR SELECT TO anon`) is a deliberate public-data
  pattern and is intentionally not flagged. Configurable via
  `[lint.rules.SEC039].anon_roles` (default `["anon"]`) for deployments that
  rename or add unauthenticated roles. Brings the catalog to **52 lint rules**
  (17 auto-fixable).

## [0.24.0] - 2026-06-09

### Added

- `pgrls verify --mode cross-tenant` now proves isolation for **integer/bigint
  tenant keys** scoped by a sort-changing cast on the session identity —
  `tenant_id = (SELECT current_setting('app.tenant_id', true)::bigint)` (the
  predicate `pgrls generate` emits for an integer tenant column —
  `smallint`/`int`/`bigint`/…). Such policies
  previously degraded to `UNVERIFIED` because the cast dropped the session
  marker in the Z3 encoder; they are now `PROVEN` (or `LEAK`, with a runnable
  `--emit-repro` reproduction that authenticates tenant A by setting the right
  GUC *through* the cast). `uuid`/`text` tenant keys were already covered
  (sort-preserving casts). Soundness is unchanged — the cast of an arbitrary
  other tenant's identity is modeled as a fresh free symbol of the target
  type, which can only leave the leak check satisfiable (decline), never
  manufacture a false `PROVEN`. The default `--mode anon` path is
  byte-for-byte unchanged.

## [0.23.2] - 2026-06-09

### Fixed

- `pgrls verify --mode cross-tenant` text/JSON output now phrases an
  unconditional cross-tenant leak as "a row of **any other** tenant is
  readable", matching the emitted `--emit-repro` reproduction and the README.
  It previously read "a row of another tenant" — a wording divergence for the
  same verdict across surfaces (the characterizing-row and conditional-leak
  phrasings were already consistent). Output text only; verdicts unchanged.

## [0.23.1] - 2026-06-09

### Fixed

- `pgrls verify --emit-repro`: a `TO public` policy's reproduction no longer
  invents a spurious quoted `"PUBLIC"` application role. Live introspection
  renders the PUBLIC pseudo-role as the literal uppercase `'PUBLIC'`, but the
  repro builder compared roles against lowercase `"public"` — so a
  live-introspected `TO public` policy emitted `CREATE ROLE "PUBLIC"` /
  `SET ROLE "PUBLIC"` (a distinct role) instead of granting `TO PUBLIC` and
  running as the dedicated `pgrls_repro_runner`. The reproduction stayed sound
  (`"PUBLIC"` was still NOSUPERUSER/NOBYPASSRLS) but was inelegant. Now matched
  case-insensitively. Affects both anonymous-read and cross-tenant repros.

## [0.23.0] - 2026-06-09

### Added

- `pgrls verify --mode cross-tenant --emit-repro DIR` — the cross-tenant prover
  now emits runnable reproductions too (previously `anon`-only). For each
  cross-tenant `LEAK` it writes a `.sql` script and a pytest that recreate a
  throwaway copy of the table + policy, **authenticate the session as tenant A**
  (setting the JWT-claim GUC the policy's auth function reads, or a direct
  `current_setting('<guc>')`), insert a row belonging to a **different tenant
  B**, drop into a NOSUPERUSER/NOBYPASSRLS runner, and `SELECT` it back — the
  cross-tenant leak, reproduced and rolled back. The runner is non-privileged so
  a *fixed* policy returns zero rows (the reproduction is sound, not a
  RLS-bypass). Tenant A/B values are synthesized for the discriminator's type
  (the proof's pinned value for a hardcoded `tenant = 'X'` bypass); a custom
  `--auth-function` helper's identity is set via the same JWT-claim GUC. The
  default `--mode anon` reproduction is unchanged.

## [0.22.0] - 2026-06-09

### Added

- `pgrls verify --mode cross-tenant` — a second, complementary threat model for
  the Z3 isolation prover: can a session authenticated as **one tenant** read a
  **different tenant's** row? For the policy's own `<column> = <session
  identity>` scoping equality (the predicate `pgrls generate` emits), a row is
  exposed iff it can be visible while `column` differs from the session's
  tenant — `PROVEN` when that is UNSAT, `LEAK` when SAT (with a concrete
  cross-tenant row for an `OR is_public`-style bypass, or a conditional leak
  with no single characterizing row when the bypass depends on the session —
  an admin-role disjunct — rather than the row). The default `--mode anon` is
  unchanged. The two modes are complementary: the signature
  inverted-auth policy `auth.uid() IS NULL OR tenant_id = auth.uid()` is an
  anon `LEAK` but cross-tenant `PROVEN` (an authenticated tenant only sees its
  own rows). Same soundness contract — `cross-tenant` declines to `UNVERIFIED`
  (never a false `PROVEN`) when a policy has no single scoping equality (a total
  `USING (true)` leak, already caught by `anon` mode), multiple competing
  discriminators, or an untranslatable predicate. JSON output gains a top-level
  `"mode"` and an `"any_other_tenant"` witness scope. `--emit-repro` remains
  `anon`-only.

### Internal

- The 3VL anonymous-read encoder (`_z3_compare._anon_3vl`) gains a
  `_Context.session_mode` flag that binds auth-context calls to free, non-null
  *session symbols* instead of NULL — the sole behavioral fork; with the flag
  off (every existing caller) the encoder is byte-for-byte unchanged.

## [0.21.0] - 2026-06-08

### Added

- `pgrls verify --emit-repro DIR` — for each `LEAK`, write a **runnable
  reproduction** to `DIR`: a `.sql` script and a pytest that recreate a
  throwaway copy of the table (from the introspected column types), install the
  leaking policy verbatim, insert the counterexample row, drop into an
  anonymous session, and `SELECT` the row back — turning verify's proof into
  something you run and watch happen, then roll back. Counterexample columns the
  proof pins are set to their leak-triggering values; other NOT NULL columns get
  type-appropriate placeholders so the script runs (for a *conditional* leak the
  proof can't pin to a single row, the placeholder row is best-effort and the
  emitted header flags it for a hand-edit). The pytest asserts the anonymous
  read returns the row (a red test that goes green once the policy is fixed).
  Filenames are policy-inclusive so multiple leaks on one table don't collide;
  re-running won't clobber a hand-edited reproduction unless `--force`.

## [0.20.0] - 2026-06-08

### Added

- `pgrls verify` — a **Z3 tenant-isolation prover**. For every RLS-enabled
  table it *proves* whether an anonymous session (every auth function —
  `auth.uid()`/`role()`/`jwt()`, `current_setting(...)` — NULL) can read any
  row, with three honest verdicts: `PROVEN` (the `USING` predicate is
  unsatisfiable under anon → no row is ever anonymously visible), `LEAK` (a
  row *is* — with a concrete counterexample: a characterizing row such as
  `is_public=True`, or "every row" for the `auth.uid() IS NULL OR …`
  inversion / `USING (true)`), or `UNVERIFIED` (Z3 unavailable, the predicate
  is outside the decidable fragment, or it timed out — the point where the
  verifier degrades to the linter). Exits non-zero on any leak (a hard CI
  tenant-isolation gate); `--strict` also fails on UNVERIFIED. `text` / `json`
  output; `--auth-function` extends the anon-NULL set with a project's helper.
  Reuses the SEC038 3VL encoder (soundness over recall — never claims a leak
  it cannot exhibit, never claims isolated unless Z3 proves it). v1 covers the
  anonymous-read threat model; authenticated cross-tenant isolation is next.

### Fixed

- `pgrls diff --apply` no longer crashes with `IndeterminateDatatype` when the
  captured baseline references a non-PUBLIC role (e.g. `authenticated`). The
  ephemeral role-provisioning step composed the role name with a server-side
  `%s` parameter inside a `DO` block body — which has no inferable type — so
  any baseline carrying a policy/grant for a named role failed to restore. The
  role name is now composed client-side with `psycopg.sql` (same fix class as
  the ephemeral migration engine).

## [0.19.0] - 2026-06-08

### Added

- `pgrls matrix` — an **effective access matrix**: for every role × table ×
  command, one verdict — `OPEN` (every row reachable), `DENIED` (no privilege,
  or RLS on with no applicable permissive policy), or `COND` (gated by a row
  predicate, shown in `--format json`/`html`). It collapses table `GRANT`s, the
  RLS enabled/forced flags, and the permissive(OR) / restrictive(AND) policy
  set into a single grid — the audit companion to `pgrls report`. Per command it
  evaluates the clause Postgres applies (`WITH CHECK` for INSERT, `USING` for
  SELECT/UPDATE/DELETE — for UPDATE, v1 shows the read-side `USING`, not the
  write-side `WITH CHECK`) and accounts for `BYPASSRLS` roles. `--roles a,b`
  overrides the role columns; `--include-system-roles` adds `pg_*`. Four output
  formats (text / json / markdown / html); runs no lint rules.

## [0.18.0] - 2026-06-08

### Added

- **`pgrls lint --migrations <path>` — lint with no live database.** pgrls
  boots a throwaway Postgres (testcontainers), applies your migration files
  in order, introspects the result, lints, and tears it down — removing the
  "stand up and migrate a database first" onboarding step. Accepts a
  directory or a single `.sql` file; the layout is auto-detected (Supabase,
  Prisma, Flyway, sqitch, or plain ordered `.sql`) and overridable with
  `--migrations-layout` / `--migrations-glob`. `--supabase` is a shortcut for
  `./supabase/migrations` that also provisions the `auth.*` stubs and the
  `anon` / `authenticated` / `service_role` roles; `--create-role` pre-creates
  any other role your policies reference. Requires Docker and the new
  `pgrls[ephemeral]` extra (an alias of `pgrls[diff-apply]`).

## [0.17.0] - 2026-06-03

A soundness- and precision-hardening release: the output of a 20-round
adversarial repo-review loop (each finding independently verified before
acceptance), plus one new diff capability. No new rules; the Z3-backed
SEC038 verifier and the whole rule set are materially more trustworthy.

### Added

- **Column-level grants are now captured and diffed.** Introspection
  reads `pg_attribute.attacl`, so a `GRANT SELECT (col) … TO PUBLIC` on a
  table with RLS off routes to the dangerous `GRANT_PUBLIC_NO_RLS` path
  (previously invisible — table-level `relacl` only). Snapshot format
  bumps to **v15** (additive — the key is emitted only when present, so
  pre-feature snapshots serialize byte-identically apart from the version
  number); v3–v14 snapshots still load.
- **`pgrls diff --format json|sarif` carries the raw 4-way
  classification** (`safe` / `requires_review` / `breaking` /
  `dangerous`) instead of collapsing it to three buckets.

### Fixed

- **Z3 / SEC038 soundness — abstain over fabricate.** The 3VL anon-read
  verifier and the diff counterexample emitter no longer mis-prove or
  mis-emit on several shapes: a mismatched-sort `COALESCE` fold (a bare
  integer column defaulted to BoolSort and Z3 silently coerced it to
  {0,1}, fabricating an "anonymous read leak" on a safe
  `COALESCE(level, 0) < 3` gate); String-sorted arithmetic; never-NULL
  `current_setting`/`current_user`/`session_user` leaves; and a
  synthetic-marker name colliding with a real column. Uncertain shapes
  degrade to no-fire / label-only rather than a false verdict.
- **Rule false positives eliminated** on real-world-shaped policies:
  SEC026 (auth value matched against a hard-coded literal / `SIMILAR TO`
  / ltree pattern), SEC033 (now requires the JSON chain to root in a
  verified JWT source), SEC036 (a single-target `IN`/`= ANY (SELECT
  auth.uid())` is recognized as a caller binding), SEC030, SEC024, and
  SEC006 (a USING-only UPDATE is safe — Postgres reuses USING as the
  implicit WITH CHECK).
- **No dangerous or un-runnable generated SQL.** PERF004 abstains on a
  non-IMMUTABLE index expression (incl. the STABLE 2-arg `length(bytea,
  name)` overload); `generate --auth-function` rejects an ambiguous
  multi-dot name; the SEC015 fixer quotes reserved-keyword search-path
  tokens; and `pgrls fix` / `Schema.to_sql()` close latent
  identifier-quoting and DDL-injection gaps.
- **SEC015 / SEC017 fixers emitted the wrong `ALTER FUNCTION` target
  when a schema name contained a dot.** Introspection now captures the
  schema and function name as separate fields on `SecdefFunction` /
  `LeakproofFunction` instead of splitting the ambiguous
  `nspname || '.' || proname` join; the fixers use them directly and
  abstain when the fields are absent (a pre-v14 snapshot) rather than
  guess a target.
- **`[database].url` env interpolation is now lazy.** `pgrls diff`
  (snapshot-vs-snapshot) and `pgrls explain` no longer fail with exit 2
  just because a `[database].url` env var referenced by an auto-loaded
  `pgrls.toml` is unset — the error is deferred to the commands that
  actually open a connection.
- **Introspection determinism:** the grant queries `SELECT DISTINCT`, so
  a privilege re-granted to the same role by two grantors no longer
  duplicates in the snapshot.

### Changed

- Model decode/emit hardening: empty-privilege grants are rejected at
  snapshot decode; `policy_to_sql` validates the policy command on emit
  and the roles list on decode.

## [0.16.0] - 2026-06-01

### Added

- **SEC038 — semantic anonymous-read leak (Z3-backed).** A new
  `error`-severity rule that proves, with the Z3 SMT solver, that a
  read-capable policy's USING predicate is *unconditionally TRUE for an
  unauthenticated session* — one where every auth-context function
  (`auth.uid()` / `auth.role()` / `auth.jwt()`, `current_user`,
  `session_user`, `current_setting()`) returns NULL. Under SQL
  three-valued (Kleene) logic a row is visible iff USING is exactly TRUE,
  so a predicate that is valid (TRUE for *every* row) under anon reads
  the whole table — the Lovable-CVE catastrophic class.

  SEC038 is the semantic sibling of the always-on, dependency-free
  syntactic SEC004. SEC004 matches the literal shape `auth_func() IS
  NULL`; SEC038 catches the inverted-auth variants that match misses —
  `NOT (auth.uid() IS NOT NULL) OR …`, `(auth.uid() IS NULL)::bool OR …`,
  a coerced-GUC `(SELECT current_setting('app.x'))::uuid IS NULL OR …`.
  Both rules co-fire on the canonical Lovable shape; neither suppresses
  the other (SEC004 still fires on a machine without the Z3 extra).

  Firing criterion is *anonymous validity*: SEC038 fires iff
  `NOT(USING_anon is TRUE)` is unsatisfiable under Kleene 3VL. This is
  provably zero-false-positive on safe policies — a tenant/owner
  predicate `col = (SELECT current_setting(…))` becomes `col = NULL` →
  Kleene unknown (not TRUE) → not valid → does not fire; a narrow public
  carve-out (`col = <constant> OR …`) is TRUE only for some rows → not
  valid → does not fire. Soundness over recall: any sub-expression the
  encoding cannot translate makes the predicate UNKNOWN, so validity
  can't be proven and the rule stays silent. Because validity means
  "TRUE for every row", the finding reports an unconditional leak (all
  rows), not a single example row.

  Runs on a plain `pip install pgrls` — `z3-solver` is now a core
  dependency (see Changed below). In the unusual case where z3 can't be
  imported SEC038 NO-OPs; SEC004 keeps the syntactic guard. Configurable
  via `[lint.rules.SEC038]` (`auth_functions`, `allowlist`).

  Rule count is now 51 (was 50). The new Kleene 3VL encoder
  (`anon_read_counterexample` in `pgrls.diff._z3_compare`) is purely
  additive — the 2-valued `pgrls diff` implication path is unchanged.

### Changed

- **`z3-solver` is now a core dependency** (was the optional `diff-z3`
  extra). The semantic verifier features — SEC038 and `pgrls diff`'s
  concrete leaking-row counterexample — now run on a plain
  `pip install pgrls` instead of silently no-op'ing without the extra.
  z3-solver ships precompiled wheels (one package, no C++ toolchain). The
  `pgrls[diff-z3]` extra is retained as a no-op alias for backward
  compatibility.

## [0.15.0] - 2026-06-01

### Added

- **`pgrls diff` counterexamples** — when the Z3 analysis proves a
  policy-predicate change is DANGEROUS by *semantic loosening* (the new
  predicate admits a strict superset of the old one's row set), the
  verdict now carries a concrete *leaking row* — e.g.
  `example leaking row: {tenant_id=2}` — a row the new policy admits but
  the old one rejected. Surfaced in text output and as a structured
  `counterexample` key in JSON (additive, non-breaking). The row is a
  verifier artifact, emitted unconditionally on the Z3 path (not gated
  behind `--explain`).

  Soundness first: a row is emitted only when its real-column values are
  a *self-sufficient* witness — i.e. every row matching them genuinely
  lies in HEAD ∖ BASE. When the leak hinges on a NULL test or an opaque
  value (a function call, `current_setting(...)` GUC, `COALESCE`, or
  `CASE`) that a column-only row cannot honestly express, no row is
  emitted and the verdict degrades to the label-only DANGEROUS — never a
  row that does not actually leak. Requires the optional
  `pgrls[diff-z3]` extra; without it the DANGEROUS verdict is unchanged
  and no counterexample appears.

- **Precision corpus** (`corpus/`) — an adjudicated set of small,
  self-contained schemas (positives that must fire a specific rule +
  deliberately adversarial negatives that must stay silent: a
  `coalesce()`-wrapped auth check, an `IS NULL` buried in a subquery or
  under `AND`, …) measuring per-rule precision and false-positive behavior
  over the real introspection + lint path. The published run is
  `docs/PRECISION.md`; a new CI job (`pytest corpus/`) re-measures on every
  push and fails on any false positive or false negative. Regenerate with
  `python -m corpus.measure`. Not shipped in the wheel — it's a quality
  gate, not a runtime dependency.

### Changed

- CI `lint` job now also ruff-checks `corpus/` and `bench/`, not just
  `src/` and `tests/`.

## [0.14.0] - 2026-05-30

### Added

- **`pgrls perf --statements`** — attribute observed seq-scan cost to the
  specific queries that drive it, via `pg_stat_statements`. It reads the
  recorded statements, parses each normalized query for the tables it
  references, keeps those touching a table under seq-scan pressure, and
  lists the costliest by total execution time — turning "this table
  seq-scans" into "*this query* seq-scans it" (text / JSON / Markdown / HTML).
  Degrades cleanly when the extension isn't installed: a one-line note,
  base report unchanged. Completes the runtime-PERF milestone — the
  table-level caveat (`pg_stat_user_tables` counts every scan, not only
  RLS-driven ones) is what statement-level attribution resolves.

## [0.13.0] - 2026-05-30

### Added

- **PERF005 — RLS-protected table observed to sequentially scan in
  production** (info, opt-in). The lint-gate face of `pgrls perf`: capture a
  runtime-stats snapshot with `pgrls perf --snapshot .pgrls-perf.json`, then
  `pgrls lint --perf .pgrls-perf.json` fires PERF005 for every RLS-enabled
  table the snapshot shows under sequential-scan pressure — so observed
  seq-scans gate CI next to the static rules. Inert on a normal lint run (no
  artifact, like HYG004 and its coverage artifact). Thresholds are tunable
  per-rule (`[lint.rules.PERF005]` `min_rows` / `min_seq_scans` /
  `min_seq_pct`, sharing `pgrls perf`'s gate so the two never disagree), and
  a table can be allowlisted. Brings the catalog to **50 rules**. Table-level
  counters include every scan, not only RLS-driven ones, so PERF005
  prioritises investigation rather than proving RLS is the cause.
- **`pgrls perf --snapshot PATH`** writes the raw `pg_stat_user_tables`
  artifact PERF005 consumes (bare `--snapshot` writes `.pgrls-perf.json`).
- **`pgrls lint --perf PATH`** loads that artifact and enables PERF005.

## [0.12.0] - 2026-05-30

### Added

- **`pgrls perf`** — runtime sequential-scan analysis. PERF003 predicts a
  missing index *statically*; `pgrls perf` reads what the database actually
  did (`pg_stat_user_tables`) and ranks RLS-enabled tables by rows read
  sequentially, cross-referencing each against PERF003: a table PERF003
  flagged that is *also* observed seq-scanning is a **confirmed**
  missing-index candidate; a table PERF003 thought was indexed that still
  seq-scans means the index **isn't being used** (poor selectivity, stale
  statistics) — a finding static analysis can't produce. Text / JSON /
  Markdown / HTML output; `--min-rows` / `--min-seq-scans` / `--min-seq-pct`
  tune the thresholds (defaults conservative — small tables seq-scan by the
  planner's choice); `--fail-on-findings` gates CI. Table-level counters
  include every scan, not only RLS-driven ones, so this prioritises
  investigation rather than proving RLS is the cause (statement-level
  attribution via `pg_stat_statements` comes in a later release).

## [0.11.0] - 2026-05-30

### Added

- **`pgrls init --preset`** — scaffold a `pgrls.toml` tailored to a stack:
  `generic` (per-tenant via an `app.*` GUC), `supabase` / `neon` (per-user
  ownership via `auth.uid()` / `auth.user_id()`), or `postgrest` (per-tenant
  via a `request.jwt.claim.*` GUC). Each preset documents its tenancy
  convention and the exact `pgrls generate` command that scaffolds matching,
  lint-clean policies, turning a two-step (configure, then learn the generate
  flags) onboarding into one. Presets change documentation only — the
  generated config parses identically and leaves every rule at its default
  regardless of preset, so `pgrls lint` runs unchanged. Defaults to `generic`
  (the prior `pgrls init` output).

## [0.10.0] - 2026-05-30

### Added

- **SEC035 — UNIQUE constraint not scoped to the tenant discriminator.**
  A multi-tenant table with a global `UNIQUE (email)` (instead of
  `UNIQUE (tenant_id, email)`) leaks cross-tenant existence: an INSERT
  colliding with another tenant's invisible row raises a duplicate-key
  error, an enumeration oracle across the RLS boundary — and blocks
  legitimate writes. SEC035 (warning) flags a unique index that excludes
  the discriminator the table's policies scope by, excluding the PRIMARY
  KEY and all-uuid uniques (globally unique by design) to stay
  high-precision. Allowlist a table where a cluster-wide unique is
  intentional. Brings the catalog to **49 rules**.

### Changed

- Snapshot format → **v13**: `Index.is_primary` is now captured (from
  `pg_index.indisprimary`), letting SEC035 tell a surrogate primary key
  apart from a tenant-scopable UNIQUE. Pre-v13 snapshots load unchanged
  (the field defaults to false).

## [0.9.0] - 2026-05-30

### Added

- **`pgrls generate --model owner` — per-user row ownership.** Alongside the
  default tenant-isolation model, `generate` now scaffolds per-user RLS for
  tables with an owner column (default `user_id`). `--convention supabase`
  emits the canonical Supabase shape, `user_id = (SELECT auth.uid())`
  (`--auth-function` overrides the function); `--convention app-guc` /
  `postgrest` use `current_setting('app.user_id', …)` /
  `current_setting('request.jwt.claim.sub', …)`. Policies are named
  `<table>_owner_isolation` / `_owner_floor`. The output lints clean for
  every convention (pinned by live-DB e2e tests, including the `auth.uid()`
  form). `--convention supabase` requires `--model owner`. The tenant model
  is unchanged.

## [0.8.1] - 2026-05-30

### Fixed

- **`pgrls generate` no longer duplicates indexes on partitioned tables.**
  For a declarative-partitioned tenant table, `generate` set up the parent
  *and* every child, so each child got two identical discriminator indexes
  (the parent's partitioned index cascades to children automatically, plus
  `generate`'s own per-child `CREATE INDEX`). `generate` now sets up the
  partitioned parent only and skips children (reported, pointing at the
  parent) — mirroring how the SEC001 rule/fixer already treat partitions.
  RLS on the parent covers parent-routed queries and its index cascades, so
  the result still lints clean; each child carries exactly one index.

## [0.8.0] - 2026-05-29

### Added

- **`pgrls generate` — scaffold gold-standard RLS.** pgrls lints, fixes,
  tests, and diffs RLS; now it also *produces* it. For every table that
  carries a tenant-discriminator column (default `tenant_id`,
  `--tenant-column` / `--table schema.tbl:col`) and has no policies,
  `generate` emits the complete correct setup — `ENABLE` + `FORCE` row
  security, a permissive tenant-isolation policy, a `RESTRICTIVE` floor
  (`--no-restrictive` to skip), and the supporting index — built so the
  result **lints with zero findings** (an end-to-end test pins the
  guarantee). The predicate compares the column to a session value
  (`--convention app-guc` → `current_setting('app.<col>', true)`, or
  `postgrest` → `request.jwt.claim.<col>`), wrapped in `(SELECT …)` for
  per-statement caching and cast to the column's type. Dry-run by default;
  `--output FILE` writes a migration, `--apply` runs it in one
  all-or-nothing transaction. Tables that already have policies are
  skipped and reported — `generate` never clobbers hand-written intent, so
  re-runs are idempotent. Targets the common single-column tenant model;
  per-CRUD / membership-join / row-owner shapes remain hand-written.

## [0.7.1] - 2026-05-29

### Fixed

Three coverage over-credit ("false covered") bugs in 0.7.0 — each could
report an RLS policy as tested when no test genuinely exercised it,
contradicting the documented "never over-credit" guarantee. All affect
`pgrls coverage` and HYG004.

- **Same-named tables across schemas.** In a one-schema-per-tenant
  database (`tenant_a.events` / `tenant_b.events`), a test that exercised
  one tenant's table via an unqualified query (`FROM events`, resolved
  through `search_path`) was marking *every* same-named table's policies
  covered. An unqualified (schema-less) coverage tuple now credits a
  table by bare name only when that name is unique across the scanned
  schemas; for an ambiguous name, qualify the test query
  (`FROM tenant_a.events`). Single-schema setups are unchanged.
- **Data-modifying CTEs and `SELECT INTO`.** A writable CTE
  (`WITH d AS (DELETE FROM secret RETURNING *) SELECT … FROM d`) credited
  `secret` as a `SELECT` read — falsely covering its SELECT policy —
  because the command was taken from the outer statement. The CTE's write
  target now gets its real command (`DELETE`/`UPDATE`/`INSERT`), and a
  `SELECT … INTO new_table` no longer credits the created table as a read.
- **CTE alias names leaked as phantom relations.** A CTE name referenced
  in the query (including from a sibling/nested CTE) was recorded as a
  `SELECT` against a table of that name; aliases are now dropped across
  the whole `WITH` scope. A real, schema-qualified table that happens to
  share an alias name is still credited.

## [0.7.0] - 2026-05-29

### Added

- **RLS test coverage.** A new `pgrls coverage` command reports which
  RLS policies your `pgrls.testing` suite actually exercised, and which
  were never touched — the cross-tenant `DELETE` nobody tested. The
  pytest plugin now records the `(schema, relation, role, command)`
  tuples each test runs and writes them to `.pgrls-coverage.json` on
  session finish (best-effort; disable with `pgrls_coverage = false` or
  `PGRLS_COVERAGE=off`). `pgrls coverage` renders text / json / markdown
  / html and gates CI with `--fail-under N`. A policy is *covered* when
  a test queried its table, under a role it targets (or `PUBLIC`), with
  a matching command.
- **HYG004 — policy has no behavioral test.** A new (info, opt-in) lint
  rule that flags uncovered policies. Inert on a normal run; enable it
  with `pgrls lint --coverage .pgrls-coverage.json`. Shares the coverage
  matching with `pgrls coverage`. Brings the catalog to **48 rules**.

## [0.6.24] - 2026-05-28

### Changed

- **Internal refactor — shared HTML datetime helpers.** The
  `generated_at` handling (default-to-now, naive-datetime
  `ValueError` guard, ISO-8601-UTC-with-`Z` formatting) was copy-
  pasted verbatim across the four timestamped HTML formatters
  (`lint`, `report`, `history`, `diff`). Extracted to
  `pgrls._html_common` (`resolve_generated_at` + `to_iso_z`). Output
  is byte-for-byte identical — the existing HTML snapshot tests pin
  it — so there is no CLI or formatting change. The per-formatter
  CSS is deliberately *not* centralised (the five renderers have
  intentionally divergent stylesheets). Net −55 lines of duplication;
  the naive-datetime contract now has a single definition.

## [0.6.23] - 2026-05-27

### Added

- **Cross-format consistency tests for `pgrls explain`** — completes
  the v0.6.17 / v0.6.20 pattern (lint, report, history, diff already
  pinned). Seven new tests assert that all four explain renderers
  (text / markdown / json / html) agree on:

  - Catalog rule count (JSON `count`, text rule-line count, markdown
    table-body row count, HTML tbody `<tr>` count all match
    `len(all_rules())`).
  - Every rule ID surfaces in every format.
  - Per-rule severity is consistent (text `[<sev>]`, markdown column,
    HTML `sev-<sev>` pill class, JSON field).
  - JSON `fixable` flag and HTML `✦ fix` badge agree per rule.
  - Single-rule mode: `id` / `severity` / `title` consistent across
    text, markdown, JSON, and HTML (HTML title gets `html.escape`d
    for apostrophe-bearing titles like SEC014's "caller's RLS").
  - Rule reference body (docstring minus title) surfaces in every
    format — first non-blank line is the stable anchor; HTML escapes
    it the same way the renderer does.
  - HTML catalog's `pgrls {__version__}` meta line matches JSON's
    `pgrls_version` field.

### Fixed

- **`pgrls --version` reported the wrong release**. `__version__`
  in `src/pgrls/__init__.py` had been hard-coded to `"0.6.0"` since
  the v0.6.0 milestone cut; the CLI's `--version` flag and the JSON
  catalog's `pgrls_version` field both read from it, so users saw
  the stale `0.6.0` after upgrading. Sourced from
  `importlib.metadata.version("pgrls")` so the in-process value
  tracks the pyproject `[project].version` automatically. New
  `test_package_version_matches_pyproject` parses pyproject via
  `tomllib` and pins the two sources to each other so the drift
  can't recur silently — the prior `test_root_version_flag` compared
  `__version__` to itself and passed for the wrong reason.

  Source-tree imports without `pip install -e .` fall back to
  `0.0.0.dev0` (PEP 440 dev release, parses cleanly via
  `packaging.version.Version`) instead of crashing.

## [0.6.22] - 2026-05-27

### Added

- **`pgrls lint --format html`** — standalone HTML page for lint
  findings, distinct from `pr-comment` (which is Markdown + embedded
  HTML `<details>` blocks for GitHub PR comments) and `markdown`
  (pipe table for runbooks). Same self-contained shape every other
  pgrls HTML formatter (`report` / `history` / `diff` / `explain`)
  uses: embedded CSS, no external assets, light/dark via
  `prefers-color-scheme`, ISO-Z generation timestamp.

  Each violation renders as one row with severity emoji + coloured
  pill, rule ID linked to `docs/RULES.md` anchor, location in a
  `<code>` block, and the message body. Empty case gets a green
  "No findings" banner instead of an empty table.

  Every cell `html.escape`-d — quoted-identifier hazards (`weird<name>&"`)
  and SQL operators in messages (`<>`, `<=`) can't break layout
  or inject markup. Unknown severities (from extra rules emitting
  unexpected values) degrade gracefully to a neutral bullet rather
  than crashing.

  API: `format_html(violations, *, generated_at=None)` — naive
  datetimes raise `ValueError`, same contract every other pgrls
  HTML formatter honours.

  **Toolchain milestone:** with this release, every pgrls command
  that produces structured output has a full standalone HTML
  format. Same visual fingerprint across all five (`lint`,
  `report`, `history`, `diff`, `explain`).

## [0.6.21] - 2026-05-27

### Added

- **`pgrls explain --format html`** — standalone HTML pages for
  both single-rule and full-catalog modes. Same self-contained
  shape `pgrls report --format html`, `pgrls history --format
  html`, and `pgrls diff --format html` established: embedded
  CSS, no external assets, light/dark theme. Single-rule mode
  renders the rule's reference body in a `<pre>` block (preserves
  the rule-author's intended whitespace, code fences, bullet
  alignment) with a severity-coloured pill and a green
  `✦ auto-fixable` badge when applicable. Catalog mode renders
  a per-rule table with the ID linking to the
  `docs/RULES.md#rule-<id>` anchor on GitHub so a reviewer can
  click through to canonical references. Useful as a shareable
  rule reference for someone who doesn't run pgrls — paste into
  internal wiki, print to PDF for a runbook attachment, email
  to an auditor.

  Every rendered string is `html.escape`-d (defence against any
  future rule with a `<` / `>` / `&` in its title or body — even
  though no shipped rule has them today).

## [0.6.20] - 2026-05-27

### Tests

- **Cross-format consistency tests for `pgrls diff`** — pin that
  all five renderers (text / json / sarif / markdown / html) agree
  on the same input. Caught a real label inconsistency in the
  process: `_BUCKET_LABEL["requires_review"]` is `"requires-review"`
  (with hyphen), and the consistency test made the wording explicit
  in the contract rather than the implementation detail it had
  been. Five new tests covering: total change count agreement
  across all five formats; per-classification count agreement;
  every Change.location surfaces in every format; predicate
  before/after SQL renders consistently in text+html for
  USING_*/WITH_CHECK_* kinds (markdown deliberately summary-only);
  empty-changes case consistent across all five.

  Test-only release — no source / behavior change.

## [0.6.19] - 2026-05-27

### Added

- **`pgrls diff --format html`** — standalone HTML audit page,
  the final format in the diff command's set. Same self-contained
  shape `pgrls report --format html` (v0.6.7) and `pgrls history
  --format html` (v0.6.16) established: embedded CSS, no external
  `<link>` / `<script>` (opens offline, renders identically in
  browsers and `wkhtmltopdf`-style PDF converters), light/dark
  via `prefers-color-scheme`. Each Change renders as one row
  with a coloured classification pill — green for SAFE, amber for
  REQUIRES REVIEW, orange for BREAKING, red for DANGEROUS — so
  the at-a-glance read of "is this migration safe?" doesn't
  require parsing the summary band. ISO-8601 UTC generation
  timestamp; `format_diff_html(changes, *, generated_at=None)`
  exposes the timestamp-pinning API (naive datetime raises
  `ValueError`). All cells `html.escape`-d — quoted-identifier
  hazards like `weird<name>&"` can't break layout or inject markup.

## [0.6.18] - 2026-05-27

### Added

- **`pgrls diff --format markdown`** — completes the diff
  command's format set (text/json/sarif shipped earlier; markdown
  now). Renders a GFM table with one row per Change:
  Classification (emoji + uppercase label — `✅ SAFE`, `⚠️ REQUIRES
  REVIEW`, `🚦 BREAKING`, `❌ DANGEROUS`) | Kind (humanized
  ChangeKind name, e.g. `Using Tightened`, `RLS Flipped`) | Object
  (qualified identifier through `gfm_inline_code`) | Summary
  (per-Change message with `|` / `\n` escaping for the table).
  Paste-ready for a PR review comment or a Markdown runbook.
  Trailing summary line `**Summary:** N changes — A dangerous, B
  breaking, C safe.` mirrors the text formatter's phrasing so
  script consumers grepping either format see identical text.
  Empty-changes case returns `pgrls diff: no changes.\n` verbatim.

## [0.6.17] - 2026-05-27

### Tests

- **Cross-format consistency tests** for `pgrls history` and
  `pgrls report` — pin that all four renderers (text / json /
  markdown / html) agree on the underlying numbers for the same
  input. Each renderer is hand-written; without these tests a
  typo or off-by-one in one format wouldn't be caught by the
  other format's tests. Six new tests across history (per-snapshot
  totals, NEW/FIXED deltas, series summary, per-severity counts)
  and report (status pill counts, every-table-row presence).

- **Property-based tests for formatter helpers.** New
  `test_property_formatters.py` covers `gfm_inline_code`
  (shared by markdown + pr-comment formatters) and `_html_escape`
  (used by pr-comment + history/report HTML formats). Hypothesis
  exercises the combinatorial space the example tests don't —
  random content strings biased toward the adversarial cases
  (backtick runs of varying length, embedded `<`/`>`/`&`). Pins
  three invariants for each helper: wrapper run strictly exceeds
  inner run, opener/closer match, content survives the wrap;
  no raw `<`/`>` in output, every `&` is the start of one of three
  entities, the not-idempotent-by-design contract holds.

  Test-only release — no source / behavior change.

## [0.6.16] - 2026-05-27

### Added

- **`pgrls history --format html` — standalone HTML trend page.**
  Mirrors `pgrls report --format html` for the same reading
  context: archive as the weekly engineering-review artefact,
  print to PDF for a quarterly compliance file, email to a
  stakeholder. Embedded CSS, no external assets — opens offline,
  renders identically in browsers and `wkhtmltopdf`-style PDF
  converters. Per-snapshot row table with severity totals + the
  NEW/FIXED delta vs. the prior snapshot; the NEW column highlights
  red and the FIXED column highlights green when non-zero, so the
  at-a-glance read of "are we gaining ground" doesn't require
  parsing the trailing summary. Summary band shows
  first→last totals with a coloured net-change badge
  (green for `net -N`, red for `net +N`, grey for flat).
  Light/dark color scheme via `prefers-color-scheme`. Filenames
  are HTML-escaped — a directory contaminated with a filename
  containing `<` / `&` can't break the layout or inject markup.

- **API: `pgrls.history.render_html(rows, *, generated_at=None)`.**
  Same shape `pgrls.report.render_html` exposes — optional
  timezone-aware `datetime` for deterministic snapshot tests; a
  naive `datetime` raises `ValueError` rather than being silently
  coerced through the host's local timezone.

## [0.6.15] - 2026-05-27

### Added

- **`pgrls fix` now remediates SEC030** (policy scopes by a
  nullable discriminator column — the silent-row-hiding-then-
  cross-tenant-leak footgun). Emits `ALTER TABLE <schema>.<table>
  ALTER COLUMN <column> SET NOT NULL;` per flagged column.
  Mechanically-fixable rule count: 16 → **17** of 47.

  **`--apply` will fail if existing NULLs are present** — Postgres
  scans the column at ALTER time and rejects with
  `ERROR: column contains null values` on any NULL row. The Fix
  description names this prominently and supplies the backfill
  `UPDATE` recipe: `UPDATE <schema>.<table> SET <column> = <value>
  WHERE <column> IS NULL;` before running the fix. Pgrls can't
  infer the right tenant id / sentinel to backfill with — that's
  application logic — so the operator either backfills first,
  adds a DEFAULT in a migration, or allowlists the table if the
  NULLs are intentional. `--output FILE` writes the SQL to a
  migration so the backfill + ALTER can be scripted together.

  One Fix per flagged column (a table with two nullable scoping
  columns gets two Fix entries — each ALTER COLUMN is independent
  and may succeed independently). Mixed-case column names are
  properly quoted (`"TenantId"`). Allowlist semantics mirror the
  rule: `[lint.rules.SEC030].allowlist` keyed on table name
  (qualified or bare); an entry silences the whole table.

## [0.6.14] - 2026-05-27

### Fixed

- **SEC014 / SEC015 / VIEW004 — overload-handling.** Three rules
  had pre-existing latent bugs surfaced by snapshot v12's
  per-overload `signature` capture. The underlying SECDEF
  introspection query (`_SECDEF_FUNCS_SQL`) never had a `SELECT
  DISTINCT` — overloads were always separate rows. v12 just made
  the contract explicit by adding the `signature` field.

  * **SEC014** docstring promised "Two overloads of the same
    qualified name are flagged once and allowlisted once" but the
    code didn't enforce it — two overloads produced two
    byte-identical violations. Added a `seen: set[str]` dedup by
    qualified_name (same pattern SEC017 picked up in v0.6.11) so
    the rule matches its documented contract.

  * **SEC015** likewise emitted one violation per overload. Same
    qname-keyed dedup added. In practice all overloads of a
    function share a `proconfig` (search_path is per-function), so
    the user-facing behavior is essentially unchanged; the rare
    mixed-safe-and-unsafe-overload case reports the first
    unsafe overload (the allowlist silences all, the paired
    SEC015 fixer retains per-overload granularity).

  * **VIEW004** built `secdef_bodies = {f.qualified_name: f for
    f in ...}` — a dict comprehension that is last-wins on
    duplicate qnames. Pre-v12 the "winner" was implementation-
    defined; v12's `ORDER BY qname, signature` made it the
    lex-last signature deterministically — but still only ONE
    overload's body. If two overloads of the same function have
    different bodies (one reading an RLS-protected table, one
    not), VIEW004 only analyzed the lex-last and could miss the
    leak. Now walks every overload's body per qname; per-overload
    PL/pgSQL / parse-error stderr warnings name the specific
    overload (e.g. `public.lookup(text)`) so the operator knows
    which one wasn't analyzed.

  9 new regression tests across the three rules pin the contracts.
  No behavior change for schemas with no overloaded SECDEF /
  LEAKPROOF functions (the common case).

## [0.6.13] - 2026-05-27

### Added

- **`pgrls fix` now remediates SEC015** (SECURITY DEFINER function
  whose `search_path` exposes it to `pg_temp` shadowing — the
  CVE-2018-1058 escalation family). The fixer emits `ALTER
  FUNCTION <schema>.<name>(<signature>) SET search_path = <safe>;`
  per overload, where `<safe>` is either the minimal `pg_catalog,
  pg_temp` default (when the function pinned no path at all) or
  the existing tokens with any earlier `pg_temp` stripped and
  `pg_temp` re-pinned as the final entry. Postgres resolves
  `search_path` in first-occurrence order, so pinning `pg_temp`
  last forces the temp schema to be searched last — the
  structurally safe shape SEC015 requires. Abstains on pre-v12
  snapshots (empty signature) and on the documented quoted-comma
  edge case the naive tokenizer can't handle. Mechanically-
  fixable rule count: 15 → **16** of 47.

## [0.6.12] - 2026-05-26

### Added

- **`pgrls fix` now remediates SEC017** (function marked
  `LEAKPROOF` — bypasses the RLS / security_barrier qual). The
  fixer emits `ALTER FUNCTION <schema>.<name>(<signature>) NOT
  LEAKPROOF;` per overload using the per-overload `signature`
  field captured in snapshot v12. Distinct from how SEC017 itself
  reports (per qualified name, deduped): each overload needs its
  own ALTER FUNCTION since a bare `ALTER FUNCTION name()` would
  target only the zero-arg overload. Abstains on pre-v12 snapshots
  where `signature=""` (a wrong ALTER FUNCTION targeting the wrong
  overload would be worse than no fix; re-snapshot to populate).
  `[lint.rules.SEC017].allowlist` (qualified function name)
  silences every overload — matches the rule's allowlist
  semantics. Mechanically-fixable rule count: 14 → **15** of 47.

## [0.6.11] - 2026-05-26

### Changed

- **Snapshot v12 — per-overload function `signature` captured.**
  `SecdefFunction` and `LeakproofFunction` now carry a `signature`
  field (`pg_get_function_identity_arguments(p.oid)` output —
  empty for zero-arg functions, non-empty like `integer, text`
  for overloads). Two overloads of the same qualified name appear
  as separate entries (the `_LEAKPROOF_FUNCS_SQL` query dropped its
  `SELECT DISTINCT`); SEC017's reporting still dedupes by
  qualified name, so the message surface is unchanged.

  This is the introspection-layer refactor the upcoming SEC014 /
  SEC015 / SEC017 fixers need: `ALTER FUNCTION name(<signature>)
  NOT LEAKPROOF` (and the SECDEF analogues) require the argument-
  type signature, which earlier snapshot versions did not capture.

  v3-v11 baselines still load. `SecdefFunction`/`LeakproofFunction`
  parsed out of a pre-v12 snapshot default `signature` to `""`;
  fixers that need the signature see empty and abstain (a wrong
  ALTER FUNCTION would be worse than no fix). Re-snapshot against
  a live database to populate the signatures.

## [0.6.10] - 2026-05-26

### Added

- **`pgrls history <dir>` — snapshot time-series.** New subcommand
  that consumes a directory of JSON files written by `pgrls lint
  --format json` and emits a chronological trend report: per-snapshot
  totals by severity, plus the per-step **NEW** / **FIXED** delta
  (findings keyed by `(rule_id, location)` — a schema-wide finding
  with `location=None` is stable identity, classified PERSISTENT
  rather than NEW+FIXED on every comparison). Pair with a daily
  cron writing `snapshots/$(date -u +%FT%H%M%SZ).json` and answer
  "are we gaining ground over time?" weekly. `--format text` (fixed-
  width terminal table, default), `--format json` (`{snapshots,
  summary}` machine-readable shape), `--format markdown` (paste-ready
  GitHub table for a weekly update). `--output FILE` writes to a
  file. Files that don't parse as the pgrls JSON shape are skipped
  with a stderr warning; the report still renders for the readable
  ones.

## [0.6.9] - 2026-05-26

### Added

- **`pgrls fix` now remediates PERF004** (policy filters on a
  function-wrapped column, defeating the plain leading-column index).
  The fixer walks the policy AST, finds each outermost `FuncCall`
  wrapping a flagged column, renders it back to SQL via
  `pglast.stream.RawStream`, and emits `CREATE INDEX ON
  <schema>.<table> (<expression>);` — an expression index that
  matches the predicate exactly. The existing plain index on the
  bare column stays in place; this adds a parallel index for the
  function-wrapped form. Two policies sharing the same
  `lower(email)` predicate collapse to one CREATE INDEX (dedup by
  rendered expression). For a large, busy table, the fix description
  points at `CREATE INDEX CONCURRENTLY` and `pgrls fix --output`.
  Mechanically-fixable rule count: 13 → **14** of 47.

## [0.6.8] - 2026-05-26

### Added

- **`pgrls fix` now remediates SEC032** (table has policies but RLS
  not enabled — the dormant-policies footgun). The fixer emits the
  same `ALTER TABLE … ENABLE ROW LEVEL SECURITY` statement as
  SEC001's fix; the difference is the prior state. SEC032 flags a
  table whose policies are sitting in `pg_policy` doing nothing,
  and enabling RLS activates them immediately. Partition-child
  cases SEC032 itself cedes are skipped by the fixer on the same
  grounds: a child whose ancestor has RLS is already covered for
  parent-routed queries, and flipping RLS on the child alone could
  surprise direct-on-child reads. `[lint.rules.SEC032].allowlist`
  (qualified or bare table name) silences both the rule and the
  fixer. Mechanically-fixable rule count: 12 → **13** of 47.

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

- **API: `pgrls.report.render_html(report, *, generated_at=None)`.**
  Programmatic consumers can pin the generation timestamp for
  deterministic snapshot tests or to reflect the time of an
  earlier introspection (when rendering offline from a cached
  `Report`). Must be timezone-aware; a naive `datetime` raises
  `ValueError` rather than being silently coerced through the
  host's local zone.

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
