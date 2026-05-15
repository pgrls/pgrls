# Changelog

All notable changes to `pgrls-test-go` (the Go port of `pgrls.testing`).

The format follows [Keep a Changelog](https://keepachangelog.com/) and the
module adheres to [Semantic Versioning](https://semver.org/). Protocol
versioning is independent — `ProtocolVersion` (currently `1`) only bumps
on wire-level breaking changes shared with the Python and TypeScript clients.

## [0.7.6] - 2026-05-14

**Step 7 of 7 — CI hardening + release plumbing.** Wraps the
v0.7.x staged rollout: every PR / push to `go/**` or
`tests/protocol/**` now runs the test matrix + a separate
golangci-lint job + a govulncheck job; tag pushes (`go/v0.7.x`)
trigger a release workflow that verifies the tag's commit
passes every gate, warms the public Go module proxy via
`go list -m`, and cuts a GitHub Release with the changelog
stanza extracted from this file. The v0.7.x sequence is
complete with this release; future pgrls-test-go releases ship
as `go/v0.8.x` tags.

### Added

- **`go/.golangci.yml`** — v1-schema config selecting a small
  high-signal linter set (`errcheck`, `govet`, `ineffassign`,
  `staticcheck`, `unused`). `disable-all: true` + explicit
  enable avoids opt-out drift when golangci-lint adds new
  linters. `errcheck.exclude-functions` documents the
  cleanup-call sites (`sql.DB.Close`, `pgxpool.Pool.Close`,
  `testcontainers.Container.Terminate`) where ignoring an error
  is the deliberate pattern. Test files are exempt from the
  `errcheck` "Error return value of" message via
  `issues.exclude-rules`.

- **`golangci-lint` CI job** (`.github/workflows/go.yml`)
  pinned to `golangci/golangci-lint-action@v6` running the
  v1.62.2 linter (last v1.x release; matches the v1 config
  schema). Runs once per push / PR (not per-Go-version since
  the config is version-agnostic), against the `go/`
  working directory.

- **`govulncheck` CI job** at
  `.github/workflows/go.yml` runs `govulncheck@v1.1.4` against
  `./...`. Pinned to Go 1.23 for the run (Go 1.22 stdlib
  carries unpatched CVEs that govulncheck reports as
  "your code is affected by" — they aren't bugs in this
  module's code but in the Go release line itself, and the
  test matrix already exercises both Go versions for
  compatibility).

- **`.github/workflows/go-release.yml`** — tag-triggered
  release workflow firing on `go/v*` tag push (and via
  `workflow_dispatch` for manual cuts):
  - **`verify`** job: re-checks out the tag's commit and runs
    the same gates as the PR workflow (`go mod tidy`, gofmt,
    `go vet`, `go test -race`) plus a cross-check that the
    tag's version has a matching `## [X.Y.Z]` entry in
    `go/CHANGELOG.md`. A mismatch (missing entry, typo'd
    version) is a release-process bug worth blocking on.
  - **`warm-proxy`** job: issues `go list -m
    github.com/pgrls/pgrls/go@<version>` so the default
    `proxy.golang.org` fetches and caches the tag, avoiding a
    cold-cache stall the first time a user runs
    `go get github.com/pgrls/pgrls/go@<tag>`.
  - **`release`** job: extracts the version's stanza from
    `go/CHANGELOG.md` via awk (between `## [X.Y.Z]` and the
    next `## ` heading), writes the result as the GitHub
    Release body, and calls `gh release create`.

### Changed

- **`protocol.go` status comment** advanced to step 7 of 7
  (the final step of the v0.7.x sequence).

### Future

- The next pgrls-test-go release ships as `go/v0.8.x`. v0.8.0
  is the natural place to bump the module's `go 1.22` floor
  to 1.23 (so `govulncheck` no longer needs the 1.23-runner
  workaround) and pick up the still-go-1.22-compatible
  testcontainers-go v0.35.0 (or jump to v0.41.x if the floor
  bump targets 1.25). No protocol-version (`ProtocolVersion`)
  bump is planned for v0.8.x — the Layer 1 wire contract
  stays at v1.

## [0.7.5] - 2026-05-14

**Step 6 of 7 — cross-language conformance suite.** Wires both
adapter packages (pgx and lib/pq) into a single conformance
suite that runs against a real Postgres container, exercising
the four Layer 1 protocol criteria from
`docs/pgrls-test-protocol.md` plus end-to-end tests of the
public API. Reuses the same SQL fixture
(`tests/protocol/{schema,seed}.sql`) the Python conformance
suite (`tests/protocol/test_protocol_conformance.py`) consumes,
so a single edit to the fixture propagates Python ↔ Go. The
TypeScript port hand-rolls its own `FIXTURE_SQL` covering the
same four Layer 1 criteria — a deliberate fork-in-the-road
documented in `AGENTS.md`, which lists three valid patterns
(manifest reuse, full hand-roll, and the Go hybrid). The Go suite is a hybrid: it
consumes Approach 1's `schema.sql` + `seed.sql` files (so a
single edit propagates to the Python run unchanged) but skips
the rest of Approach 1's `manifest.json` indirection in favor
of an in-Go scenario harness covering the same four Layer 1
criteria.

### Added

- **`pgrlstest/conformance_test.go`** — package-scoped
  `TestMain` boots one Postgres testcontainer
  (`postgres:17-alpine`) shared across all conformance tests,
  applies the shared fixture, then runs
  `TestConformance_PgxAdapter` and `TestConformance_PqAdapter`.
  Each adapter test runs 13 subtests:
  - Four Layer 1 protocol criteria: `SET LOCAL ROLE` resets on
    rollback, `set_config(..., true)` resets on rollback,
    `InsufficientPrivilege` (SQLSTATE 42501) for WITH CHECK
    violations, silent-drop for `UPDATE … RETURNING` when
    `USING` filters the targeted rows out.
  - Nine end-to-end public-API tests: tenant-isolation under
    AsRole, nested AsRole restoring outer claims, AsRole with
    `Claims: nil` skipping set_config, Seed + AssertRows, the
    AssertSilentlyDropped verb-gate on a real driver,
    AssertRejected returning *AssertionError when the query
    succeeds, AssertVisible / AssertInvisible against the
    tenant-isolation fixture, plus two additional AsRole
    nested-restore cases (case 4 — inner-no-claims preserves
    outer; case 2 — inner-on-empty-outer clears on exit via
    explicit `set_config(NULL, true)`).
  - 26 conformance subtests pass against real Postgres 17
    (13 per adapter × 2 adapters).

- **`PGRLS_CONFORMANCE_DSN` env-var fallback** — local
  developers can point the conformance suite at a pre-running
  Postgres instead of using testcontainers (useful when running
  `go test` inside a Docker harness where testcontainers'
  default host-bridge address doesn't route between sibling
  containers). The env-var path runs the same fixture install
  with an idempotent teardown so reruns against a persistent
  database don't fail with "role already exists".

- **Docker-availability fallback** — when testcontainers can't
  start a container (Docker not reachable, image pull failed,
  port allocation rejected — or fixture install fails),
  `TestMain` leaves `containerDSN` empty and `TestConformance_*`
  parent tests both `t.Skip` on entry with a generic message
  pointing the reader at the TestMain stderr output (where the
  actual failure reason is logged). The rest of the package's
  unit-test suite stays runnable in Docker-less environments.
  `-short` also skips the conformance suite.

### Changed

- **`go.mod` gains test-time deps**: `testcontainers-go v0.34.0`
  and `testcontainers-go/modules/postgres v0.34.0` (compatible
  with the module's `go 1.22` floor). Upstream cutover points:
  v0.34/v0.35 → `go 1.22`, v0.36–v0.38 → `go 1.23`, v0.39/v0.40 →
  `go 1.24`, v0.41+ → `go 1.25`. When this module bumps its Go
  floor in v0.7.6, the testcontainers pin can bump in lockstep
  with whichever cutover-bucket matches the new floor. Also
  pulls transitive Docker / OpenTelemetry / mux deps.
- **`protocol.go` status comment** advanced to step 6 of 7.
- **`.github/workflows/go.yml`** now triggers on changes to
  `tests/protocol/**` (the cross-port fixture directory — both
  the Python and Go conformance suites read these files) and
  gates a `gofmt` check at CI alongside `go vet` and
  `go test -race -v ./...`.

## [0.7.4] - 2026-05-14

**Step 5 of 7 — assertion helpers.** Wires the Layer 1 wire
contract for the five RLS-shape assertions; matches the Python
(`pgrls.testing.assertions`) and TypeScript (`pgrls-test`'s
`assertions.ts`) byte-for-byte wire SQL (same `pgrls_check`
savepoint prefix, same RELEASE-on-success / ROLLBACK-on-failure
pattern, same UPDATE/DELETE verb gate, same RETURNING-keyword
word-boundary check) and shape-equivalent error messages (each
port leads with its idiomatic helper-name prefix —
`AssertRejected:` here, `assertRejected:` in TS,
`assert_rejected:` in Python — same substantive content).

### Added

- **Five assertion helpers** at `pgrlstest/assertions.go`,
  exposed both as `Client` methods (`Client.AssertRows`,
  `Client.AssertVisible`, `Client.AssertInvisible`,
  `Client.AssertRejected`, `Client.AssertSilentlyDropped`) AND
  as exported package-level functions (`pgrlstest.AssertRows`,
  etc.) taking a `*Client` argument. The methods are thin
  forwarders; both forms have identical wire output. Matches
  the TS port's `assertRows(client, sql, options)` callable
  shape exactly (same `PgrlsTestClient` / `*Client` wrapper as
  the first arg). Python's `assert_rows(conn, sql, count=N)`
  takes a lower-level `psycopg.Connection` directly — that's a
  layer-of-abstraction divergence Go inherits from the TS port,
  not a wire-protocol difference.
  - `AssertRows(ctx, sql, &AssertRowsOptions{Count: N})` —
    exact row-count match. Returns `*AssertionError` (matches
    `ErrAssertion`) on mismatch.
  - `AssertVisible(ctx, sql)` — at least one row. Returns
    `*AssertionError` on zero rows.
  - `AssertInvisible(ctx, sql)` — zero rows. Returns
    `*AssertionError` on any rows.
  - `AssertRejected(ctx, sql)` — SQL must raise SQLSTATE 42501
    (`InsufficientPrivilege`). Wraps the query in a
    `SAVEPOINT pgrls_check_<rand>` so the aborted-transaction
    state doesn't poison subsequent queries; RELEASEs on
    success, ROLLBACK TO SAVEPOINTs on any error path.
  - `AssertSilentlyDropped(ctx, sql)` — UPDATE/DELETE with
    RETURNING that yields zero rows (the Postgres RLS
    silent-drop shape). Rejects non-UPDATE/DELETE verbs and
    missing-RETURNING SQL upfront as misuse (`*Error`,
    matches `ErrAPIError`), distinct from the RLS-misbehavior
    case (`*AssertionError`).

- **`AssertRowsOptions` struct** wrapping the row-count argument
  for `Client.AssertRows`. Keeps the call site readable and lets
  future optional knobs (partial-match, regex over a column,
  etc.) extend without churning callers.

- **26 unit tests** in `assertions_test.go` (plus one
  cross-file invariant pin `TestAssertionError_NoUnwrapChain`
  in `errors_test.go`) covering the
  pass/fail branches of each helper, the savepoint wire
  sequence in `AssertRejected` (success → RELEASE,
  42501-rejection → ROLLBACK TO SAVEPOINT, wrong-shape error →
  ROLLBACK TO SAVEPOINT + AssertionError carrying the underlying
  error's type and message in `Msg` — no `Unwrap` chain, pinned
  by `TestAssertionError_NoUnwrapChain`), savepoint-call failure
  paths (SAVEPOINT-on-entry,
  ROLLBACK after wrong-shape body error, RELEASE on success),
  the misuse-error branches in `AssertSilentlyDropped` (SELECT,
  INSERT, missing RETURNING, RETURNING inside a column name,
  empty Command verb), and case-insensitive / word-boundary
  matching for the RETURNING regex. Driver-error propagation
  through every helper is pinned.

### Changed

- **`protocol.go` status comment** advanced to step 5 of 7.
- **Module surface** grows by eleven new exports: the five
  `Client.AssertX` methods, the five package-level `AssertX`
  functions (`pgrlstest.AssertRows` / `AssertVisible` /
  `AssertInvisible` / `AssertRejected` /
  `AssertSilentlyDropped`), and the `AssertRowsOptions`
  config struct.

## [0.7.3] - 2026-05-14

**Step 4 of 7 — Client API.** Wires the `Driver` adapters (v0.7.2)
behind a stable API: per-test transactions, role+claims switching,
simple seeding, optional pinned-conn teardown. The wire-level
Layer 1 sequence is byte-equivalent to the Python and TypeScript
ports — the conformance suite (step 6 / v0.7.5) pins this against
a shared fixture once testcontainers-go is wired up.

### Added

- **`Client` struct** at `pgrlstest/client.go` with a
  `NewClient` constructor and seven public methods
  (`Transaction`, `Exec`, `FetchAll`, `AsRole`, `Seed`, `Close`,
  `Driver`):
  - `NewClient(driver)` builds a client from any `Driver`-shaped
    adapter (typically `pgxdriver.Conn` / `pgxdriver.Pool` or
    `pqdriver.Conn` / `pqdriver.DB`).
  - `Client.Transaction(ctx, body)` issues an explicit `BEGIN`,
    runs `body`, ROLLBACKs in a `defer` regardless of body
    outcome. Body errors shadow rollback errors (the doomed
    transaction's rollback failure isn't the meaningful one).
  - `Client.Exec(ctx, sql, params...)` runs a single statement,
    discards rows. For SELECT / RETURNING-bearing DML, use
    `FetchAll` instead.
  - `Client.FetchAll(ctx, sql, params...)` returns
    `[]map[string]any` — same row shape as `QueryResult.Rows`.
    The TS port carries a generic `<TRow>` type cast for
    ergonomics; Go's type system doesn't permit a free generic
    over `map[string]any` without forcing a conversion step, so
    callers wrap with their own typed-row helper if desired.
  - `Client.AsRole(ctx, role, options, body)` implements the
    full Layer 1 scenario-block protocol — capture current
    role+claims, SAVEPOINT, SET LOCAL ROLE (quoted), set_config
    of claims JSON (when non-nil), run body, then on clean
    exit RELEASE SAVEPOINT + restore prior role + restore (or
    clear) prior claims, or on body error ROLLBACK TO
    SAVEPOINT. `AsRoleOptions.Claims` distinguishes the three
    cases the protocol cares about: `nil` (don't touch GUC),
    `map[string]any{}` (set GUC to JSON `"{}"`), and a
    populated map.
  - `Client.Seed(ctx, table, rows)` bulk-inserts rows. All rows
    must share the same keys; columns are sorted
    alphabetically for deterministic SQL output (Go's randomized
    map iteration would otherwise produce different SQL between
    runs). Schema-qualified `app.invoices` is supported via
    right-split-on-`.`; multi-dot names are rejected as
    cross-database refs aren't supported.
  - `Client.Close(ctx)` type-asserts the underlying driver
    against `Closer` and forwards if present; a no-op for
    caller-owned single-conn drivers.

- **`QuoteIdent` / `QuoteQualified`** at `pgrlstest/idents.go`
  with the Postgres 16 reserved-keyword set (78 entries —
  byte-equivalent to the Python `_RESERVED_KEYWORDS` and the
  TypeScript `RESERVED_KEYWORDS`). Reserved keywords match
  case-insensitively; embedded double quotes are escaped via
  doubling; C0 control characters and DEL are rejected
  outright with a clear error rather than emitting confusing
  SQL.

- **`NewSavepointName`** at `pgrlstest/savepoint.go` —
  crypto/rand-backed 8-hex-char suffix generator shared between
  `Client.AsRole` (prefix `pgrls_actor`) and the assertion
  helpers (prefix `pgrls_check`, added in v0.7.4). Mirrors
  Python's `secrets.token_hex(4)` and TypeScript's
  `crypto.getRandomValues` wire shape exactly.

- **35+ unit-test functions** covering the wire sequence (clean
  exit, error path, outer-claims restore, reserved-keyword
  quoting), the seed helper's quoting and key-consistency
  checks, the savepoint-name format and entropy, the identifier-
  quoting matrix (plain names, reserved keywords, non-plain
  needing quotes, embedded quotes, control-char rejection),
  and the `Close` type-assertion contract (forwards when
  driver is a `Closer`, no-op otherwise). Tests use a
  `recordingDriver` so the wire-level SQL ordering is
  asserted directly — real-Postgres conformance lands in
  v0.7.5 step 6.

### Changed

- **`protocol.go` status comment** advanced to step 4 of 7.
- **Module surface** grows by seven new public exports: the
  `Client` struct (with `NewClient` constructor and
  `Transaction` / `Exec` / `FetchAll` / `AsRole` / `Seed` /
  `Close` / `Driver` methods), the `AsRoleOptions` config
  struct, and the four helpers `QuoteIdent`, `QuoteQualified`,
  `NewSavepointName`, and `ReservedKeywords` (the keyword map,
  exported so callers can verify their custom role names
  against the same wire rules pgrls-test uses).

## [0.7.2] - 2026-05-13

**Step 3 of 7 — pgx + lib/pq driver adapters.** Implements the `Driver`
interface (v0.7.1) against the two dominant Go Postgres drivers. Each
adapter ships two constructors: one for a caller-owned pinned connection,
one for the pool variant that lazily acquires + releases via `Closer`.

### Added

- **`drivers/pgx` package** at `pgrlstest/drivers/pgx/pgx.go` —
  jackc/pgx adapter.
  - `pgx.Conn(c *pgx.Conn) pgrlstest.Driver` wraps a single
    `*pgx.Conn` directly; caller owns the connection lifecycle.
  - `pgx.Pool(p *pgxpool.Pool) pgrlstest.Driver` wraps a
    `*pgxpool.Pool`; lazily calls `pool.Acquire(ctx)` on first
    query, pins the connection for every subsequent call,
    releases via `Close(ctx)` (implements `pgrlstest.Closer`).
    Race-safety model: a single `sync.Mutex` serializes every
    `Query` / `Rollback` / `Close` end-to-end (mirrors the
    intent of the postgres.js adapter's `sql.reserve()`
    pattern from `pgrls-test` v0.6.2, simpler implementation
    because Go's mutex gives us the race guarantees for free
    — no need for the TS port's promise-memoization +
    identity-guarded clear-on-reject gymnastics).
  - SQLSTATE 42501 classification via `errors.As(err,
    &pgconn.PgError)` + `pgerrcode.InsufficientPrivilege`.

- **`drivers/pq` package** at `pgrlstest/drivers/pq/pq.go` —
  lib/pq + database/sql adapter.
  - `pq.Conn(c *sql.Conn) pgrlstest.Driver` wraps a single
    pinned `*sql.Conn`; caller owns the lifecycle.
  - `pq.DB(d *sql.DB) pgrlstest.Driver` wraps a `*sql.DB`;
    lazily calls `db.Conn(ctx)` on first query, pins the
    connection, releases via `Close(ctx)` (implements
    `pgrlstest.Closer`).
  - SQLSTATE 42501 classification via `errors.As(err,
    &pq.Error)` + string equality against `"42501"` (lib/pq
    doesn't ship a centralized SQLSTATE constants package).

- **Shared routing logic** in both adapters: SELECT / WITH /
  VALUES / SHOW / EXPLAIN plus any SQL containing a top-level
  `RETURNING` keyword (case-insensitive, word-boundary
  matched) routes through the rows-returning path
  (`pgx.Rows` / `*sql.Rows` iteration into
  `[]map[string]any`); everything else uses the command-tag
  / exec path. `Command` is normalized to upper-case via the
  shared `firstWord` helper. `hasReturning` is conservatively
  word-boundaried so a literal column named `returning_col`
  doesn't accidentally route as a returning DML.

- **20 unit-test functions** (10 per adapter package,
  parametrized so the actual test-case count is higher) pinning
  SQLSTATE classification correctness against both wrapped and
  direct error chains, `firstWord` / `hasReturning` /
  `isIdentChar` helper behavior (including the underscore-
  boundary case — `returning_col` must NOT match RETURNING;
  earlier letters-only boundary was a real bug caught during
  local testing), pool / DB driver `Close` idempotency on
  never-used drivers, and compile-time interface-satisfaction
  (`var _ pgrlstest.Driver = (*…)(nil)` + `var _
  pgrlstest.Closer = (*…)(nil)`). Real-Postgres integration
  tests land in v0.7.5 step 6 via testcontainers-go; this
  release verifies what can be verified without a database.

### Changed

- **go.mod gains driver-library deps**: `pgx/v5 v5.7.1`,
  `lib/pq v1.10.9`, `pgerrcode v0.0.0-20240316143900`, plus
  pgx's transitive deps (pgpassfile, pgservicefile, puddle,
  golang.org/x/crypto, x/sync, x/text). All are runtime deps
  (the adapter packages import them directly). Test-time
  deps (testcontainers-go, etc.) come in v0.7.5 step 6 for
  the conformance suite.

## [0.7.1] - 2026-05-13

**Step 2 of 7 — Driver interface.** Adds the abstraction the test client
(step 4) will use to talk to Postgres without coupling to a specific driver
library. One adapter per supported driver (`drivers/pgx`, `drivers/pq`)
ships in step 3 / v0.7.2; this release pins the contract.

### Added

- **`Driver` interface** at `pgrlstest/driver.go` with three required
  methods: `Query(ctx, sql, params...)` returns a normalized
  `QueryResult`; `Rollback(ctx)` discards the current transaction
  (must be safe even when the transaction is in aborted state);
  `IsInsufficientPrivilege(err)` classifies a driver error as a
  SQLSTATE 42501 RLS rejection. Cross-language guarantee:
  structurally aligned with the TypeScript `Driver` interface
  and the Python client's reach-into-psycopg pattern — same
  three operations, same Layer 1 wire output, with Go-idiomatic
  adaptations (`ctx context.Context` first arg, variadic
  `params ...any`, error return alongside the result).

- **`QueryResult` struct** with `Rows []map[string]any`, `Command
  string`, `RowCount int64`. Matches the union of what pgx
  (`pgx.Rows` + command tag) and lib/pq (`database/sql.Rows` +
  `Result`) expose, reduced to the three fields the assertion
  helpers (step 5 / v0.7.4) actually read.

- **`Closer` optional interface** at the same file. Adapters whose
  underlying client needs explicit teardown (pgx's `*pgxpool.Conn`,
  lib/pq's `*sql.Conn`) implement it; the test client (step 4 /
  v0.7.3) will type-assert and call `Close(ctx)` if present.
  `*sql.DB`-backed adapters that don't need teardown just omit
  the method — Go's idiomatic "optional method via type assertion"
  pattern.

- **8 unit tests** at `pgrlstest/driver_test.go` pinning the
  interface shape, the `QueryResult` zero-value behavior, the
  type-assertion contract for `Closer`, context propagation
  through `Query` and `Rollback`, the `IsInsufficientPrivilege`
  nil-input contract, and `QueryResult.Rows` heterogeneous value
  types. Includes a compile-time `var _ Driver =
  (*fakeDriver)(nil)` assertion so a future signature change
  breaks the build, not just the tests.

## [0.7.0] - 2026-05-13

**Step 1 of 7 — scaffold.** Establishes the module path, the Layer 1 protocol-
version constant, and the error types. Subsequent steps ship as their own
minor versions (v0.7.1 = Driver interface; v0.7.2 = pgx + lib/pq adapters;
v0.7.3 = Client API; v0.7.4 = assertion helpers; v0.7.5 = conformance suite;
v0.7.6 = CI hardening + release plumbing). Each step ships as a separately-
reviewable PR. The TypeScript port took seven steps to ship v0.6.0;
the Go port follows the same staged release pattern.

### Added

- **Module skeleton** at `go/` in the [pgrls/pgrls](https://github.com/pgrls/pgrls)
  monorepo. Module path `github.com/pgrls/pgrls/go`; import path for the
  package is `github.com/pgrls/pgrls/go/pgrlstest`. Tag convention:
  `go/v0.7.0`, `go/v0.7.1`, etc. — distinct from the Python (`v0.5.10`)
  and TypeScript (`ts-v0.6.2`) release tracks so the three ports can
  ship independently.

- **`ProtocolVersion = 1` constant.** Cross-language contract: the
  Python and TypeScript clients also export the same integer. A future
  bump of the wire shape (savepoint naming, claims-encoding rules,
  etc.) updates all three in lockstep.

- **`*Error` and `*AssertionError` types** with the sentinel matchers
  `ErrAPIError` and `ErrAssertion`. Mirrors `PgrlsTestError` and
  `PgrlsTestAssertionError` in Python and TypeScript. The Go type
  names use Go's idiomatic short form (already namespaced under
  `pgrlstest`); the `errors.Is` machinery lets callers route failures
  without type-asserting. 11 unit tests pin the exported surface,
  error formatting, sentinel matching, and `Unwrap()` behavior.

- **Per-port README + CHANGELOG + LICENSE** at `go/`. Status table
  marks each Layer 1 capability against its planned step number.

### Planned (later steps in v0.7.x)

- **v0.7.1** — Step 2: `Driver` interface (`Query`, `Rollback`,
  `IsInsufficientPrivilege`, optional `Close`). Mirrors the TypeScript
  `Driver` shape that the pgx and lib/pq adapters will implement.
- **v0.7.2** — Step 3: pgx adapter (`pgrlstest/drivers/pgx`) + lib/pq
  adapter (`pgrlstest/drivers/pq`). The two cover the dominant Go
  Postgres drivers; both expose a single `*pgxpool.Conn` / `*sql.Conn`
  for the pinned-connection semantics the protocol needs.
- **v0.7.3** — Step 4: `Client` struct with `Transaction`, `AsRole`,
  `Exec`, `FetchAll`, `Seed` methods.
- **v0.7.4** — Step 5: five assertion helpers (`AssertRows`,
  `AssertVisible`, `AssertInvisible`, `AssertRejected`,
  `AssertSilentlyDropped`).
- **v0.7.5** — Step 6: cross-language conformance suite running against
  testcontainers-go, exercising the same Layer 1 contract the Python
  and TypeScript conformance suites verify.
- **v0.7.6** — Step 7: CI hardening (`golangci-lint`, `govulncheck`)
  and GitHub Release plumbing. The `go/v0.7.x` tags trigger
  per-version `go list -m` proxy refreshes; no separate publish
  registry — Go consumers `go get github.com/pgrls/pgrls/go@<tag>`.

The step numbering matches the TypeScript port's history at PRs #28–#41
for ease of cross-reference; the Go port may collapse steps if a single
PR is small enough to review cleanly.
