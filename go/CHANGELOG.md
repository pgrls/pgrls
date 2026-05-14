# Changelog

All notable changes to `pgrls-test-go` (the Go port of `pgrls.testing`).

The format follows [Keep a Changelog](https://keepachangelog.com/) and the
module adheres to [Semantic Versioning](https://semver.org/). Protocol
versioning is independent — `ProtocolVersion` (currently `1`) only bumps
on wire-level breaking changes shared with the Python and TypeScript clients.

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
    Mirrors the postgres.js adapter's `sql.reserve()` pattern
    from `pgrls-test` v0.6.2 — same race-safety design (cached
    promise, identity-guarded clear-on-reject) goes in step 6
    once the conformance suite exercises concurrency against
    a real Postgres.
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
library. One adapter per supported driver (`drivers/pgx`, `drivers/lib_pq`)
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
  and TypeScript (`ts-v0.6.1`) release tracks so the three ports can
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
  adapter (`pgrlstest/drivers/lib_pq`). The two cover the dominant Go
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
