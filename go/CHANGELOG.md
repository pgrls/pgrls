# Changelog

All notable changes to `pgrls-test-go` (the Go port of `pgrls.testing`).

The format follows [Keep a Changelog](https://keepachangelog.com/) and the
module adheres to [Semantic Versioning](https://semver.org/). Protocol
versioning is independent — `ProtocolVersion` (currently `1`) only bumps
on wire-level breaking changes shared with the Python and TypeScript clients.

## [0.7.0] - 2026-05-13

**Step 1 of N — scaffold.** Establishes the module path, the Layer 1 protocol-
version constant, and the error types. Subsequent steps add the `Driver`
interface, the pgx + lib/pq adapters, the `Client` API, the five assertion
helpers, and the cross-language conformance suite. The TypeScript port took
seven steps from v0.6.0 → v0.6.2; the Go port follows the same staged
release pattern so each step ships as a reviewable PR.

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

- Step 2: `Driver` interface (`Query`, `Rollback`, `IsInsufficientPrivilege`,
  optional `Close`). Mirrors the TypeScript `Driver` shape that the pgx
  and lib/pq adapters will implement.
- Step 3: pgx adapter (`pgrlstest/drivers/pgx`) + lib/pq adapter
  (`pgrlstest/drivers/lib_pq`). The two cover the dominant Go Postgres
  drivers; both expose a single `*pgxpool.Conn` / `*sql.Conn` for the
  pinned-connection semantics the protocol needs.
- Step 4: `Client` struct with `Transaction`, `AsRole`, `Exec`,
  `FetchAll`, `Seed` methods.
- Step 5: five assertion helpers (`AssertRows`, `AssertVisible`,
  `AssertInvisible`, `AssertRejected`, `AssertSilentlyDropped`).
- Step 6: cross-language conformance suite running against
  testcontainers-go, exercising the same Layer 1 contract the Python
  and TypeScript conformance suites verify.
- Step 7: `go/v0.7.0` release tag + GitHub Release plumbing, including
  the `go vet` / `go test -race` / `golangci-lint` CI gates.

The step numbering matches the TypeScript port's history at PRs #28–#41
for ease of cross-reference; the Go port may collapse steps if a single
PR is small enough to review cleanly.
