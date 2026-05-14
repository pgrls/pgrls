# pgrls-test-go

Go port of [`pgrls.testing`](https://pypi.org/project/pgrls/) — code-first RLS testing for Postgres.

Implements the cross-language Layer 1 protocol (`ProtocolVersion = 1`) shared with the Python (`pgrls.testing`) and TypeScript ([`pgrls-test`](https://www.npmjs.com/package/pgrls-test)) clients. Fixtures roundtrip across all three; the same RLS-protected schema can be exercised from any language.

> **Status: v0.7.2 — step 3 of 7 (pgx + lib/pq adapters).** This release adds adapter packages for the two dominant Go Postgres drivers ([pgx](https://github.com/jackc/pgx) and [lib/pq](https://github.com/lib/pq)). Each ships two constructors: one for a caller-owned pinned connection, one for the pool variant that lazily acquires + releases via `Closer`. Subsequent steps add the `Client` API (transactions, role-switching, seed), the five assertion helpers, the cross-language conformance suite, and CI hardening. Track progress in [CHANGELOG.md](CHANGELOG.md).

## Install

```sh
go get github.com/pgrls/pgrls/go@latest
```

Import:

```go
import "github.com/pgrls/pgrls/go/pgrlstest"
```

## Status against the Layer 1 protocol

| Capability | Step | Status |
|---|---|---|
| `ProtocolVersion` constant | 1 | ✅ shipped (v0.7.0) |
| `Error` + `AssertionError` types | 1 | ✅ shipped (v0.7.0) |
| `Driver` + `Closer` interfaces + `QueryResult` | 2 | ✅ shipped (v0.7.1) |
| pgx adapter (`drivers/pgx`: `Conn` + `Pool`) | 3 | ✅ shipped (v0.7.2) |
| lib/pq adapter (`drivers/pq`: `Conn` + `DB`) | 3 | ✅ shipped (v0.7.2) |
| `Client` (Transaction, AsRole, Exec, FetchAll, Seed) | 4 | planned (v0.7.3) |
| Assertion helpers (AssertRows, AssertVisible, AssertInvisible, AssertRejected, AssertSilentlyDropped) | 5 | planned (v0.7.4) |
| Cross-language conformance suite | 6 | planned (v0.7.5) |
| CI hardening + release plumbing | 7 | planned (v0.7.6) |

## Cross-language guarantee

The Python, TypeScript, and Go clients all implement the same Layer 1 protocol. A fixture set written for one client interoperates with the others — the wire sequence (`SAVEPOINT pgrls_actor_<rand>`, `SET LOCAL ROLE …`, `set_config('request.jwt.claims', $1, true)`, rollback to savepoint) is byte-identical across the three.

See [docs/pgrls-test-protocol.md](../docs/pgrls-test-protocol.md) (in the parent directory) for the full spec.

## Comparison to Python and TypeScript

| Concept | Python | TypeScript | Go |
|---|---|---|---|
| Package | `pgrls.testing.PgrlsTestClient` | `pgrls-test.PgrlsTestClient` | `pgrlstest.Client` (step 4) |
| Error base | `PgrlsTestError` | `PgrlsTestError` | `*pgrlstest.Error` |
| Assertion error | `PgrlsTestAssertionError` | `PgrlsTestAssertionError` | `*pgrlstest.AssertionError` |
| Protocol version | `PROTOCOL_VERSION = 1` | `PROTOCOL_VERSION = 1` | `ProtocolVersion = 1` |
| Driver abstraction | (inlined psycopg cursor) | `Driver` interface | `Driver` interface |
| Row shape | `Cursor.fetchall()` tuples | `readonly Record<string, unknown>[]` | `[]map[string]any` |
| Driver teardown | caller-owned connection | optional `close?()` method | separate `Closer` interface |

The Go type names use Go's idiomatic short form (just `Error`, `AssertionError`) since they're already namespaced under the `pgrlstest` package. The `errors.Is` machinery exposes two sentinel values — `ErrAPIError` and `ErrAssertion` — for callers that want to route errors without type-asserting.

The `Driver` and `Closer` interfaces are structurally aligned with the TypeScript `Driver` — semantically identical operations (parameterized query, rollback, error classification, optional teardown) with Go-idiomatic adaptations (`ctx context.Context` first arg, variadic `params ...any`, error return alongside the result, separate `Closer` interface for the optional-teardown method).

## License

MIT — same as the main pgrls project. See `LICENSE`.

## Source

- Repo: [github.com/pgrls/pgrls](https://github.com/pgrls/pgrls)
- Module: `github.com/pgrls/pgrls/go`
- Tag convention: `go/v0.7.0`, `go/v0.7.1`, … (distinct from `v0.5.10` Python tags and `ts-v0.6.1` TypeScript tags so the three ports ship independently)
