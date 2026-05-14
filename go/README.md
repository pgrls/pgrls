# pgrls-test-go

Go port of [`pgrls.testing`](https://pypi.org/project/pgrls/) — code-first RLS testing for Postgres.

Implements the cross-language Layer 1 protocol (`ProtocolVersion = 1`) shared with the Python (`pgrls.testing`) and TypeScript ([`pgrls-test`](https://www.npmjs.com/package/pgrls-test)) clients. Fixtures roundtrip across all three; the same RLS-protected schema can be exercised from any language.

> **Status: v0.7.4 — step 5 of 7 (assertion helpers).** This release adds the five RLS-shape assertion helpers — `AssertRows`, `AssertVisible`, `AssertInvisible`, `AssertRejected` (savepoint-wrapped via `pgrls_check_<rand>`), and `AssertSilentlyDropped` (UPDATE/DELETE … RETURNING with the row-count check) — each exposed as a `Client` method and matching the Python / TypeScript wire sequence byte-for-byte. Subsequent steps add the cross-language conformance suite and CI hardening. Track progress in [CHANGELOG.md](CHANGELOG.md).

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
| `Client` (Transaction, AsRole, Exec, FetchAll, Seed, Close, Driver) | 4 | ✅ shipped (v0.7.3) |
| `QuoteIdent` + `QuoteQualified` + `ReservedKeywords` (78 entries) | 4 | ✅ shipped (v0.7.3) |
| `NewSavepointName` (crypto/rand 4-byte → 8-hex) | 4 | ✅ shipped (v0.7.3) |
| Assertion helpers (AssertRows, AssertVisible, AssertInvisible, AssertRejected, AssertSilentlyDropped) | 5 | ✅ shipped (v0.7.4) |
| Cross-language conformance suite | 6 | planned (v0.7.5) |
| CI hardening + release plumbing | 7 | planned (v0.7.6) |

## Assertion helper semantics

| Helper | Passes when | Fails when |
|---|---|---|
| `AssertRows(ctx, sql, &AssertRowsOptions{Count: N})` | query returns exactly N rows | row count differs (`*AssertionError`) |
| `AssertVisible(ctx, sql)` | query returns ≥ 1 row | zero rows (`*AssertionError`) |
| `AssertInvisible(ctx, sql)` | query returns 0 rows | any rows (`*AssertionError`) |
| `AssertRejected(ctx, sql)` | Postgres raises `InsufficientPrivilege` (SQLSTATE `42501`) | query succeeded OR raised a different error (`*AssertionError`) |
| `AssertSilentlyDropped(ctx, sql)` | `UPDATE/DELETE … RETURNING` succeeds but `USING` filters the row out before the write; `RETURNING` is empty | DML raises (driver error propagates) OR `RETURNING` returns rows (`*AssertionError`). Non-UPDATE/DELETE SQL (SELECT, INSERT, …) and UPDATE/DELETE missing `RETURNING` both return `*Error` (matches `ErrAPIError`) — caller-error, distinct from RLS-misbehavior. |

`AssertRejected` and `AssertSilentlyDropped` distinguish two distinct Postgres failure modes — `WITH CHECK` violations raise (catch with the first); `USING` filtering of `UPDATE`/`DELETE` returns silently empty (catch with the second).

`AssertSilentlyDropped` rejects mis-shaped SQL via the result's command-tag verb, which means the SQL is fully executed (and any side-effects committed within the current transaction) before the verb-gate rejects it. Pass only the UPDATE/DELETE you actually want to execute.

Each helper is exposed both as a `Client` method (`client.AssertRows(ctx, sql, opts)`) AND as a package-level function (`pgrlstest.AssertRows(ctx, client, sql, opts)`). The two forms have identical wire output — the methods are thin forwarders.

## Cross-language guarantee

The Python, TypeScript, and Go clients all implement the same Layer 1 protocol. A fixture set written for one client interoperates with the others — the wire sequence (`SAVEPOINT pgrls_actor_<rand>`, `SET LOCAL ROLE …`, `set_config('request.jwt.claims', $1, true)`, rollback to savepoint) follows the same step-by-step pattern across the three. Two language-driven knobs are NOT byte-equal but don't affect RLS evaluation:

- **JWT claims JSON encoding.** Each port uses its language's stock encoder: Python `json.dumps` and TS `JSON.stringify` preserve insertion order; Go `encoding/json` sorts keys alphabetically. The encoded JSON string is the `$1` parameter passed to `set_config('request.jwt.claims', $1, true)` — the SQL itself is identical; only the parameter bytes differ on input.
- **`Seed` column ordering.** Python and TS preserve dict / object insertion order in the emitted `INSERT INTO t (col1, col2)` SQL; Go sorts alphabetically (Go has no insertion-order map primitive). `Seed` is the test-helper layer, deliberately scoped out of the Layer 1 protocol — see `docs/pgrls-test-protocol.md` ("What's deliberately out of contract").

See [docs/pgrls-test-protocol.md](../docs/pgrls-test-protocol.md) (in the parent directory) for the full spec.

## Comparison to Python and TypeScript

| Concept | Python | TypeScript | Go |
|---|---|---|---|
| Package | `pgrls.testing.PgrlsTestClient` | `pgrls-test.PgrlsTestClient` | `pgrlstest.Client` |
| Error base | `PgrlsTestError` | `PgrlsTestError` | `*pgrlstest.Error` |
| Assertion error | `PgrlsTestAssertionError` | `PgrlsTestAssertionError` | `*pgrlstest.AssertionError` |
| Protocol version | `PROTOCOL_VERSION = 1` | `PROTOCOL_VERSION = 1` | `ProtocolVersion = 1` |
| Driver abstraction | (inlined psycopg cursor) | `Driver` interface | `Driver` interface |
| Row shape | `list[dict[str, object]]` (psycopg `dict_row` factory) | `readonly Record<string, unknown>[]` | `[]map[string]any` |
| Driver teardown | caller-owned connection | optional `close?()` method | separate `Closer` interface |

The Go type names use Go's idiomatic short form (just `Error`, `AssertionError`) since they're already namespaced under the `pgrlstest` package. The `errors.Is` machinery exposes two sentinel values — `ErrAPIError` and `ErrAssertion` — for callers that want to route errors without type-asserting.

The `Driver` and `Closer` interfaces are structurally aligned with the TypeScript `Driver` — semantically identical operations (parameterized query, rollback, error classification, optional teardown) with Go-idiomatic adaptations (`ctx context.Context` first arg, variadic `params ...any`, error return alongside the result, separate `Closer` interface for the optional-teardown method).

## License

MIT — same as the main pgrls project. See `LICENSE`.

## Source

- Repo: [github.com/pgrls/pgrls](https://github.com/pgrls/pgrls)
- Module: `github.com/pgrls/pgrls/go`
- Tag convention: `go/v0.7.0`, `go/v0.7.1`, … (distinct from `v0.5.10` Python tags and `ts-v0.6.2` TypeScript tags so the three ports ship independently)
