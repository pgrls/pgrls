package pgrlstest

import "context"

// QueryResult is the normalized result of a single SQL execution.
//
// Mirrors the union of what pgx's `pgx.Rows` + command tag and
// lib/pq's `database/sql.Rows` + result expose, but reduced to
// the three fields the test client actually needs. Adapters
// (`drivers/pgx`, `drivers/lib_pq` — step 3 / v0.7.2) translate
// their native types into this shape so the client code stays
// driver-agnostic.
//
// Cross-language guarantee: byte-equivalent to the TypeScript
// `QueryResult` interface (`ts/src/drivers/types.ts`) and the
// Python `psycopg.Cursor.description + fetchall()` tuple — the
// same three concepts (rows, command verb, row count) reach the
// assertion helpers from any of the three ports.
type QueryResult struct {
	// Rows returned by the query, as plain string-keyed maps.
	//
	// For SELECT and any RETURNING clause: the result rows.
	// For UPDATE / DELETE / INSERT without RETURNING: nil or
	// empty — drivers don't synthesize rows for non-returning
	// DML. The assertion helpers (`AssertSilentlyDropped` in
	// particular) treat `len(Rows) == 0` as the signal to
	// look at `Command` for the UPDATE/DELETE gate.
	//
	// `[]map[string]any` (Go 1.18+) keeps the test ergonomics
	// — `result.Rows[0]["tenant_id"]` reads naturally — and
	// matches the row shape the TS / Python clients return.
	// Strongly-typed row decoding is a future addition (a
	// generic `FetchAll[T]` wrapper, planned for v0.7.3 step
	// 4); the Driver interface stays untyped so adapters
	// don't have to carry generic plumbing.
	//
	// **Mutation contract**: callers MUST treat Rows as read-
	// only. Adapter implementations are free to reuse backing
	// allocations between calls — pgx in particular may
	// hand back rows that share buffers with its row-iteration
	// state. Go has no `readonly slice` analogue (unlike the
	// TS port's `readonly Record<string, unknown>[]`), so the
	// contract is documented, not enforced. If a caller needs
	// to mutate (rare), copy first via `slices.Clone` /
	// `maps.Clone`.
	Rows []map[string]any

	// Command is the verb returned by Postgres in the command
	// tag (`SELECT`, `INSERT`, `UPDATE`, `DELETE`, `BEGIN`,
	// `COMMIT`, `ROLLBACK`, `SAVEPOINT`, `RELEASE`, etc.) —
	// always upper-case, never abbreviated.
	//
	// `AssertSilentlyDropped` reads this to gate on
	// UPDATE/DELETE only; a SELECT returning zero rows isn't a
	// "silent drop," it's just an empty SELECT.
	//
	// Empty string when the driver can't determine the verb
	// (defensive — shouldn't happen against a real Postgres,
	// but adapter implementations should map their "unknown"
	// state to "" rather than panicking).
	Command string

	// RowCount is the affected-row count from the command tag.
	//
	// For SELECT and any RETURNING clause: number of rows
	// returned (matches `len(Rows)`).
	// For UPDATE / DELETE / INSERT without RETURNING: number
	// of rows touched.
	//
	// `int64` matches both `pgx.CommandTag.RowsAffected()` and
	// `database/sql.Result.RowsAffected()` — neither library
	// uses `int`. The TS port uses `number`; Python uses
	// `int`. The wider Go integer is a no-op at the call sites
	// and avoids an explicit cast inside the adapter.
	RowCount int64
}

// Driver is the abstraction the pgrls test client uses to talk
// to Postgres without coupling to a specific Go database driver.
//
// One adapter per supported driver lives under `drivers/`
// (`drivers/pgx`, `drivers/lib_pq` — step 3 / v0.7.2); each
// exports a factory that wraps a user-supplied connection /
// pool into this interface so callers keep their existing
// connection management (pools, hooks, instrumentation,
// observability wrappers) untouched.
//
// Why an interface instead of importing pgx or lib/pq directly:
//
//   - Two dominant Go Postgres drivers have meaningfully different
//     APIs (pgx's `Query(ctx, sql, args...)` vs database/sql's
//     `db.QueryContext`); pinning to one would force users on the
//     other to maintain a fork or a wrapper.
//   - Error shapes differ (pgx exposes `*pgconn.PgError.Code`,
//     lib/pq exposes `*pq.Error.Code`); the
//     `IsInsufficientPrivilege` predicate hides that detail so
//     the client doesn't carry conditionals.
//   - Future drivers (a hypothetical Bun adapter when Bun's Go
//     binding stabilizes, a Cloudflare Hyperdrive adapter) plug
//     in without touching client code.
//
// The interface is deliberately small. The Python client reaches
// into psycopg for cursors and savepoints; the Go port (like the
// TS port) issues savepoint SQL via `Query` so the driver
// doesn't need a separate savepoint API.
//
// Cross-language guarantee: byte-equivalent to the TypeScript
// `Driver` interface. All three ports issue the same Layer 1
// wire sequence (BEGIN → optional setup → per-scenario
// SAVEPOINT pgrls_actor_<rand> → SET LOCAL ROLE → set_config →
// assertions → ROLLBACK TO SAVEPOINT → final ROLLBACK).
type Driver interface {
	// Query runs a parameterized SQL statement and returns the
	// normalized result.
	//
	// `params` uses Postgres's positional placeholders
	// (`$1, $2, ...`); both supported drivers consume those
	// natively, so the adapter doesn't need to rewrite the
	// SQL.
	//
	// Context is mandatory (Go convention — every driver call
	// must be cancellable). Test callers typically pass
	// `context.Background()` or a per-test context with a
	// deadline.
	//
	// Errors from the underlying driver propagate unchanged —
	// the test client uses `IsInsufficientPrivilege` to
	// classify them (right-shape RLS rejection vs typo / table-
	// not-found / etc.). Adapters MUST NOT wrap errors in a
	// way that obscures the original error's type;
	// `IsInsufficientPrivilege` typically uses `errors.As` on
	// the driver's structured-error type, which only works if
	// the chain reaches the underlying error.
	Query(ctx context.Context, sql string, params ...any) (QueryResult, error)

	// Rollback discards the current transaction.
	//
	// Called by `Client.Transaction()`'s deferred cleanup
	// (step 4 / v0.7.3) to revert the test's writes. Must be
	// safe to call even when the transaction is in an aborted
	// state (Postgres's "current transaction is aborted"
	// condition); adapters typically issue `ROLLBACK` directly
	// via the driver's lower-level escape hatch rather than
	// through `Query` so the aborted state doesn't bounce the
	// statement.
	//
	// Returning an error from Rollback is for catastrophic
	// failures (connection lost, etc.). Routine "transaction
	// already finished" cases SHOULD be swallowed.
	Rollback(ctx context.Context) error

	// IsInsufficientPrivilege returns true iff `err` is a
	// Postgres SQLSTATE 42501 (insufficient_privilege) error.
	//
	// RLS policy violations surface as 42501 — both
	// `WITH CHECK` failures and `USING` rejections on non-
	// RETURNING DML. `AssertRejected` (step 5 / v0.7.4) uses
	// this to tell the right-shape failure (RLS rejected the
	// write) apart from any other Postgres error.
	//
	// Adapters check the driver's structured-error type
	// (typically via `errors.As`) and map 42501 to true.
	// Non-Postgres errors (connection errors, context-
	// cancellation, etc.) MUST return false — they're not the
	// RLS signal the assertion is looking for.
	IsInsufficientPrivilege(err error) bool
}

// Closer is the optional secondary interface drivers may
// implement to surface explicit teardown.
//
// pgx's `*pgxpool.Pool` and reserved connections need an
// explicit `Release()` / `Close()` to return the connection to
// the pool. lib/pq's `*sql.Conn` similarly needs `Close()`.
// `database/sql.DB` does not — the standard library manages the
// pool itself.
//
// The test client (`Client.Close()` in step 4 / v0.7.3) does a
// type assertion: `if c, ok := driver.(Closer); ok {
// c.Close(ctx) }`. Adapters that don't need teardown just don't
// implement this interface, and the client's call becomes a
// no-op for them.
//
// Cross-language analogue: the TypeScript port models the same
// pattern as an optional `close?` method on the `Driver`
// interface; in Go the idiomatic equivalent is a separate
// interface that callers type-assert to.
//
// Signature divergence from TS: `Close` here takes a `ctx
// context.Context`, while the TS counterpart is `close():
// Promise<void>`. Go's pervasive context convention applies to
// teardown too — `Client.Close()` (step 4) typically receives a
// short-deadline ctx so a hung pool drain doesn't block test
// shutdown indefinitely. Callers without a meaningful ctx
// (panic-recovery defers, test-teardown calls without
// per-test context wiring) can pass `context.Background()`.
type Closer interface {
	Close(ctx context.Context) error
}
