// Package pgx is the [jackc/pgx] adapter for the pgrls test
// client.
//
// Two constructors:
//
//   - Conn(c) wraps a single `*pgx.Conn` directly. The caller
//     owns the connection lifecycle; the adapter does NOT
//     implement `pgrlstest.Closer`. Use this when you already
//     have a single connection (e.g. from
//     `pgx.Connect(ctx, url)` in test setup).
//
//   - Pool(p) wraps a `*pgxpool.Pool`. The adapter lazily
//     acquires one connection from the pool on the first
//     `Query` / `Rollback` call and uses that pinned connection
//     for every subsequent call. Implements `pgrlstest.Closer`
//     — `Close(ctx)` releases the pinned connection back to
//     the pool. Idempotent. Mirrors the postgres.js adapter's
//     `sql.reserve()` pattern from `pgrls-test` v0.6.2.
//
// Why both: pgx users come in two shapes. Application-tier
// users typically have a `*pgxpool.Pool` (production setup);
// integration test runners against testcontainers typically
// have a `*pgx.Conn` (single-shot connection per test). Both
// are first-class.
//
// SQLSTATE 42501 classification routes through `pgconn.PgError`
// (pgx's structured-error type) and the standardized
// `pgerrcode.InsufficientPrivilege` constant — same string
// `"42501"` either way, but using the constant keeps the
// adapter resistant to typos.
//
// [jackc/pgx]: https://github.com/jackc/pgx
package pgx

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/jackc/pgerrcode"
	pgxlib "github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/pgrls/pgrls/go/pgrlstest"
)

// connQueryer is the subset of `*pgx.Conn` / `*pgxpool.Conn`
// the adapter actually uses. Defined as an interface so the
// two constructors (Conn / Pool) can share `queryWith` /
// `rollbackWith` implementations without duplicating the
// pgx-specific row-iteration logic.
//
// Both `*pgx.Conn` and `*pgxpool.Conn` satisfy this
// structurally (their Query / Exec / Ping signatures match).
type connQueryer interface {
	Query(ctx context.Context, sql string, args ...any) (pgxlib.Rows, error)
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// Conn wraps a single `*pgx.Conn` into a pgrlstest.Driver.
//
// The caller owns the connection lifecycle — the returned
// driver does NOT implement `pgrlstest.Closer`. To release
// the connection, the caller invokes `c.Close(ctx)` directly.
//
// Use this for tests that already hold a single pgx connection
// (typical for testcontainers-backed integration suites).
func Conn(c *pgxlib.Conn) pgrlstest.Driver {
	return &connDriver{conn: c}
}

// Pool wraps a `*pgxpool.Pool` into a pgrlstest.Driver that
// implements pgrlstest.Closer.
//
// On the first `Query` / `Rollback` call the adapter lazily
// acquires a single connection from the pool via
// `pool.Acquire(ctx)` and pins it for every subsequent call —
// this keeps `BEGIN` / `SET LOCAL` / queries / `ROLLBACK` on
// the same connection so the transaction state actually
// persists. Without pinning, pool-acquired connections rotate
// across calls and the transaction breaks.
//
// `Close(ctx)` releases the pinned connection. Idempotent —
// calling it more than once is safe; subsequent `Query` calls
// re-acquire from the pool (useful for test harnesses that
// recycle the driver across test cases).
//
// Race-safety model (v0.7.2): a single `sync.Mutex` serializes
// every `Query` / `Rollback` / `Close` end-to-end. Concurrent
// first-queries do NOT share one acquire — they queue, the
// first wins the race to call `pool.Acquire`, subsequent
// callers see the pinned conn and proceed. This is simpler
// than the TS port's promise-memoization pattern; the test-
// client use case has serial driver calls so the serialization
// cost is nil. A failed `pool.Acquire` leaves `d.acquired ==
// nil`, so the next call retries — no jam on transient
// failures. The more elaborate identity-guarded promise pattern
// from `pgrls-test` v0.6.2 (postgres.js adapter) is unnecessary
// here because Go's mutex gives us the same race guarantees
// for free.
func Pool(p *pgxpool.Pool) pgrlstest.Driver {
	return &poolDriver{pool: p}
}

// connDriver is the *pgx.Conn-backed Driver. No Close method
// — the caller owns the connection.
type connDriver struct {
	conn *pgxlib.Conn
}

func (d *connDriver) Query(ctx context.Context, sql string, params ...any) (pgrlstest.QueryResult, error) {
	return queryWith(ctx, d.conn, sql, params...)
}

func (d *connDriver) Rollback(ctx context.Context) error {
	return rollbackWith(ctx, d.conn)
}

func (d *connDriver) IsInsufficientPrivilege(err error) bool {
	return isInsufficientPrivilege(err)
}

// poolDriver is the *pgxpool.Pool-backed Driver. Implements
// Closer for pinned-connection release.
type poolDriver struct {
	pool *pgxpool.Pool

	mu sync.Mutex
	// acquired is set on the first Query / Rollback and reused
	// for every subsequent call until Close clears it.
	acquired *pgxpool.Conn
}

// Query holds the mutex for the entire query lifetime — both
// the lazy acquire (if needed) AND the actual driver call.
// Without this, a concurrent `Close` could `Release()` the
// pinned `*pgxpool.Conn` while `queryWith` is mid-flight,
// causing a use-after-release panic or pool corruption.
//
// The test-client use case naturally has serial driver calls
// (one logical test thread at a time issuing BEGIN → queries
// → ROLLBACK), so the mutex's serialization of parallel Query
// calls is a non-cost. A hypothetical user that issues
// `Promise.all([driver.Query(...), driver.Query(...)])`-style
// concurrent calls (NOT supported by the test client) would
// get serial execution rather than concurrent — acceptable.
func (d *poolDriver) Query(ctx context.Context, sql string, params ...any) (pgrlstest.QueryResult, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	conn, err := d.acquireLocked(ctx)
	if err != nil {
		return pgrlstest.QueryResult{}, err
	}
	return queryWith(ctx, conn, sql, params...)
}

// Rollback holds the mutex like Query — same race-safety
// reasoning. ROLLBACK against an already-released pool
// connection would corrupt the pool's internal state.
func (d *poolDriver) Rollback(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	conn, err := d.acquireLocked(ctx)
	if err != nil {
		return err
	}
	return rollbackWith(ctx, conn)
}

func (d *poolDriver) IsInsufficientPrivilege(err error) bool {
	return isInsufficientPrivilege(err)
}

// Close releases the pinned pool connection. Idempotent — a
// second call is a no-op. After Close, the next Query /
// Rollback re-acquires a fresh connection from the pool.
//
// Holds the mutex for the duration so a concurrent Query /
// Rollback either runs to completion before Close fires or
// gets a freshly-acquired conn after Close returns. The
// pre-iter-1 version dropped the mutex between acquire and
// queryWith, leaving a use-after-release window between
// Query observing the pinned conn and Close releasing it.
//
// `ctx` is intentionally unused: `pgxpool.Conn.Release()` is
// non-blocking and has no signature for cancellation. Kept in
// the method signature to satisfy `pgrlstest.Closer` and so a
// future adapter (e.g. a Bun.sql binding) can honor the
// context without changing the interface. Callers that need
// cancellable teardown should set a deadline on `ctx` and
// rely on subsequent `Query` / `Rollback` calls (which DO
// honor ctx) to surface it.
func (d *poolDriver) Close(ctx context.Context) error {
	_ = ctx
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.acquired != nil {
		d.acquired.Release()
		d.acquired = nil
	}
	return nil
}

// acquireLocked returns the pinned connection, lazily
// acquiring it if needed. MUST be called with `d.mu` held.
// Renamed from `pinnedConn` post-iter-1 to make the locking
// requirement explicit at the call site.
func (d *poolDriver) acquireLocked(ctx context.Context) (*pgxpool.Conn, error) {
	if d.acquired != nil {
		return d.acquired, nil
	}
	conn, err := d.pool.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("pgrlstest/pgx: acquire from pool: %w", err)
	}
	d.acquired = conn
	return conn, nil
}

// queryWith runs a parameterized query against a pgx-compatible
// connection and returns the normalized QueryResult.
//
// The SELECT path uses `pgx.Rows` iteration and builds a
// map per row keyed by column name. The non-SELECT path
// (UPDATE / DELETE / INSERT without RETURNING, BEGIN /
// COMMIT / ROLLBACK / SAVEPOINT / RELEASE) uses `Exec` and
// extracts the command tag + row count without iterating
// rows.
//
// `pgx.Rows.Values()` returns `[]any` aligned with the field
// descriptions; we zip the two into a map. `pgx.Conn` already
// decodes Postgres values into Go-idiomatic types (`int4` →
// `int32`, `text` → `string`, etc.); the test client passes
// these through to user code as `any`.
//
// Command tag parsing: pgx's `CommandTag.String()` returns
// e.g. "SELECT 5", "UPDATE 0", "INSERT 0 1". We strip
// everything after the first space to get the verb, then
// uppercase it — matches the assertion-helper expectation
// from `QueryResult.Command`.
func queryWith(ctx context.Context, q connQueryer, sql string, params ...any) (pgrlstest.QueryResult, error) {
	// The lower-cased first token decides Query vs Exec. SELECT
	// and WITH (CTE) plus the savepoint/transaction verbs that
	// don't return rows — we use Query for the row-returning
	// case and Exec for the rest. WITH may or may not return
	// rows depending on the underlying CTE shape; route it
	// through Query to be safe.
	first := firstWord(sql)
	switch first {
	case "SELECT", "WITH", "VALUES", "SHOW", "EXPLAIN", "TABLE":
		return queryReturningRows(ctx, q, sql, params...)
	default:
		// UPDATE/DELETE/INSERT … RETURNING also returns rows,
		// so we still go through Query for them. The keyword
		// check is `RETURNING` (case-insensitive) anywhere in
		// the SQL; cheaper than a full SQL parse.
		if hasReturning(sql) {
			return queryReturningRows(ctx, q, sql, params...)
		}
		return execWithoutRows(ctx, q, sql, params...)
	}
}

func queryReturningRows(ctx context.Context, q connQueryer, sql string, params ...any) (pgrlstest.QueryResult, error) {
	rows, err := q.Query(ctx, sql, params...)
	if err != nil {
		return pgrlstest.QueryResult{}, err
	}
	defer rows.Close()

	cols := rows.FieldDescriptions()
	out := make([]map[string]any, 0)
	for rows.Next() {
		vals, err := rows.Values()
		if err != nil {
			return pgrlstest.QueryResult{}, err
		}
		row := make(map[string]any, len(cols))
		for i, col := range cols {
			if i < len(vals) {
				row[string(col.Name)] = vals[i]
			}
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return pgrlstest.QueryResult{}, err
	}
	// Read RowCount from the command tag, not from
	// `len(out)`. The two agree for plain SELECT, but they
	// DIVERGE for RETURNING DML when the SQL contains the
	// literal string `'RETURNING'` (or a false positive from
	// `hasReturning`) — the routing puts the SQL on this
	// path, but Postgres reports the actual affected-row
	// count via `CommandTag.RowsAffected()`, not via the
	// number of rows it streamed back. AssertSilentlyDropped
	// (planned step 5) gates on `Command == "UPDATE" &&
	// RowCount == 0`, so a stale `len(out)` would forge a
	// false-silent-drop reading.
	tag := rows.CommandTag()
	return pgrlstest.QueryResult{
		Rows:     out,
		Command:  firstWord(tag.String()),
		RowCount: tag.RowsAffected(),
	}, nil
}

func execWithoutRows(ctx context.Context, q connQueryer, sql string, params ...any) (pgrlstest.QueryResult, error) {
	tag, err := q.Exec(ctx, sql, params...)
	if err != nil {
		return pgrlstest.QueryResult{}, err
	}
	return pgrlstest.QueryResult{
		Rows:     nil,
		Command:  firstWord(tag.String()),
		RowCount: tag.RowsAffected(),
	}, nil
}

// rollbackWith issues `ROLLBACK` against the connection.
//
// Safe to call even when the transaction is in aborted state —
// Postgres accepts ROLLBACK in any transaction state including
// "current transaction is aborted, commands ignored until end
// of transaction block." `Exec` is the right primitive here
// because ROLLBACK doesn't return rows.
func rollbackWith(ctx context.Context, q connQueryer) error {
	_, err := q.Exec(ctx, "ROLLBACK")
	return err
}

// isInsufficientPrivilege returns true iff err wraps a pgx
// `*pgconn.PgError` with SQLSTATE 42501 (insufficient_privilege).
//
// Uses `errors.As` to walk the error chain — pgx may wrap the
// PgError in its own error type for context, and we want to
// classify regardless of wrapping depth. nil → false (no error
// to classify; idiomatic Go).
func isInsufficientPrivilege(err error) bool {
	if err == nil {
		return false
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return false
	}
	return pgErr.Code == pgerrcode.InsufficientPrivilege
}

// firstWord returns the first whitespace-delimited token of s,
// upper-cased. Used both for routing SQL by leading verb
// (SELECT vs UPDATE) and for normalizing the command tag
// returned to QueryResult.Command. Empty input → empty output.
// stripLeadingNoise removes leading whitespace, SQL line (`-- …`) and
// block (`/* … */`) comments, and wrapping `(` so the first keyword of
// e.g. `(SELECT …) UNION …`, `/* c */ SELECT …`, or `-- c\nSELECT …`
// is recognised for Query-vs-Exec routing. Repeats until a real token
// leads.
func stripLeadingNoise(s string) string {
	for {
		t := strings.TrimSpace(s)
		switch {
		case strings.HasPrefix(t, "--"):
			i := strings.IndexAny(t, "\r\n")
			if i < 0 {
				return ""
			}
			s = t[i:]
		case strings.HasPrefix(t, "/*"):
			i := strings.Index(t, "*/")
			if i < 0 {
				return ""
			}
			s = t[i+2:]
		case strings.HasPrefix(t, "("):
			s = t[1:]
		default:
			return t
		}
	}
}

func firstWord(s string) string {
	s = stripLeadingNoise(s)
	if s == "" {
		return ""
	}
	if i := strings.IndexAny(s, " \t\n\r"); i >= 0 {
		return strings.ToUpper(s[:i])
	}
	return strings.ToUpper(s)
}

// hasReturning checks the SQL for a top-level `RETURNING`
// keyword. Case-insensitive; whole-word match via an
// identifier-character boundary check (preceded and followed
// by a non-identifier char, treating `[A-Za-z0-9_]` as
// identifier chars per Postgres / SQL convention).
// Not a full SQL parse — a `RETURNING` inside a string literal
// would still match, but Postgres doesn't allow RETURNING
// inside the kinds of statements that confuse this check
// (UPDATE / DELETE / INSERT only).
//
// The contract is conservative: a false positive routes the
// SQL through the rows-iteration path, which works for both
// returning and non-returning DML (just allocates an empty
// rows slice for non-returning). A false negative would route
// a RETURNING statement through Exec, losing the rows.
//
// Crucially, the boundary check uses `isIdentChar`, not just
// `isLetter` — `returning_col` is a single SQL identifier
// (underscore is part of the identifier per Postgres) and
// must NOT match. A previous version using letters-only
// boundary incorrectly treated `_` as a word break.
func hasReturning(sql string) bool {
	upper := strings.ToUpper(sql)
	idx := strings.Index(upper, "RETURNING")
	for idx >= 0 {
		// Word-boundary check: previous char must be non-
		// identifier (or BOS), next char must be non-identifier
		// (or EOS).
		prevOK := idx == 0 || !isIdentChar(upper[idx-1])
		end := idx + len("RETURNING")
		nextOK := end >= len(upper) || !isIdentChar(upper[end])
		if prevOK && nextOK {
			return true
		}
		next := strings.Index(upper[idx+1:], "RETURNING")
		if next < 0 {
			return false
		}
		idx = idx + 1 + next
	}
	return false
}

// isIdentChar returns true for ASCII identifier characters:
// letters, digits, and underscore. Mirrors Postgres's
// unquoted-identifier syntax (it also allows `$` after the
// first char but that's rare in user code; conservative
// false negatives are fine here — they route a SQL through
// the rows-returning path which works for either branch).
func isIdentChar(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') ||
		(b >= '0' && b <= '9') || b == '_'
}
