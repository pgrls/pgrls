// Package pq is the [lib/pq] + database/sql adapter for the
// pgrls test client.
//
// Two constructors:
//
//   - Conn(c) wraps a single `*sql.Conn` directly. The caller
//     owns the connection lifecycle; the adapter does NOT
//     implement `pgrlstest.Closer`. Use this when you already
//     have a `*sql.Conn` (e.g. from `db.Conn(ctx)` in test
//     setup) and want to manage release yourself.
//
//   - DB(d) wraps a `*sql.DB`. The adapter lazily acquires
//     one `*sql.Conn` from the DB on the first `Query` /
//     `Rollback` call and uses that pinned connection for
//     every subsequent call. Implements `pgrlstest.Closer` —
//     `Close(ctx)` releases the pinned connection back to the
//     pool. Idempotent. Mirrors the pgx adapter's `Pool`
//     pattern.
//
// Why both: most application code holds a `*sql.DB`; some
// integration test setups hold a pinned `*sql.Conn`. Both are
// first-class.
//
// SQLSTATE 42501 classification routes through `*pq.Error.Code`.
// lib/pq's `pq.ErrorCode` is a string-typed alias; we compare
// against the literal `"42501"` (database/sql doesn't expose a
// centralized SQLSTATE constants package the way pgx does via
// pgerrcode).
//
// [lib/pq]: https://github.com/lib/pq
package pq

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"

	pqlib "github.com/lib/pq"

	"github.com/pgrls/pgrls/go/pgrlstest"
)

// connQueryer is the subset of database/sql `*sql.Conn` the
// adapter uses. Defined as an interface so the two
// constructors (Conn / DB) can share the row-iteration logic.
// `*sql.Conn` and the equivalent `*sql.DB` (when used as a
// pseudo-pinned-shape) both satisfy this structurally.
type connQueryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// Conn wraps a `*sql.Conn` into a pgrlstest.Driver.
//
// The caller owns the connection lifecycle. The returned
// driver does NOT implement `pgrlstest.Closer`; release via
// `c.Close()` directly (database/sql convention: `*sql.Conn`
// returns its connection to the pool on Close).
func Conn(c *sql.Conn) pgrlstest.Driver {
	return &connDriver{conn: c}
}

// DB wraps a `*sql.DB` into a pgrlstest.Driver that implements
// pgrlstest.Closer.
//
// On the first `Query` / `Rollback` call the adapter lazily
// invokes `db.Conn(ctx)` to acquire a pinned connection and
// uses that for every subsequent call. Without pinning, the
// database/sql pool rotates connections across calls and the
// transaction state (BEGIN, SET LOCAL ROLE, savepoints)
// breaks.
//
// `Close(ctx)` returns the pinned connection to the pool via
// `*sql.Conn.Close()`. Idempotent — subsequent `Query` calls
// re-acquire a fresh `*sql.Conn` from the DB.
func DB(d *sql.DB) pgrlstest.Driver {
	return &dbDriver{db: d}
}

// connDriver is the *sql.Conn-backed Driver. No Close method
// — caller owns the conn.
type connDriver struct {
	conn *sql.Conn
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

// dbDriver is the *sql.DB-backed Driver. Implements Closer
// for pinned-connection release.
type dbDriver struct {
	db *sql.DB

	mu sync.Mutex
	// acquired is set on the first Query / Rollback. database/
	// sql's `*sql.Conn` is the pinned-connection type;
	// `Close()` returns it to the pool.
	acquired *sql.Conn
}

// Query holds the mutex for the entire query lifetime — the
// lazy `db.Conn(ctx)` acquire AND the driver call. Without
// this, a concurrent `Close` could close the pinned
// `*sql.Conn` while `queryWith` is mid-flight, causing a
// use-after-close panic or pool corruption.
//
// The test-client use case naturally has serial driver calls
// (one logical test thread at a time issuing BEGIN → queries
// → ROLLBACK), so the mutex's serialization of parallel Query
// calls is a non-cost.
func (d *dbDriver) Query(ctx context.Context, sql string, params ...any) (pgrlstest.QueryResult, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	conn, err := d.acquireLocked(ctx)
	if err != nil {
		return pgrlstest.QueryResult{}, err
	}
	return queryWith(ctx, conn, sql, params...)
}

// Rollback holds the mutex like Query — same race-safety
// reasoning. ROLLBACK against an already-closed *sql.Conn
// would surface a confusing "sql: connection is already
// closed" rather than the operator's actual error.
func (d *dbDriver) Rollback(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	conn, err := d.acquireLocked(ctx)
	if err != nil {
		return err
	}
	return rollbackWith(ctx, conn)
}

func (d *dbDriver) IsInsufficientPrivilege(err error) bool {
	return isInsufficientPrivilege(err)
}

// Close releases the pinned *sql.Conn back to the pool.
// Idempotent — a second call is a no-op. After Close, the
// next Query / Rollback re-acquires.
//
// `ctx` is intentionally unused: `*sql.Conn.Close()` has no
// ctx-aware variant in the stdlib. Kept in the signature to
// satisfy `pgrlstest.Closer`. Callers that need cancellable
// teardown rely on subsequent `Query` / `Rollback` (which DO
// honor ctx) to surface deadline issues.
func (d *dbDriver) Close(ctx context.Context) error {
	_ = ctx
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.acquired != nil {
		err := d.acquired.Close()
		d.acquired = nil
		return err
	}
	return nil
}

// acquireLocked returns the pinned *sql.Conn, lazily
// acquiring via db.Conn(ctx) if needed. MUST be called with
// `d.mu` held.
func (d *dbDriver) acquireLocked(ctx context.Context) (*sql.Conn, error) {
	if d.acquired != nil {
		return d.acquired, nil
	}
	conn, err := d.db.Conn(ctx)
	if err != nil {
		return nil, fmt.Errorf("pgrlstest/pq: acquire from DB: %w", err)
	}
	d.acquired = conn
	return conn, nil
}

// queryWith runs a parameterized query against a database/sql
// connection and returns the normalized QueryResult.
//
// Routing matches the pgx adapter: SELECT / WITH / VALUES /
// SHOW / EXPLAIN + anything containing RETURNING goes through
// QueryContext + row iteration; everything else (UPDATE /
// DELETE / INSERT without RETURNING + BEGIN / COMMIT /
// ROLLBACK / SAVEPOINT / RELEASE) goes through ExecContext.
//
// database/sql doesn't expose the command-tag verb directly —
// `sql.Result` returns LastInsertId (PG doesn't support it)
// and RowsAffected. We derive Command from the SQL's first
// word for the Exec path, and for the Query path we use the
// same — there's no command-tag reading API in database/sql.
func queryWith(ctx context.Context, q connQueryer, sqlText string, params ...any) (pgrlstest.QueryResult, error) {
	first := firstWord(sqlText)
	if first == "SELECT" || first == "WITH" || first == "VALUES" || first == "SHOW" || first == "EXPLAIN" || hasReturning(sqlText) {
		return queryReturningRows(ctx, q, sqlText, params...)
	}
	return execWithoutRows(ctx, q, sqlText, params...)
}

func queryReturningRows(ctx context.Context, q connQueryer, sqlText string, params ...any) (pgrlstest.QueryResult, error) {
	rows, err := q.QueryContext(ctx, sqlText, params...)
	if err != nil {
		return pgrlstest.QueryResult{}, err
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		return pgrlstest.QueryResult{}, err
	}
	out := make([]map[string]any, 0)
	for rows.Next() {
		// database/sql wants a []any of *any pointers to scan
		// into; we build that, scan, then unwrap into the row
		// map.
		ptrs := make([]any, len(cols))
		dest := make([]any, len(cols))
		for i := range cols {
			ptrs[i] = &dest[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return pgrlstest.QueryResult{}, err
		}
		row := make(map[string]any, len(cols))
		for i, col := range cols {
			row[col] = dest[i]
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return pgrlstest.QueryResult{}, err
	}
	// database/sql doesn't expose the Postgres command tag for
	// the SELECT/RETURNING path. Derive Command from the SQL's
	// first verb — same convention as the assertion helpers
	// expect (always upper-case). For RETURNING DML we report
	// the DML verb (UPDATE / DELETE / INSERT), not "SELECT".
	return pgrlstest.QueryResult{
		Rows:     out,
		Command:  firstWord(sqlText),
		RowCount: int64(len(out)),
	}, nil
}

func execWithoutRows(ctx context.Context, q connQueryer, sqlText string, params ...any) (pgrlstest.QueryResult, error) {
	res, err := q.ExecContext(ctx, sqlText, params...)
	if err != nil {
		return pgrlstest.QueryResult{}, err
	}
	// sql.Result.RowsAffected returns (int64, error). The
	// error is the underlying driver's "this kind of statement
	// doesn't have a row count" — for transaction control
	// statements (BEGIN, ROLLBACK, etc.) it's expected to be
	// nil with 0 rows. Treat any error as "no row count
	// available" → 0 (matches what pgx returns for the same
	// statements via CommandTag).
	count, _ := res.RowsAffected()
	return pgrlstest.QueryResult{
		Rows:     nil,
		Command:  firstWord(sqlText),
		RowCount: count,
	}, nil
}

func rollbackWith(ctx context.Context, q connQueryer) error {
	_, err := q.ExecContext(ctx, "ROLLBACK")
	return err
}

// isInsufficientPrivilege returns true iff err wraps a lib/pq
// `*pq.Error` with SQLSTATE 42501 (insufficient_privilege).
//
// lib/pq's `pq.ErrorCode` is a `type ErrorCode string` —
// compared via string equality against the literal "42501".
// database/sql doesn't ship a centralized SQLSTATE constants
// package the way pgx does via pgerrcode; we use the literal
// directly with a comment naming the symbol.
func isInsufficientPrivilege(err error) bool {
	if err == nil {
		return false
	}
	var pqErr *pqlib.Error
	if !errors.As(err, &pqErr) {
		return false
	}
	// "42501" = insufficient_privilege per Postgres' SQLSTATE
	// catalog. https://www.postgresql.org/docs/current/errcodes-appendix.html
	return string(pqErr.Code) == "42501"
}

func firstWord(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if i := strings.IndexAny(s, " \t\n\r"); i >= 0 {
		return strings.ToUpper(s[:i])
	}
	return strings.ToUpper(s)
}

func hasReturning(sqlText string) bool {
	upper := strings.ToUpper(sqlText)
	idx := strings.Index(upper, "RETURNING")
	for idx >= 0 {
		// Word-boundary check: previous + next chars must be
		// non-identifier (treating `[A-Za-z0-9_]` as ident
		// chars per Postgres convention). Underscore matters:
		// `returning_col` is a single identifier and must NOT
		// match RETURNING.
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
// unquoted-identifier syntax.
func isIdentChar(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') ||
		(b >= '0' && b <= '9') || b == '_'
}
