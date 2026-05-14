package pgrlstest

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Client is the Go port of `pgrls.testing.PgrlsTestClient` (Python)
// and `PgrlsTestClient` (TypeScript). It implements the Layer 1
// wire protocol over a `Driver` — same SAVEPOINT name format,
// same `SET LOCAL ROLE` / `set_config` sequence, same restoration
// logic on clean exit, same `ROLLBACK TO SAVEPOINT` on exception.
// Documented at the cross-language wire-contract spec
// (`docs/pgrls-test-protocol.md`).
//
// Construct with a driver from `drivers/pgx` or `drivers/pq`. Both
// adapters accept either a single connection (which the caller
// owns) or a pool (in which case the adapter pins one connection
// for the client's lifetime and releases it via `Close`).
//
// Example with pgx (the pool variant releases the pinned conn on
// Client.Close; for a caller-owned single conn use `pgxdriver.Conn`
// instead):
//
//	import (
//	    "context"
//	    "github.com/jackc/pgx/v5/pgxpool"
//	    "github.com/pgrls/pgrls/go/pgrlstest"
//	    pgxdriver "github.com/pgrls/pgrls/go/pgrlstest/drivers/pgx"
//	)
//
//	pool, _ := pgxpool.New(ctx, dsn)
//	defer pool.Close()
//	client := pgrlstest.NewClient(pgxdriver.Pool(pool))
//	defer client.Close(ctx)
//
//	err := client.Transaction(ctx, func(ctx context.Context) error {
//	    if err := client.Seed(ctx, "app.invoices", []map[string]any{
//	        {"tenant_id": "t1", "amount": 100},
//	    }); err != nil { return err }
//	    return client.AsRole(ctx, "app_authenticated", &pgrlstest.AsRoleOptions{
//	        Claims: map[string]any{"sub": "user-a", "tenant_id": "t1"},
//	    }, func(ctx context.Context) error {
//	        rows, err := client.FetchAll(ctx, "SELECT id FROM app.invoices")
//	        _ = rows
//	        return err
//	    })
//	})
//
// Cross-language guarantee: byte-equivalent Layer 1 wire sequence
// to the Python and TypeScript ports. The conformance suite (step
// 6 / v0.7.5) pins this against a shared fixture.
type Client struct {
	// driver is the underlying connection adapter. Used by the
	// package-internal assertion helpers in `assertions.go`
	// (added in v0.7.4) and read by external callers via the
	// `Driver()` accessor.
	driver Driver
}

// NewClient builds a new test client over the given driver.
//
// The driver is supplied externally so callers keep their
// connection-management patterns intact — pools, hooks,
// instrumentation, observability wrappers all flow through.
func NewClient(driver Driver) *Client {
	return &Client{driver: driver}
}

// Driver returns the underlying driver. Exposed for the assertion
// helpers (added in v0.7.4) to issue their own `SAVEPOINT` /
// `ROLLBACK TO SAVEPOINT` wire sequence inside `AssertRejected`.
// Not part of the stable public API — subject to change between
// minor versions.
func (c *Client) Driver() Driver { return c.driver }

// Transaction runs `body` inside a transaction and ROLLBACKs on
// exit (always — clean or error).
//
// Per-test isolation: the body seeds data, switches roles,
// asserts; the trailing `ROLLBACK` ensures nothing persists.
// Errors from the body propagate; a rollback error is returned
// only if the body itself succeeded (so a rollback failure
// doesn't shadow the real error).
//
// Issues an explicit `BEGIN` at entry and `ROLLBACK` at exit —
// works regardless of the driver's autocommit setting (matters
// for `database/sql` users who haven't pinned a `*sql.Conn`).
func (c *Client) Transaction(ctx context.Context, body func(ctx context.Context) error) (err error) {
	if _, beginErr := c.driver.Query(ctx, "BEGIN"); beginErr != nil {
		return beginErr
	}
	defer func() {
		rbErr := c.driver.Rollback(ctx)
		// Rollback's error is returned ONLY if body succeeded.
		// If body failed, the body's error is the meaningful
		// one — surfacing a rollback error from a doomed
		// transaction would shadow it.
		if err == nil && rbErr != nil {
			err = rbErr
		}
	}()
	err = body(ctx)
	return err
}

// Exec runs a single SQL statement and discards rows.
//
// For SELECT or RETURNING-bearing DML where rows matter, use
// `FetchAll` instead. Mirrors Python's `client.exec(sql,
// params=...)` and the TypeScript `client.exec(sql, params)`.
func (c *Client) Exec(ctx context.Context, sqlText string, params ...any) error {
	_, err := c.driver.Query(ctx, sqlText, params...)
	return err
}

// FetchAll runs a query and returns rows as plain string-keyed
// maps.
//
// Cross-language analogue: the TypeScript port returns
// `Promise<TRow[]>` with a generic type parameter for ergonomics
// (an unchecked cast). Go's type system doesn't permit a free
// generic over `map[string]any` without forcing a conversion
// step, so this returns the raw shape and lets callers
// type-assert per column. For the typed-row use case, callers can
// wrap with their own helper using `mapstructure` or the
// driver's native row-scanning APIs.
func (c *Client) FetchAll(ctx context.Context, sqlText string, params ...any) ([]map[string]any, error) {
	res, err := c.driver.Query(ctx, sqlText, params...)
	if err != nil {
		return nil, err
	}
	return res.Rows, nil
}

// AsRoleOptions holds the per-scenario actor configuration.
//
// `Claims` carries the JWT claims to set in the
// `request.jwt.claims` GUC for the duration of the block. The
// protocol distinguishes three cases:
//
//   - `Claims = nil` (or `&AsRoleOptions{}` with no Claims field):
//     don't touch the GUC. The role switches but claims-derived
//     RLS predicates evaluate against whatever the outer
//     transaction had (or no value, if untouched).
//
//   - `Claims = map[string]any{}` (empty non-nil map): set the
//     GUC to the JSON string `"{}"` — an "actor with no claims"
//     request. RLS predicates that try to read a claim get NULL,
//     which is distinct from no-GUC-set behavior.
//
//   - `Claims = map[string]any{"sub": "user-a", ...}`: set the
//     GUC to the JSON-encoded map.
//
// Cross-language guarantee: same three cases as Python's
// `claims=None` / `claims={}` / `claims={"sub": ...}` and
// TypeScript's `claims: null` / `claims: {}` / `claims: {...}`.
type AsRoleOptions struct {
	// Claims is the JWT claims to install via set_config.
	//
	// nil means "skip set_config entirely". An empty non-nil
	// map (`map[string]any{}`) means "set claims to JSON `{}`"
	// — distinct from nil. See the AsRoleOptions docs for the
	// rationale.
	Claims map[string]any
}

// AsRole switches role + claims for the duration of `body`.
//
// Layer 1 wire sequence (cross-language equivalent):
//
//  1. Capture current role + claims via
//     `SELECT current_user, current_setting('request.jwt.claims', true)`.
//  2. SAVEPOINT `pgrls_actor_<8-hex>` (random suffix from
//     crypto/rand).
//  3. SET LOCAL ROLE <quoted role>.
//  4. If `Claims` is non-nil:
//     SELECT set_config('request.jwt.claims', $1, true) with the
//     JSON-encoded claims.
//  5. Run body.
//  6a. Clean exit: RELEASE SAVEPOINT, then explicitly restore
//     prior role + claims. RELEASE keeps SET LOCAL changes merged
//     into the outer transaction; without explicit restoration,
//     nested AsRole blocks would lose the outer role on return.
//  6b. Exception path: ROLLBACK TO SAVEPOINT, which auto-restores
//     SET LOCAL state (role and GUC both revert).
//
// The role identifier is quoted via QuoteIdent — reserved
// keywords (`"order"`, `"user"`) and mixed-case / special-char
// names are handled correctly.
func (c *Client) AsRole(
	ctx context.Context,
	role string,
	options *AsRoleOptions,
	body func(ctx context.Context) error,
) (err error) {
	var claims map[string]any
	if options != nil {
		claims = options.Claims
	}

	// Quote the requested role BEFORE issuing any SQL. If the
	// role name is malformed (empty / control chars), fail
	// without leaving state — no savepoint, no capture, just a
	// clean error.
	quotedRole, err := QuoteIdent(role)
	if err != nil {
		return &Error{
			Msg:   fmt.Sprintf("AsRole: invalid role name %q", role),
			Cause: err,
		}
	}

	savepoint, err := NewSavepointName("pgrls_actor")
	if err != nil {
		return err
	}

	// 1. Capture state BEFORE the savepoint so we can restore
	// it on clean exit. RELEASE SAVEPOINT keeps SET LOCAL
	// changes merged into the outer transaction; without
	// explicit restoration, nested AsRole blocks would lose
	// the outer role.
	captured, err := c.driver.Query(
		ctx,
		"SELECT current_user, current_setting('request.jwt.claims', true) AS claims",
	)
	if err != nil {
		return err
	}
	if len(captured.Rows) == 0 {
		// Defensive: SELECT current_user always returns one
		// row, but a custom driver could violate that
		// contract.
		return &Error{
			Msg: "AsRole: failed to capture current role/claims " +
				"(SELECT current_user returned no row — driver in unexpected state)",
		}
	}
	captureRow := captured.Rows[0]
	prevUser, ok := captureRow["current_user"].(string)
	if !ok {
		return &Error{
			Msg: fmt.Sprintf(
				"AsRole: SELECT current_user returned non-string %T for current_user",
				captureRow["current_user"],
			),
		}
	}
	// `current_setting(..., true)` returns NULL when the GUC is
	// unset; both pgx and lib/pq surface that as a nil
	// interface{} in the row map. A non-nil non-empty string
	// means the outer transaction had claims to restore.
	var prevClaims string
	if rawClaims, present := captureRow["claims"]; present && rawClaims != nil {
		if s, isString := rawClaims.(string); isString && s != "" {
			prevClaims = s
		}
	}

	// Quote the previous role NOW (before issuing the
	// savepoint) so a malformed `current_user` value — which
	// shouldn't happen against a real Postgres, but could from
	// a hand-rolled fake driver — fails before we open a
	// savepoint we'd then have to roll back.
	quotedPrevRole, err := QuoteIdent(prevUser)
	if err != nil {
		return &Error{
			Msg:   fmt.Sprintf("AsRole: cannot restore previous role %q", prevUser),
			Cause: err,
		}
	}

	// 2. SAVEPOINT. Name is locally generated random hex — safe
	// to interpolate without quoting.
	if _, err = c.driver.Query(ctx, "SAVEPOINT "+savepoint); err != nil {
		return err
	}

	bodyOK := false
	defer func() {
		if bodyOK {
			// 6a. Clean exit. RELEASE SAVEPOINT, then
			// explicitly restore prior role + claims. RELEASE
			// keeps SET LOCAL changes merged into the outer
			// transaction; without restoration, nested AsRole
			// blocks would see the inner role on return.
			if _, releaseErr := c.driver.Query(ctx, "RELEASE SAVEPOINT "+savepoint); releaseErr != nil {
				err = releaseErr
				return
			}
			if _, restoreErr := c.driver.Query(ctx, "SET LOCAL ROLE "+quotedPrevRole); restoreErr != nil {
				err = restoreErr
				return
			}
			if prevClaims != "" {
				// Outer had claims; restore them whether or
				// not inner changed them (a no-op set is
				// cheap).
				if _, claimsErr := c.driver.Query(
					ctx,
					"SELECT set_config('request.jwt.claims', $1, true)",
					prevClaims,
				); claimsErr != nil {
					err = claimsErr
					return
				}
			} else if claims != nil {
				// Outer had no claims; inner set some. Clear
				// the GUC via `set_config(name, NULL, true)`.
				// Postgres collapses NULL to '' on custom
				// GUCs once they've been touched in the
				// session — so
				// `current_setting('request.jwt.claims',
				// true)` returns `''` rather than NULL — but
				// the inner-block JSON is gone, so a
				// downstream policy doing
				// `current_setting(...)::jsonb` raises
				// `invalid input syntax for type json`
				// instead of silently authorizing as the
				// inner-block actor.
				if _, clearErr := c.driver.Query(
					ctx,
					"SELECT set_config('request.jwt.claims', NULL, true)",
				); clearErr != nil {
					err = clearErr
					return
				}
			}
			// else: outer had no claims and inner didn't set
			// any — the GUC was never touched, no restore
			// needed.
		} else {
			// 6b. Exception path. ROLLBACK TO SAVEPOINT
			// restores SET LOCAL state from before the
			// savepoint — role and GUC both revert
			// automatically. If the rollback itself fails the
			// body's error is the meaningful one; the rollback
			// error is surfaced only if no body error already
			// set `err`. (The `err == nil` branch is reachable
			// in principle if `body` panics: bodyOK is still
			// false, err is still nil. The named-return update
			// is ineffective in that case — the panic
			// propagates past this defer without converting to
			// an error — but the rollback itself still runs and
			// reverts state.)
			if _, rbErr := c.driver.Query(ctx, "ROLLBACK TO SAVEPOINT "+savepoint); rbErr != nil {
				if err == nil {
					err = rbErr
				}
			}
		}
	}()

	// 3. Switch role.
	if _, err = c.driver.Query(ctx, "SET LOCAL ROLE "+quotedRole); err != nil {
		return err
	}

	// 4. Set claims if provided. nil skips the call. Empty map
	// is a deliberate "actor with no claims" request and IS
	// sent (as JSON `"{}"`).
	if claims != nil {
		claimsJSON, marshalErr := json.Marshal(claims)
		if marshalErr != nil {
			return &Error{
				Msg:   "AsRole: failed to JSON-encode claims",
				Cause: marshalErr,
			}
		}
		if _, err = c.driver.Query(
			ctx,
			"SELECT set_config('request.jwt.claims', $1, true)",
			string(claimsJSON),
		); err != nil {
			return err
		}
	}

	// 5. Run body.
	if err = body(ctx); err != nil {
		return err
	}
	bodyOK = true
	return nil
}

// Seed bulk-inserts `rows` into `table` in the current (admin)
// context.
//
// All rows must have the same keys (column set). Empty list is a
// no-op. Identifiers are double-quoted via QuoteIdent /
// QuoteQualified so reserved keywords and mixed-case names are
// handled correctly.
//
// Schema-qualified table names work: pass `"app.invoices"` and
// the helper splits on the rightmost dot, quoting each segment
// independently. Names with more than one dot are rejected —
// cross-database refs aren't supported.
//
// Mirrors the Python `client.seed(table, rows)` and TypeScript
// `client.seed(table, rows)`. For richer factory needs
// (sequencing, faker integration, post-insert hooks), use a
// dedicated factory framework — pgrls-test's seeder is
// intentionally tiny.
func (c *Client) Seed(ctx context.Context, table string, rows []map[string]any) error {
	if len(rows) == 0 {
		return nil
	}

	keys := make([]string, 0, len(rows[0]))
	for k := range rows[0] {
		keys = append(keys, k)
	}
	// Sort keys for a deterministic column order in emitted
	// SQL. Map iteration order in Go is randomized; without
	// sorting, two runs of the same test would emit different
	// column orderings, making query logs and snapshot diffs
	// noisy. The TypeScript port preserves
	// `Object.keys` insertion order; Python preserves dict
	// insertion order (3.7+). Go has no insertion-order map
	// primitive, so deterministic-sort is the closest analogue.
	sort.Strings(keys)

	keySet := make(map[string]struct{}, len(keys))
	for _, k := range keys {
		keySet[k] = struct{}{}
	}
	for i := 1; i < len(rows); i++ {
		row := rows[i]
		matches := len(row) == len(keys)
		if matches {
			for k := range row {
				if _, ok := keySet[k]; !ok {
					matches = false
					break
				}
			}
		}
		if !matches {
			// Match the Python/TS error shape so cross-language
			// debugging output stays comparable: include both
			// sorted key lists in the message.
			rowKeys := make([]string, 0, len(row))
			for k := range row {
				rowKeys = append(rowKeys, k)
			}
			sort.Strings(rowKeys)
			return &Error{
				Msg: fmt.Sprintf(
					"Seed: rows must all have the same keys; row 0 has %v, row %d has %v",
					keys, i, rowKeys,
				),
			}
		}
	}

	// Right-split on `.` — a single dot means schema.table;
	// absent dot means an unqualified name in the current
	// search_path. Mirror the Python/TS helpers.
	var quotedTable string
	dotCount := strings.Count(table, ".")
	if dotCount > 1 {
		return &Error{
			Msg: fmt.Sprintf(
				"Seed: table name %q contains more than one dot. "+
					"Cross-database table references aren't supported — pass an "+
					"unqualified name (uses search_path) or a qualified 'schema.table'.",
				table,
			),
		}
	}
	if dotCount == 1 {
		lastDot := strings.LastIndex(table, ".")
		schema := table[:lastDot]
		name := table[lastDot+1:]
		q, err := QuoteQualified(schema, name)
		if err != nil {
			return &Error{
				Msg:   fmt.Sprintf("Seed: invalid table name %q", table),
				Cause: err,
			}
		}
		quotedTable = q
	} else {
		q, err := QuoteIdent(table)
		if err != nil {
			return &Error{
				Msg:   fmt.Sprintf("Seed: invalid table name %q", table),
				Cause: err,
			}
		}
		quotedTable = q
	}

	quotedCols := make([]string, len(keys))
	for i, k := range keys {
		q, err := QuoteIdent(k)
		if err != nil {
			return &Error{
				Msg:   fmt.Sprintf("Seed: invalid column name %q", k),
				Cause: err,
			}
		}
		quotedCols[i] = q
	}

	placeholders := make([]string, len(keys))
	for i := range keys {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
	}

	sqlText := fmt.Sprintf(
		"INSERT INTO %s (%s) VALUES (%s)",
		quotedTable,
		strings.Join(quotedCols, ", "),
		strings.Join(placeholders, ", "),
	)

	// Postgres doesn't have a multi-row $-parameterized form
	// that fits both pgx and lib/pq cleanly, so issue one
	// INSERT per row. Same as the Python `executemany` shape
	// and the TS port's `for (const row of rows)` loop. This
	// is a test-time helper; bulk-loading isn't the
	// performance hot path.
	for _, row := range rows {
		values := make([]any, len(keys))
		for i, k := range keys {
			values[i] = row[k]
		}
		if _, err := c.driver.Query(ctx, sqlText, values...); err != nil {
			return err
		}
	}
	return nil
}

// Close releases any driver resources acquired during testing.
//
// Forwards to the driver's optional `Close(ctx)` (the `Closer`
// interface). Adapters that pin a pool connection
// (`drivers/pgx.Pool`, `drivers/pq.DB`) use this to
// release the pinned connection back to the pool — without
// `Close`, the connection stays held until the pool itself
// shuts down, which leaks one connection per Client instance.
//
// Adapters that wrap a caller-owned single connection
// (`drivers/pgx.Conn`, `drivers/pq.Conn`) don't
// implement `Closer`: the caller already owns the connection and
// releases it through their own lifecycle. For those, this
// method is a no-op.
//
// Idempotent: calling Close more than once is safe; subsequent
// calls are no-ops. Adapter-specific behavior: an Exec /
// FetchAll / Transaction / assertion call after Close may
// re-acquire a fresh connection.
//
// Typical usage:
//
//	client := pgrlstest.NewClient(pgxdriver.Pool(pool))
//	defer client.Close(ctx)
func (c *Client) Close(ctx context.Context) error {
	if closer, ok := c.driver.(Closer); ok {
		return closer.Close(ctx)
	}
	return nil
}
