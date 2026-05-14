package pgrlstest

import (
	"context"
	"fmt"
	"regexp"
)

// RLS-specific assertion helpers — the Go port of
// `pgrls.testing.assertions` (Python) and `pgrls-test`'s
// `assertions.ts` (TypeScript).
//
// Each helper takes a `*Client` and a SQL string. `Client`
// exposes them as instance methods (`AssertRows`, etc.) for
// the common case; the package-level functions stay reachable
// for non-`Client` contexts (custom drivers, ad-hoc scripts,
// alternative test runners).
//
// Failure mode: every helper returns `*AssertionError` (which
// matches the `ErrAssertion` sentinel via `errors.Is`) so the
// `go test` runner renders the failure with its standard
// machinery. A helper that detects misuse (wrong-shape SQL
// passed to `AssertSilentlyDropped`) returns `*Error` instead —
// distinct from an RLS-misbehavior assertion failure.

// assertRows is the package-level helper. Callers typically
// reach it via `Client.AssertRows` (defined below).
//
// Returns `*AssertionError` (matches `ErrAssertion`) if the
// query's row count differs from `count`.
func assertRows(ctx context.Context, c *Client, sqlText string, count int) error {
	result, err := c.driver.Query(ctx, sqlText)
	if err != nil {
		return err
	}
	actual := len(result.Rows)
	if actual != count {
		return &AssertionError{
			Msg: fmt.Sprintf(
				"AssertRows: expected %d row(s), got %d for query: %q",
				count, actual, sqlText,
			),
		}
	}
	return nil
}

// assertVisible is the package-level helper. Returns
// `*AssertionError` when the query yields zero rows.
func assertVisible(ctx context.Context, c *Client, sqlText string) error {
	result, err := c.driver.Query(ctx, sqlText)
	if err != nil {
		return err
	}
	if len(result.Rows) == 0 {
		return &AssertionError{
			Msg: fmt.Sprintf(
				"AssertVisible: expected at least 1 row, got 0 for query: %q",
				sqlText,
			),
		}
	}
	return nil
}

// assertInvisible is the package-level helper. Returns
// `*AssertionError` when the query yields any rows.
func assertInvisible(ctx context.Context, c *Client, sqlText string) error {
	result, err := c.driver.Query(ctx, sqlText)
	if err != nil {
		return err
	}
	if len(result.Rows) != 0 {
		return &AssertionError{
			Msg: fmt.Sprintf(
				"AssertInvisible: expected 0 rows, got %d for query: %q",
				len(result.Rows), sqlText,
			),
		}
	}
	return nil
}

// assertRejected is the package-level helper.
//
// Layer 1 wire sequence:
//
//  1. SAVEPOINT pgrls_check_<rand>.
//  2. Run `sqlText`.
//     - If it raises and the driver classifies the error as
//     SQLSTATE 42501 (`Driver.IsInsufficientPrivilege` returns
//     true): ROLLBACK TO SAVEPOINT, return nil.
//     - If it raises with any other error: ROLLBACK TO SAVEPOINT,
//     return `*AssertionError` wrapping the wrong-shape error.
//     - If it succeeds: RELEASE SAVEPOINT, return
//     `*AssertionError` (succeeded but expected rejection). The
//     RELEASE keeps any side-effects within the outer
//     transaction; the outer `Transaction()` will ROLLBACK
//     anyway, but releasing matches Python's exact sequence.
//
// Cross-language guarantee: same savepoint prefix
// (`pgrls_check`), same RELEASE-on-success / ROLLBACK-on-failure
// pattern, same error-message shapes as Python and TypeScript.
func assertRejected(ctx context.Context, c *Client, sqlText string) error {
	savepoint, err := NewSavepointName("pgrls_check")
	if err != nil {
		return err
	}
	if _, err := c.driver.Query(ctx, "SAVEPOINT "+savepoint); err != nil {
		return err
	}

	_, queryErr := c.driver.Query(ctx, sqlText)

	var (
		rejectedAsExpected bool
		unexpectedError    error
	)
	if queryErr != nil {
		if c.driver.IsInsufficientPrivilege(queryErr) {
			rejectedAsExpected = true
		} else {
			unexpectedError = queryErr
		}
	}

	// Always roll back or release the savepoint. On the
	// rejection-as-expected path the transaction is in aborted
	// state and ROLLBACK TO is the only way to recover. On
	// success, RELEASE keeps the side-effect committed within
	// the outer transaction (which Transaction() will ROLLBACK
	// anyway); this matches Python's exact sequence and makes
	// the intent clear.
	if rejectedAsExpected || unexpectedError != nil {
		if _, rbErr := c.driver.Query(ctx, "ROLLBACK TO SAVEPOINT "+savepoint); rbErr != nil {
			return rbErr
		}
	} else {
		if _, relErr := c.driver.Query(ctx, "RELEASE SAVEPOINT "+savepoint); relErr != nil {
			return relErr
		}
	}

	if rejectedAsExpected {
		return nil
	}
	if unexpectedError != nil {
		return &AssertionError{
			Msg: fmt.Sprintf(
				"AssertRejected: expected InsufficientPrivilege (SQLSTATE 42501), got %T: %s",
				unexpectedError, unexpectedError.Error(),
			),
		}
	}
	// queryErr == nil — succeeded.
	return &AssertionError{
		Msg: fmt.Sprintf(
			"AssertRejected: query succeeded but expected RLS rejection: %q",
			sqlText,
		),
	}
}

// returningKeywordRe matches the literal `RETURNING` keyword in
// SQL, case-insensitively, with word boundaries (so column
// names like `returning_col` don't trip it). Used by
// `assertSilentlyDropped` to reject mis-shaped DML upfront.
var returningKeywordRe = regexp.MustCompile(`(?i)\bRETURNING\b`)

// assertSilentlyDropped is the package-level helper.
//
// Asserts that an UPDATE or DELETE with RETURNING succeeds but
// yields zero rows — the Postgres RLS shape where the policy's
// USING expression filters every row out before the write. The
// helper rejects non-UPDATE/DELETE verbs (SELECT, INSERT, etc.)
// and SQL missing RETURNING as misuse — both raise `*Error`
// (matches `ErrAPIError`), distinct from `*AssertionError`.
//
// Note on INSERT: Postgres's INSERT … RETURNING does NOT
// silently drop; a WITH CHECK violation raises 42501. Use
// `AssertRejected` for the INSERT case, `AssertInvisible` for
// the SELECT case.
//
// Side-effect note: like Python, the SQL runs to completion
// before the verb-gate check. A misuse call still executes the
// statement; the verb-gate raises afterwards. Only call with
// the UPDATE/DELETE you actually want to run.
//
// Unlike `AssertRejected`, this helper does NOT wrap the query
// in a savepoint — the contract is "the DML succeeds silently
// with no rows," and a real driver error (typo, bad column ref)
// should surface loudly. If you want savepoint-tolerant
// rejection assertions, use `AssertRejected` for the raise path.
func assertSilentlyDropped(ctx context.Context, c *Client, sqlText string) error {
	result, err := c.driver.Query(ctx, sqlText)
	if err != nil {
		return err
	}

	// Gate on the verb so a SELECT (which produces a result set
	// whether or not it returns rows) can't silently masquerade
	// as the silent-drop shape. `AssertSilentlyDropped("SELECT *
	// FROM t WHERE 1=0")` would otherwise pass with zero rows
	// even though no RLS-aware DML ran.
	if result.Command != "UPDATE" && result.Command != "DELETE" {
		verbRepr := "'(unknown)'"
		if result.Command != "" {
			verbRepr = fmt.Sprintf("%q", result.Command)
		}
		return &Error{
			Msg: fmt.Sprintf(
				"AssertSilentlyDropped is for UPDATE/DELETE … RETURNING "+
					"(USING acts as a row pre-filter); INSERT … RETURNING does "+
					"NOT silently drop — Postgres raises InsufficientPrivilege "+
					"on a WITH CHECK violation. Use AssertInvisible for SELECT "+
					"and AssertRejected for INSERT. Got command verb %s for "+
					"query: %q",
				verbRepr, sqlText,
			),
		}
	}

	// Both supported drivers (pgx, lib/pq) synthesize an empty
	// rows slice for UPDATE/DELETE without RETURNING — we can't
	// distinguish "RETURNING returned 0 rows" from "no RETURNING
	// at all" by looking at result.Rows. The TS port has the
	// same problem and solves it with a literal-keyword check;
	// the Python port distinguishes via psycopg's
	// `ProgrammingError` from `fetchall()` on a no-result-set
	// cursor.
	//
	// False positives (RETURNING inside a comment / string) are
	// out of scope — the helper's contract is "the SQL has
	// RETURNING and we're checking its row count." A user
	// passing literal-RETURNING-in-a-comment is asking for it.
	if !returningKeywordRe.MatchString(sqlText) {
		return &Error{
			Msg: fmt.Sprintf(
				"AssertSilentlyDropped requires the SQL to use RETURNING — "+
					"the helper checks that the affected row was hidden from "+
					"the current role by counting RETURNING's output. Without "+
					"RETURNING, the row count is not the relevant signal. "+
					"Query: %q",
				sqlText,
			),
		}
	}

	if len(result.Rows) > 0 {
		return &AssertionError{
			Msg: fmt.Sprintf(
				"AssertSilentlyDropped: expected RETURNING to yield 0 rows, "+
					"got %d row(s) for query: %q",
				len(result.Rows), sqlText,
			),
		}
	}
	return nil
}

// AssertRowsOptions holds the row-count argument for
// `Client.AssertRows`. Wrapping it in a struct keeps the call
// site readable — `client.AssertRows(ctx, sql,
// &AssertRowsOptions{Count: 1})` — and lets us add optional
// future knobs (e.g. partial-match) without churning callers.
type AssertRowsOptions struct {
	// Count is the expected row count (exact match).
	Count int
}

// AssertRows asserts the query returns exactly
// `options.Count` rows.
//
// Returns `*AssertionError` (matches `ErrAssertion`) if the
// count differs.
func (c *Client) AssertRows(
	ctx context.Context,
	sqlText string,
	options *AssertRowsOptions,
) error {
	if options == nil {
		return &Error{Msg: "AssertRows: options is nil; pass &AssertRowsOptions{Count: N}"}
	}
	return assertRows(ctx, c, sqlText, options.Count)
}

// AssertVisible asserts the query returns at least one row.
//
// Returns `*AssertionError` if zero rows.
func (c *Client) AssertVisible(ctx context.Context, sqlText string) error {
	return assertVisible(ctx, c, sqlText)
}

// AssertInvisible asserts the query returns zero rows.
//
// Returns `*AssertionError` if any rows returned.
func (c *Client) AssertInvisible(ctx context.Context, sqlText string) error {
	return assertInvisible(ctx, c, sqlText)
}

// AssertRejected asserts that running `sqlText` raises Postgres
// `InsufficientPrivilege` (SQLSTATE 42501).
//
// Wraps the query in a savepoint so the failure (which puts the
// transaction in 'aborted' state until rollback) doesn't poison
// subsequent queries. See the package-level docstring for the
// full Layer 1 wire sequence.
//
// Returns `*AssertionError` if the query succeeds or raises a
// different error. Driver errors from the SAVEPOINT / ROLLBACK
// TO SAVEPOINT / RELEASE SAVEPOINT calls themselves propagate
// unchanged (catastrophic connection loss, etc.).
func (c *Client) AssertRejected(ctx context.Context, sqlText string) error {
	return assertRejected(ctx, c, sqlText)
}

// AssertSilentlyDropped asserts that an UPDATE/DELETE with
// RETURNING yields zero rows — the Postgres RLS shape where
// the policy's USING expression filters every row out before
// the write.
//
// Returns `*Error` (matches `ErrAPIError`) for misuse (non-
// UPDATE/DELETE verb, missing RETURNING) — distinct from
// `*AssertionError` for the RLS-misbehavior case (RETURNING
// yielded rows).
//
// Side-effect: the SQL runs to completion before the verb-gate
// fires. Only call with the UPDATE/DELETE you actually want to
// execute.
func (c *Client) AssertSilentlyDropped(ctx context.Context, sqlText string) error {
	return assertSilentlyDropped(ctx, c, sqlText)
}
