package pgx

import (
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/pgrls/pgrls/go/pgrlstest"
)

// Compile-time check: both constructors return values
// satisfying pgrlstest.Driver. A future signature change to
// the Driver interface that the adapters miss will break this
// test file's compilation, not just an `it()` assertion.
// (We don't have a real *pgx.Conn / *pgxpool.Pool to feed in
// here — but a typed nil pointer is enough for the compile
// check.)
//
// The poolDriver also satisfies pgrlstest.Closer; pin that.
var (
	_ pgrlstest.Driver = (*connDriver)(nil)
	_ pgrlstest.Driver = (*poolDriver)(nil)
	_ pgrlstest.Closer = (*poolDriver)(nil)
)

func TestIsInsufficientPrivilege_TrueFor42501(t *testing.T) {
	// pgx surfaces server errors as `*pgconn.PgError` with
	// Code set to the 5-char SQLSTATE. 42501 is
	// insufficient_privilege — what RLS policy violations
	// raise. AssertRejected (step 5) keys off this.
	err := &pgconn.PgError{Code: pgerrcode.InsufficientPrivilege}
	if !isInsufficientPrivilege(err) {
		t.Error("expected true for *pgconn.PgError{Code: 42501}")
	}
}

func TestIsInsufficientPrivilege_FalseForOtherSQLSTATEs(t *testing.T) {
	cases := []string{
		pgerrcode.UniqueViolation,        // 23505
		pgerrcode.SyntaxError,            // 42601
		pgerrcode.UndefinedColumn,        // 42703
		pgerrcode.ConnectionDoesNotExist, // 08003
	}
	for _, code := range cases {
		t.Run(code, func(t *testing.T) {
			err := &pgconn.PgError{Code: code}
			if isInsufficientPrivilege(err) {
				t.Errorf("expected false for SQLSTATE %s", code)
			}
		})
	}
}

func TestIsInsufficientPrivilege_FalseForNonPgError(t *testing.T) {
	// Connection errors, context-cancellation, garden-variety
	// errors — none should classify as 42501.
	cases := []error{
		errors.New("connection closed"),
		fmt.Errorf("wrapped: %w", errors.New("nope")),
	}
	for i, err := range cases {
		t.Run(fmt.Sprintf("case-%d", i), func(t *testing.T) {
			if isInsufficientPrivilege(err) {
				t.Errorf("expected false for non-PgError input %v", err)
			}
		})
	}
}

func TestIsInsufficientPrivilege_NilReturnsFalse(t *testing.T) {
	if isInsufficientPrivilege(nil) {
		t.Error("expected false for nil input")
	}
}

func TestIsInsufficientPrivilege_WalksWrappedChain(t *testing.T) {
	// pgx may surface the PgError wrapped — e.g. pgxpool can
	// wrap acquisition errors. `errors.As` MUST unwrap; the
	// adapter uses that primitive precisely so wrapping
	// doesn't break the classification.
	inner := &pgconn.PgError{Code: pgerrcode.InsufficientPrivilege}
	wrapped := fmt.Errorf("transaction aborted: %w", inner)
	if !isInsufficientPrivilege(wrapped) {
		t.Error("expected true for wrapped PgError chain")
	}
}

func TestFirstWord_ParsesCommandTag(t *testing.T) {
	cases := map[string]string{
		"SELECT 5":              "SELECT",
		"UPDATE 3":              "UPDATE",
		"INSERT 0 12":           "INSERT",
		"DELETE 0":              "DELETE",
		"BEGIN":                 "BEGIN",
		"ROLLBACK":              "ROLLBACK",
		"SAVEPOINT":             "SAVEPOINT",
		"  select  *  from t ": "SELECT", // leading whitespace, mixed case
		"":                      "",
		"   ":                   "",
		"select\tfrom":          "SELECT", // tab separator
	}
	for input, want := range cases {
		got := firstWord(input)
		if got != want {
			t.Errorf("firstWord(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestHasReturning_DetectsKeyword(t *testing.T) {
	cases := map[string]bool{
		"UPDATE t SET x = 1 RETURNING id":         true,
		"UPDATE t SET x = 1 returning id":         true,         // case-insensitive
		"DELETE FROM t RETURNING *":               true,
		"INSERT INTO t (x) VALUES (1) RETURNING id": true,
		"UPDATE t SET x = 1":                      false,       // no RETURNING
		"SELECT * FROM t":                         false,
		"UPDATE t SET returning_col = 1":          false,       // word boundary: returning_col is not RETURNING
		"UPDATE t SET preturning = 1":             false,       // prefix
		"":                                        false,
	}
	for sql, want := range cases {
		got := hasReturning(sql)
		if got != want {
			t.Errorf("hasReturning(%q) = %v, want %v", sql, got, want)
		}
	}
}

func TestIsIdentChar_MatchesSQLIdentifierShape(t *testing.T) {
	cases := map[byte]bool{
		// ASCII letters
		'A': true, 'Z': true, 'a': true, 'z': true, 'M': true, 'm': true,
		// ASCII digits — part of identifiers (after the first char)
		'0': true, '9': true,
		// Underscore — part of identifiers (`returning_col`)
		'_': true,
		// Whitespace + punctuation — word boundaries
		' ': false, '\t': false,
		'(': false, ')': false, ';': false, '\'': false, ',': false,
	}
	for b, want := range cases {
		got := isIdentChar(b)
		if got != want {
			t.Errorf("isIdentChar(%q) = %v, want %v", b, got, want)
		}
	}
}
