package pq

import (
	"errors"
	"fmt"
	"testing"

	pqlib "github.com/lib/pq"

	"github.com/pgrls/pgrls/go/pgrlstest"
)

// Compile-time check: both constructors return values that
// satisfy pgrlstest.Driver. The dbDriver additionally
// satisfies pgrlstest.Closer (it pins a *sql.Conn lazily and
// releases it on Close); the connDriver does NOT (the caller
// owns the *sql.Conn lifecycle). A future signature change to
// the Driver / Closer interfaces breaks this file's
// compilation, not just an assertion.
var (
	_ pgrlstest.Driver = (*connDriver)(nil)
	_ pgrlstest.Driver = (*dbDriver)(nil)
	_ pgrlstest.Closer = (*dbDriver)(nil)
)

func TestIsInsufficientPrivilege_TrueFor42501(t *testing.T) {
	// lib/pq surfaces server errors as `*pq.Error` with Code
	// set to a stringly-typed SQLSTATE alias. "42501" is
	// insufficient_privilege — what RLS policy violations
	// raise. AssertRejected (step 5) keys off this.
	err := &pqlib.Error{Code: pqlib.ErrorCode("42501")}
	if !isInsufficientPrivilege(err) {
		t.Error(`expected true for *pq.Error{Code: "42501"}`)
	}
}

func TestIsInsufficientPrivilege_FalseForOtherSQLSTATEs(t *testing.T) {
	cases := []string{
		"23505", // unique_violation
		"42601", // syntax_error
		"42703", // undefined_column
		"08003", // connection_does_not_exist
	}
	for _, code := range cases {
		t.Run(code, func(t *testing.T) {
			err := &pqlib.Error{Code: pqlib.ErrorCode(code)}
			if isInsufficientPrivilege(err) {
				t.Errorf("expected false for SQLSTATE %s", code)
			}
		})
	}
}

func TestIsInsufficientPrivilege_FalseForNonPqError(t *testing.T) {
	cases := []error{
		errors.New("connection refused"),
		fmt.Errorf("wrapped: %w", errors.New("nope")),
	}
	for i, err := range cases {
		t.Run(fmt.Sprintf("case-%d", i), func(t *testing.T) {
			if isInsufficientPrivilege(err) {
				t.Errorf("expected false for non-pq.Error input %v", err)
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
	// database/sql may wrap the underlying pq.Error in its own
	// error type for context. `errors.As` MUST unwrap; the
	// adapter uses that primitive precisely so wrapping
	// doesn't break the classification.
	inner := &pqlib.Error{Code: pqlib.ErrorCode("42501")}
	wrapped := fmt.Errorf("transaction aborted: %w", inner)
	if !isInsufficientPrivilege(wrapped) {
		t.Error("expected true for wrapped pq.Error chain")
	}
}

func TestFirstWord_ParsesSQL(t *testing.T) {
	cases := map[string]string{
		"SELECT * FROM t":     "SELECT",
		"UPDATE t SET x = 1":  "UPDATE",
		"INSERT INTO t (x)":   "INSERT",
		"DELETE FROM t":       "DELETE",
		"BEGIN":               "BEGIN",
		"ROLLBACK":            "ROLLBACK",
		"SAVEPOINT sp1":       "SAVEPOINT",
		" select id ":         "SELECT", // leading whitespace
		"":                    "",
		"   ":                 "",
		"select\tfrom":        "SELECT", // tab separator
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
		"UPDATE t SET x = 1 RETURNING id":           true,
		"UPDATE t SET x = 1 returning id":           true,
		"DELETE FROM t RETURNING *":                 true,
		"INSERT INTO t (x) VALUES (1) RETURNING id": true,
		"UPDATE t SET x = 1":                        false,
		"SELECT * FROM t":                           false,
		// Word-boundary check: `returning_col` (subword) and
		// `preturning` (prefix) must NOT match.
		"UPDATE t SET returning_col = 1": false,
		"UPDATE t SET preturning = 1":    false,
		"":                               false,
	}
	for sqlText, want := range cases {
		got := hasReturning(sqlText)
		if got != want {
			t.Errorf("hasReturning(%q) = %v, want %v", sqlText, got, want)
		}
	}
}

func TestDBDriver_CloseIsIdempotentSerial(t *testing.T) {
	// Pin idempotency: a dbDriver with no pinned conn yet
	// MUST treat Close as a no-op (acquired == nil branch).
	d := &dbDriver{}
	if err := d.Close(nil); err != nil { //nolint:staticcheck // nil ctx test
		t.Errorf("first Close on never-used driver: %v", err)
	}
	if err := d.Close(nil); err != nil { //nolint:staticcheck
		t.Errorf("second Close on never-used driver: %v", err)
	}
}

func TestDBDriver_CloseOnlyReleasesWhenAcquired(t *testing.T) {
	d := &dbDriver{}
	if err := d.Close(nil); err != nil { //nolint:staticcheck
		t.Errorf("Close on zero-value dbDriver: %v", err)
	}
}

func TestIsIdentChar_MatchesSQLIdentifierShape(t *testing.T) {
	cases := map[byte]bool{
		// Letters
		'A': true, 'Z': true, 'a': true, 'z': true,
		// Digits — part of identifiers
		'0': true, '9': true,
		// Underscore — part of identifiers (e.g. `returning_col`)
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
