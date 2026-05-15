package pgrlstest

import (
	"errors"
	"fmt"
	"testing"
)

func TestError_FormatsMsgWithPrefix(t *testing.T) {
	err := &Error{Msg: "bad SQL"}
	got := err.Error()
	want := "pgrlstest: bad SQL"
	if got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

func TestError_FormatsWithCause(t *testing.T) {
	cause := errors.New("driver: connection closed")
	err := &Error{Msg: "transaction aborted", Cause: cause}
	got := err.Error()
	want := "pgrlstest: transaction aborted: driver: connection closed"
	if got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

func TestError_Unwrap_ReturnsCause(t *testing.T) {
	cause := errors.New("inner")
	err := &Error{Msg: "outer", Cause: cause}
	if !errors.Is(err, cause) {
		t.Errorf("errors.Is should walk Unwrap() to find cause")
	}
}

func TestError_Unwrap_NilWhenNoCause(t *testing.T) {
	err := &Error{Msg: "no cause"}
	if err.Unwrap() != nil {
		t.Errorf("Unwrap() should be nil when Cause is nil")
	}
}

func TestError_IsMatchesSentinel(t *testing.T) {
	err := &Error{Msg: "any"}
	if !errors.Is(err, ErrAPIError) {
		t.Errorf("errors.Is(err, ErrAPIError) must be true for any *Error")
	}
}

func TestError_IsDoesNotMatchAssertionSentinel(t *testing.T) {
	// An API error must NOT match the assertion sentinel —
	// downstream code uses the distinction to route failures
	// differently ("schema bug" vs "test framework bug").
	err := &Error{Msg: "any"}
	if errors.Is(err, ErrAssertion) {
		t.Errorf("Error must not match ErrAssertion")
	}
}

func TestAssertionError_FormatsMsg(t *testing.T) {
	err := &AssertionError{Msg: "expected 2 rows, got 1"}
	got := err.Error()
	want := "pgrlstest: assertion failed: expected 2 rows, got 1"
	if got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

func TestAssertionError_IsMatchesSentinel(t *testing.T) {
	err := &AssertionError{Msg: "any"}
	if !errors.Is(err, ErrAssertion) {
		t.Errorf("errors.Is(err, ErrAssertion) must be true for any *AssertionError")
	}
}

func TestAssertionError_DoesNotMatchAPISentinel(t *testing.T) {
	err := &AssertionError{Msg: "any"}
	if errors.Is(err, ErrAPIError) {
		t.Errorf("AssertionError must not match ErrAPIError")
	}
}

func TestAssertionError_NoUnwrapChain(t *testing.T) {
	// Cross-language invariant: AssertionError must NOT carry an
	// Unwrap chain. Wrong-shape errors from AssertRejected are
	// stringified into Msg at throw time (matches the TS port;
	// Python uses `raise … from exc` but the Go-side surface is
	// intentionally no-chain so `errors.Is(err, driverErr)`
	// against an unrelated driver error stays false).
	//
	// Pin this so a future refactor that adds an Unwrap method
	// breaks the build, not just a runtime assertion in a
	// real-Postgres conformance run.
	driverErr := errors.New("23505 unique_violation")
	asserted := &AssertionError{
		Msg: fmt.Sprintf("AssertRejected: expected InsufficientPrivilege, got %T: %s", driverErr, driverErr.Error()),
	}
	if errors.Unwrap(asserted) != nil {
		t.Error("AssertionError must not have an Unwrap chain")
	}
	if errors.Is(asserted, driverErr) {
		t.Error("AssertionError must not transitively match the underlying driver error via errors.Is")
	}
}

// Pin the documented exported names against the cross-language
// contract — Python uses `PgrlsTestError` / `PgrlsTestAssertionError`,
// TS the same, Go uses the shorter `Error` / `AssertionError`
// (already namespaced under the `pgrlstest` package). The
// CHANGELOG entry calls this out explicitly; pin the actual
// types here so a rename never slips past CI without updating
// the cross-language doc.
func TestAPI_TypesExist(t *testing.T) {
	// `*Error` and `*AssertionError` are exported; constructing
	// them via zero value should compile.
	var _ error = &Error{}
	var _ error = &AssertionError{}
	// Sentinel values are exported and non-nil.
	if ErrAPIError == nil || ErrAssertion == nil {
		t.Fatal("sentinel errors must be non-nil")
	}
}

// Example usage that exercises the cross-language pattern:
// an API misuse (passing a non-DML SQL to AssertSilentlyDropped)
// surfaces as *Error matching ErrAPIError, while a row-count
// mismatch surfaces as *AssertionError matching ErrAssertion.
// Both can be filtered with errors.Is.
func ExampleError() {
	err := &Error{Msg: "AssertSilentlyDropped requires UPDATE/DELETE … RETURNING"}
	if errors.Is(err, ErrAPIError) {
		fmt.Println("API misuse:", err)
	}
	// Output: API misuse: pgrlstest: AssertSilentlyDropped requires UPDATE/DELETE … RETURNING
}

func ExampleAssertionError() {
	err := &AssertionError{Msg: "expected 2 row(s), got 1"}
	if errors.Is(err, ErrAssertion) {
		fmt.Println("RLS assertion failed:", err)
	}
	// Output: RLS assertion failed: pgrlstest: assertion failed: expected 2 row(s), got 1
}
