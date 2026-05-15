package pgrlstest

import "errors"

// Error is the base error type for pgrls-test issues that aren't
// driver failures or test assertion failures. It signals a misuse
// of the API: bad SQL passed to a helper that requires a specific
// shape (UPDATE/DELETE for `AssertSilentlyDropped`), an
// unsupported PG version, etc.
//
// Cross-language guarantee: this mirrors `PgrlsTestError` in
// Python and TypeScript. The name uses Go's idiomatic short form
// (just `Error`) since it's already namespaced under the
// `pgrlstest` package — callers see `pgrlstest.Error` which is
// equivalent to `PgrlsTestError` in the prefix-free other
// languages.
//
// Use `errors.Is(err, pgrlstest.ErrAPIError)` to test sentinel
// matches, or type-assert with `var pe *pgrlstest.Error;
// errors.As(err, &pe)` to access the structured fields. The
// underlying cause (when present) is exposed via `Unwrap()`.
type Error struct {
	// Msg is the human-readable explanation of what went wrong.
	// Stable across releases — tests may grep on substrings, but
	// the prose of the message is not committed across minor
	// versions.
	Msg string

	// Cause is the wrapped underlying error, if any. nil when
	// the error originated in pgrls-test itself rather than from
	// a driver / library underneath.
	Cause error
}

// ErrAPIError is the sentinel for `errors.Is` checks. Any
// `*Error` matches it via the `Is` method below.
var ErrAPIError = errors.New("pgrlstest: API error")

func (e *Error) Error() string {
	if e.Cause != nil {
		return "pgrlstest: " + e.Msg + ": " + e.Cause.Error()
	}
	return "pgrlstest: " + e.Msg
}

func (e *Error) Unwrap() error { return e.Cause }

func (e *Error) Is(target error) bool {
	// Match the sentinel so callers can `errors.Is(err,
	// pgrlstest.ErrAPIError)` to filter pgrls-test API errors
	// from driver errors without type-asserting.
	return target == ErrAPIError
}

// AssertionError signals that a pgrls-test assertion helper
// (AssertRows, AssertVisible, AssertInvisible, AssertRejected,
// AssertSilentlyDropped) saw a result that disagreed with its
// claim about the schema's RLS behavior.
//
// Cross-language guarantee: mirrors `PgrlsTestAssertionError` in
// Python and TypeScript. Test runners that want to distinguish
// "the test framework itself broke" from "the schema's RLS is
// wrong" can match on `errors.Is(err, pgrlstest.ErrAssertion)`.
//
// `AssertionError` does NOT carry an `Unwrap` chain — its `Msg`
// includes the underlying driver error's type and message when
// applicable (the `AssertRejected` wrong-shape-error case
// includes `%T: %s` of the underlying error in the message).
// The Go-side parity is with the TS port, which constructs the
// message at throw time rather than chaining a `from exc`
// (Python's idiom); Go callers use `errors.Is(err, ErrAssertion)`
// to route assertion failures, and read `err.Error()` for the
// underlying error's text when present.
type AssertionError struct {
	Msg string
}

// ErrAssertion is the sentinel for `errors.Is` checks. Any
// `*AssertionError` matches it via the `Is` method below.
var ErrAssertion = errors.New("pgrlstest: assertion failed")

func (e *AssertionError) Error() string {
	return "pgrlstest: assertion failed: " + e.Msg
}

func (e *AssertionError) Is(target error) bool {
	return target == ErrAssertion
}
