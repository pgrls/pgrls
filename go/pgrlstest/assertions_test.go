package pgrlstest

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// assertionDriver is a minimal Driver tailored to assertion-
// helper tests. It augments recordingDriver semantics with a
// query-failure injector keyed by exact SQL match (so a test
// can say "the assertion's body SQL fails with a 42501-shaped
// error" by SQL string rather than by call index).
type assertionDriver struct {
	calls         []recordedCall
	failBySQL     map[string]error
	rowsBySQL     map[string]QueryResult
	classifyError func(error) bool
}

func (d *assertionDriver) Query(_ context.Context, sqlText string, params ...any) (QueryResult, error) {
	d.calls = append(d.calls, recordedCall{sql: sqlText, params: params})
	if err, ok := d.failBySQL[sqlText]; ok {
		return QueryResult{}, err
	}
	if out, ok := d.rowsBySQL[sqlText]; ok {
		return out, nil
	}
	return QueryResult{}, nil
}

func (d *assertionDriver) Rollback(_ context.Context) error { return nil }

func (d *assertionDriver) IsInsufficientPrivilege(err error) bool {
	if d.classifyError != nil {
		return d.classifyError(err)
	}
	return false
}

var _ Driver = (*assertionDriver)(nil)

func TestAssertRows_Pass(t *testing.T) {
	d := &assertionDriver{
		rowsBySQL: map[string]QueryResult{
			"SELECT * FROM t": {Rows: []map[string]any{{"id": 1}, {"id": 2}}, Command: "SELECT", RowCount: 2},
		},
	}
	c := NewClient(d)

	if err := c.AssertRows(context.Background(), "SELECT * FROM t", &AssertRowsOptions{Count: 2}); err != nil {
		t.Errorf("AssertRows returned error on matching count: %v", err)
	}
}

func TestAssertRows_FailsOnMismatch(t *testing.T) {
	d := &assertionDriver{
		rowsBySQL: map[string]QueryResult{
			"SELECT * FROM t": {Rows: []map[string]any{{"id": 1}}, Command: "SELECT", RowCount: 1},
		},
	}
	c := NewClient(d)

	err := c.AssertRows(context.Background(), "SELECT * FROM t", &AssertRowsOptions{Count: 2})
	if err == nil {
		t.Fatal("expected AssertionError for row-count mismatch")
	}
	if !errors.Is(err, ErrAssertion) {
		t.Errorf("error %v does not match ErrAssertion sentinel", err)
	}
	if !strings.Contains(err.Error(), "expected 2 row(s), got 1") {
		t.Errorf("error %q missing expected message", err.Error())
	}
}

func TestAssertRows_NilOptionsIsError(t *testing.T) {
	d := &assertionDriver{}
	c := NewClient(d)

	err := c.AssertRows(context.Background(), "SELECT 1", nil)
	if err == nil {
		t.Fatal("expected error for nil options")
	}
	if !errors.Is(err, ErrAPIError) {
		t.Errorf("error %v does not match ErrAPIError sentinel", err)
	}
}

func TestAssertRows_PropagatesDriverError(t *testing.T) {
	want := errors.New("driver oops")
	d := &assertionDriver{failBySQL: map[string]error{"SELECT 1": want}}
	c := NewClient(d)

	got := c.AssertRows(context.Background(), "SELECT 1", &AssertRowsOptions{Count: 0})
	if !errors.Is(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestAssertVisible_Pass(t *testing.T) {
	d := &assertionDriver{
		rowsBySQL: map[string]QueryResult{
			"SELECT 1": {Rows: []map[string]any{{"id": 1}}, Command: "SELECT", RowCount: 1},
		},
	}
	c := NewClient(d)

	if err := c.AssertVisible(context.Background(), "SELECT 1"); err != nil {
		t.Errorf("AssertVisible returned error on visible row: %v", err)
	}
}

func TestAssertVisible_FailsOnZeroRows(t *testing.T) {
	d := &assertionDriver{
		rowsBySQL: map[string]QueryResult{
			"SELECT 1": {Rows: nil, Command: "SELECT", RowCount: 0},
		},
	}
	c := NewClient(d)

	err := c.AssertVisible(context.Background(), "SELECT 1")
	if err == nil {
		t.Fatal("expected AssertionError for zero rows")
	}
	if !errors.Is(err, ErrAssertion) {
		t.Errorf("error %v does not match ErrAssertion sentinel", err)
	}
}

func TestAssertVisible_PropagatesDriverError(t *testing.T) {
	want := errors.New("driver oops")
	d := &assertionDriver{failBySQL: map[string]error{"SELECT 1": want}}
	c := NewClient(d)

	got := c.AssertVisible(context.Background(), "SELECT 1")
	if !errors.Is(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestAssertInvisible_PropagatesDriverError(t *testing.T) {
	want := errors.New("driver oops")
	d := &assertionDriver{failBySQL: map[string]error{"SELECT 1": want}}
	c := NewClient(d)

	got := c.AssertInvisible(context.Background(), "SELECT 1")
	if !errors.Is(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestAssertInvisible_Pass(t *testing.T) {
	d := &assertionDriver{
		rowsBySQL: map[string]QueryResult{
			"SELECT 1": {Rows: nil, Command: "SELECT", RowCount: 0},
		},
	}
	c := NewClient(d)

	if err := c.AssertInvisible(context.Background(), "SELECT 1"); err != nil {
		t.Errorf("AssertInvisible returned error on zero rows: %v", err)
	}
}

func TestAssertInvisible_FailsOnAnyRows(t *testing.T) {
	d := &assertionDriver{
		rowsBySQL: map[string]QueryResult{
			"SELECT 1": {Rows: []map[string]any{{"id": 1}}, Command: "SELECT", RowCount: 1},
		},
	}
	c := NewClient(d)

	err := c.AssertInvisible(context.Background(), "SELECT 1")
	if err == nil {
		t.Fatal("expected AssertionError for non-zero rows")
	}
	if !errors.Is(err, ErrAssertion) {
		t.Errorf("error %v does not match ErrAssertion sentinel", err)
	}
	if !strings.Contains(err.Error(), "expected 0 rows, got 1") {
		t.Errorf("error %q missing expected message", err.Error())
	}
}

func TestAssertRejected_PassesOn42501(t *testing.T) {
	// Driver raises a 42501-shaped error. AssertRejected must
	// ROLLBACK TO SAVEPOINT and return nil.
	driverErr := errors.New("insufficient_privilege")
	d := &assertionDriver{
		failBySQL: map[string]error{
			"INSERT INTO t (x) VALUES (1)": driverErr,
		},
		classifyError: func(err error) bool {
			return errors.Is(err, driverErr)
		},
	}
	c := NewClient(d)

	err := c.AssertRejected(context.Background(), "INSERT INTO t (x) VALUES (1)")
	if err != nil {
		t.Errorf("AssertRejected returned error on 42501: %v", err)
	}

	// Wire sequence: SAVEPOINT pgrls_check_<rand> → body
	// (fails 42501) → ROLLBACK TO SAVEPOINT.
	if len(d.calls) != 3 {
		t.Fatalf("expected 3 calls, got %d: %#v", len(d.calls), d.calls)
	}
	if !strings.HasPrefix(d.calls[0].sql, "SAVEPOINT pgrls_check_") {
		t.Errorf("call[0] sql = %q, want SAVEPOINT pgrls_check_", d.calls[0].sql)
	}
	if d.calls[1].sql != "INSERT INTO t (x) VALUES (1)" {
		t.Errorf("call[1] sql = %q", d.calls[1].sql)
	}
	if !strings.HasPrefix(d.calls[2].sql, "ROLLBACK TO SAVEPOINT pgrls_check_") {
		t.Errorf("call[2] sql = %q, want ROLLBACK TO SAVEPOINT pgrls_check_", d.calls[2].sql)
	}
}

func TestAssertRejected_FailsOnSuccess(t *testing.T) {
	// Driver succeeds — body did not raise. AssertRejected must
	// RELEASE SAVEPOINT and return AssertionError.
	d := &assertionDriver{}
	c := NewClient(d)

	err := c.AssertRejected(context.Background(), "SELECT 1")
	if err == nil {
		t.Fatal("expected AssertionError when query succeeds")
	}
	if !errors.Is(err, ErrAssertion) {
		t.Errorf("error %v does not match ErrAssertion sentinel", err)
	}
	if !strings.Contains(err.Error(), "query succeeded but expected RLS rejection") {
		t.Errorf("error %q missing expected message", err.Error())
	}

	// Final call must be RELEASE SAVEPOINT (success path).
	last := d.calls[len(d.calls)-1]
	if !strings.HasPrefix(last.sql, "RELEASE SAVEPOINT pgrls_check_") {
		t.Errorf("last call sql = %q, want RELEASE SAVEPOINT", last.sql)
	}
}

func TestAssertRejected_FailsOnWrongError(t *testing.T) {
	// Driver raises a non-42501 error. AssertRejected must
	// ROLLBACK TO SAVEPOINT and return AssertionError wrapping
	// the wrong-shape error.
	wrongErr := errors.New("23505 unique_violation")
	d := &assertionDriver{
		failBySQL: map[string]error{
			"INSERT INTO t (x) VALUES (1)": wrongErr,
		},
		// classifyError returns false (default) — wrongErr is
		// NOT 42501.
	}
	c := NewClient(d)

	err := c.AssertRejected(context.Background(), "INSERT INTO t (x) VALUES (1)")
	if err == nil {
		t.Fatal("expected AssertionError on wrong-shape error")
	}
	if !errors.Is(err, ErrAssertion) {
		t.Errorf("error %v does not match ErrAssertion sentinel", err)
	}
	if !strings.Contains(err.Error(), "expected InsufficientPrivilege") {
		t.Errorf("error %q missing expected message", err.Error())
	}
	if !strings.Contains(err.Error(), "23505") {
		t.Errorf("error %q does not mention the underlying error message", err.Error())
	}

	// Final call must be ROLLBACK TO SAVEPOINT (recovery path
	// even on wrong-shape error — driver is in aborted state).
	last := d.calls[len(d.calls)-1]
	if !strings.HasPrefix(last.sql, "ROLLBACK TO SAVEPOINT pgrls_check_") {
		t.Errorf("last call sql = %q, want ROLLBACK TO SAVEPOINT", last.sql)
	}
}

func TestAssertRejected_PropagatesSavepointError(t *testing.T) {
	// If the SAVEPOINT itself fails, AssertRejected propagates
	// the error rather than running the body.
	want := errors.New("savepoint failed")
	d := &assertionDriver{
		// We don't know the random savepoint name; use a
		// catch-all by wrapping the classifier.
		classifyError: func(error) bool { return false },
	}
	// Bypass failBySQL keying — install a wrapper that fails
	// the first call regardless.
	wrappedFailing := &savepointFailDriver{inner: d, failOnFirst: want}
	c := NewClient(wrappedFailing)

	err := c.AssertRejected(context.Background(), "SELECT 1")
	if !errors.Is(err, want) {
		t.Errorf("got %v, want %v", err, want)
	}
}

// savepointFailDriver wraps assertionDriver and fails the first
// Query call regardless of SQL (which lands on the SAVEPOINT
// pgrls_check_<rand> call — we can't predict the random name).
// Used to test SAVEPOINT-failure propagation in AssertRejected.
type savepointFailDriver struct {
	inner       *assertionDriver
	failOnFirst error
	calls       int
}

func (d *savepointFailDriver) Query(ctx context.Context, sqlText string, params ...any) (QueryResult, error) {
	d.calls++
	if d.calls == 1 {
		return QueryResult{}, d.failOnFirst
	}
	return d.inner.Query(ctx, sqlText, params...)
}
func (d *savepointFailDriver) Rollback(ctx context.Context) error { return d.inner.Rollback(ctx) }
func (d *savepointFailDriver) IsInsufficientPrivilege(err error) bool {
	return d.inner.IsInsufficientPrivilege(err)
}

func TestAssertSilentlyDropped_Pass(t *testing.T) {
	d := &assertionDriver{
		rowsBySQL: map[string]QueryResult{
			"UPDATE t SET x = 1 RETURNING id": {
				Rows: nil, Command: "UPDATE", RowCount: 0,
			},
		},
	}
	c := NewClient(d)

	if err := c.AssertSilentlyDropped(context.Background(), "UPDATE t SET x = 1 RETURNING id"); err != nil {
		t.Errorf("AssertSilentlyDropped returned error on zero RETURNING rows: %v", err)
	}
}

func TestAssertSilentlyDropped_FailsOnReturnedRows(t *testing.T) {
	d := &assertionDriver{
		rowsBySQL: map[string]QueryResult{
			"UPDATE t SET x = 1 RETURNING id": {
				Rows: []map[string]any{{"id": 1}}, Command: "UPDATE", RowCount: 1,
			},
		},
	}
	c := NewClient(d)

	err := c.AssertSilentlyDropped(context.Background(), "UPDATE t SET x = 1 RETURNING id")
	if err == nil {
		t.Fatal("expected AssertionError when RETURNING returned a row")
	}
	if !errors.Is(err, ErrAssertion) {
		t.Errorf("error %v does not match ErrAssertion sentinel", err)
	}
	if !strings.Contains(err.Error(), "got 1 row(s)") {
		t.Errorf("error %q missing expected message", err.Error())
	}
}

func TestAssertSilentlyDropped_RejectsSelect(t *testing.T) {
	d := &assertionDriver{
		rowsBySQL: map[string]QueryResult{
			"SELECT * FROM t WHERE 1=0": {Rows: nil, Command: "SELECT", RowCount: 0},
		},
	}
	c := NewClient(d)

	err := c.AssertSilentlyDropped(context.Background(), "SELECT * FROM t WHERE 1=0")
	if err == nil {
		t.Fatal("expected misuse error for SELECT")
	}
	if !errors.Is(err, ErrAPIError) {
		t.Errorf("error %v does not match ErrAPIError sentinel (misuse, not assertion)", err)
	}
	if !strings.Contains(err.Error(), "UPDATE/DELETE") {
		t.Errorf("error %q missing UPDATE/DELETE guidance", err.Error())
	}
}

func TestAssertSilentlyDropped_RejectsInsert(t *testing.T) {
	d := &assertionDriver{
		rowsBySQL: map[string]QueryResult{
			"INSERT INTO t (x) VALUES (1) RETURNING id": {
				Rows: nil, Command: "INSERT", RowCount: 1,
			},
		},
	}
	c := NewClient(d)

	err := c.AssertSilentlyDropped(context.Background(), "INSERT INTO t (x) VALUES (1) RETURNING id")
	if err == nil {
		t.Fatal("expected misuse error for INSERT")
	}
	if !errors.Is(err, ErrAPIError) {
		t.Errorf("error %v does not match ErrAPIError sentinel", err)
	}
	// Must point user at AssertRejected for the INSERT case.
	if !strings.Contains(err.Error(), "AssertRejected") {
		t.Errorf("error %q does not steer toward AssertRejected", err.Error())
	}
}

func TestAssertSilentlyDropped_RejectsMissingRETURNING(t *testing.T) {
	d := &assertionDriver{
		rowsBySQL: map[string]QueryResult{
			"UPDATE t SET x = 1": {Rows: nil, Command: "UPDATE", RowCount: 0},
		},
	}
	c := NewClient(d)

	err := c.AssertSilentlyDropped(context.Background(), "UPDATE t SET x = 1")
	if err == nil {
		t.Fatal("expected misuse error for missing RETURNING")
	}
	if !errors.Is(err, ErrAPIError) {
		t.Errorf("error %v does not match ErrAPIError sentinel", err)
	}
	if !strings.Contains(err.Error(), "RETURNING") {
		t.Errorf("error %q missing RETURNING guidance", err.Error())
	}
}

func TestAssertSilentlyDropped_AcceptsDelete(t *testing.T) {
	d := &assertionDriver{
		rowsBySQL: map[string]QueryResult{
			"DELETE FROM t RETURNING id": {Rows: nil, Command: "DELETE", RowCount: 0},
		},
	}
	c := NewClient(d)

	if err := c.AssertSilentlyDropped(context.Background(), "DELETE FROM t RETURNING id"); err != nil {
		t.Errorf("AssertSilentlyDropped returned error for clean DELETE: %v", err)
	}
}

func TestAssertSilentlyDropped_CaseInsensitiveRETURNING(t *testing.T) {
	// Lowercase `returning` must satisfy the regex (case-
	// insensitive word-boundary match).
	d := &assertionDriver{
		rowsBySQL: map[string]QueryResult{
			"update t set x = 1 returning id": {Rows: nil, Command: "UPDATE", RowCount: 0},
		},
	}
	c := NewClient(d)

	if err := c.AssertSilentlyDropped(context.Background(), "update t set x = 1 returning id"); err != nil {
		t.Errorf("AssertSilentlyDropped should accept lowercase returning: %v", err)
	}
}

func TestAssertSilentlyDropped_WordBoundaryNotMatched(t *testing.T) {
	// `returning_col` is NOT the RETURNING keyword — the
	// word-boundary check must reject this as missing-RETURNING.
	d := &assertionDriver{
		rowsBySQL: map[string]QueryResult{
			"UPDATE t SET returning_col = 1": {Rows: nil, Command: "UPDATE", RowCount: 0},
		},
	}
	c := NewClient(d)

	err := c.AssertSilentlyDropped(context.Background(), "UPDATE t SET returning_col = 1")
	if err == nil {
		t.Fatal("expected misuse error for column-name `returning_col`")
	}
	if !errors.Is(err, ErrAPIError) {
		t.Errorf("error %v does not match ErrAPIError sentinel", err)
	}
}

func TestAssertSilentlyDropped_PropagatesDriverError(t *testing.T) {
	want := errors.New("syntax error")
	d := &assertionDriver{
		failBySQL: map[string]error{"UPDATE t SET x = 1 RETURNING id": want},
	}
	c := NewClient(d)

	got := c.AssertSilentlyDropped(context.Background(), "UPDATE t SET x = 1 RETURNING id")
	if !errors.Is(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// Compile-time pin for the wrapper used in TestAssertRejected_PropagatesSavepointError.
var _ Driver = (*savepointFailDriver)(nil)

func TestAssertSilentlyDropped_EmptyCommandFallsThroughMisuse(t *testing.T) {
	// Defensive: a driver that returns "" for Command (e.g. an
	// unknown command tag) must trigger the misuse branch with
	// the `'(unknown)'` verb rendering, not silently pass.
	d := &assertionDriver{
		rowsBySQL: map[string]QueryResult{
			"DO $$ ... $$": {Rows: nil, Command: "", RowCount: 0},
		},
	}
	c := NewClient(d)

	err := c.AssertSilentlyDropped(context.Background(), "DO $$ ... $$")
	if err == nil {
		t.Fatal("expected misuse error for empty Command")
	}
	if !errors.Is(err, ErrAPIError) {
		t.Errorf("error %v does not match ErrAPIError sentinel", err)
	}
	if !strings.Contains(err.Error(), "'(unknown)'") {
		t.Errorf("error %q should mention '(unknown)' verb", err.Error())
	}
}

func TestAssertRejected_RollbackFailureOnWrongShapeError(t *testing.T) {
	// Defensive: if the ROLLBACK TO SAVEPOINT call itself fails
	// after the body raised a wrong-shape error, AssertRejected
	// surfaces the rollback error (the wrong-shape error and
	// associated AssertionError are dropped — the rollback
	// failure is the more catastrophic event).
	wrongErr := errors.New("23505 unique_violation")
	rollbackErr := errors.New("connection lost")
	d := &rollbackFailDriver{
		bodyErr:     wrongErr,
		rollbackErr: rollbackErr,
	}
	c := NewClient(d)

	err := c.AssertRejected(context.Background(), "INSERT INTO t (x) VALUES (1)")
	if !errors.Is(err, rollbackErr) {
		t.Errorf("got %v, want rollback error %v", err, rollbackErr)
	}
}

func TestAssertRejected_ReleaseFailureOnSuccess(t *testing.T) {
	// Defensive: if the RELEASE SAVEPOINT call fails on the
	// success path, AssertRejected surfaces the release error
	// (the "succeeded but expected rejection" AssertionError is
	// dropped — the release failure is more catastrophic).
	releaseErr := errors.New("connection lost")
	d := &releaseFailDriver{releaseErr: releaseErr}
	c := NewClient(d)

	err := c.AssertRejected(context.Background(), "SELECT 1")
	if !errors.Is(err, releaseErr) {
		t.Errorf("got %v, want release error %v", err, releaseErr)
	}
}

// rollbackFailDriver: first Query (SAVEPOINT) succeeds; second
// (body SQL) returns bodyErr; third (ROLLBACK TO SAVEPOINT)
// returns rollbackErr. classifyError returns false so the body
// error is classified as wrong-shape.
type rollbackFailDriver struct {
	calls       int
	bodyErr     error
	rollbackErr error
}

func (d *rollbackFailDriver) Query(_ context.Context, _ string, _ ...any) (QueryResult, error) {
	d.calls++
	switch d.calls {
	case 1: // SAVEPOINT
		return QueryResult{}, nil
	case 2: // body SQL
		return QueryResult{}, d.bodyErr
	case 3: // ROLLBACK TO SAVEPOINT
		return QueryResult{}, d.rollbackErr
	default:
		return QueryResult{}, nil
	}
}
func (d *rollbackFailDriver) Rollback(_ context.Context) error     { return nil }
func (d *rollbackFailDriver) IsInsufficientPrivilege(_ error) bool { return false }

// releaseFailDriver: first Query (SAVEPOINT) succeeds; second
// (body SQL) succeeds; third (RELEASE SAVEPOINT) returns
// releaseErr.
type releaseFailDriver struct {
	calls      int
	releaseErr error
}

func (d *releaseFailDriver) Query(_ context.Context, _ string, _ ...any) (QueryResult, error) {
	d.calls++
	if d.calls == 3 {
		return QueryResult{}, d.releaseErr
	}
	return QueryResult{}, nil
}
func (d *releaseFailDriver) Rollback(_ context.Context) error     { return nil }
func (d *releaseFailDriver) IsInsufficientPrivilege(_ error) bool { return false }

var (
	_ Driver = (*rollbackFailDriver)(nil)
	_ Driver = (*releaseFailDriver)(nil)
)
