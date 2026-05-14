package pgrlstest

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"
)

// recordingDriver is an in-memory recorder used to pin the wire-level
// SQL sequence emitted by Client. It implements Driver and
// Closer. Each Query call is appended to `calls`; SELECTs return
// preconfigured `respondQueue` entries (FIFO). Errors at specific
// call indices can be injected via `failAt`.
type recordingDriver struct {
	calls         []recordedCall
	respondQueue  []QueryResult
	failAt        map[int]error
	rollbackErr   error
	rollbackCalls int
	closeErr      error
	closeCalls    int
	classify42501 func(error) bool
}

type recordedCall struct {
	sql    string
	params []any
}

func (d *recordingDriver) Query(_ context.Context, sqlText string, params ...any) (QueryResult, error) {
	idx := len(d.calls)
	d.calls = append(d.calls, recordedCall{sql: sqlText, params: params})
	if err, ok := d.failAt[idx]; ok {
		return QueryResult{}, err
	}
	// Only SELECT statements consume the respond queue. The
	// other Layer 1 wire calls (SAVEPOINT, SET LOCAL ROLE,
	// RELEASE SAVEPOINT, INSERT, etc.) return empty
	// QueryResult — they don't produce rows the client reads.
	// Without this gate, a non-SELECT call would pop a queued
	// row meant for a later SELECT and the capture would fail
	// with "no row".
	if len(d.respondQueue) > 0 && strings.HasPrefix(strings.TrimSpace(sqlText), "SELECT") {
		out := d.respondQueue[0]
		d.respondQueue = d.respondQueue[1:]
		return out, nil
	}
	return QueryResult{}, nil
}

func (d *recordingDriver) Rollback(_ context.Context) error {
	d.rollbackCalls++
	return d.rollbackErr
}

func (d *recordingDriver) IsInsufficientPrivilege(err error) bool {
	if d.classify42501 != nil {
		return d.classify42501(err)
	}
	return false
}

func (d *recordingDriver) Close(_ context.Context) error {
	d.closeCalls++
	return d.closeErr
}

// noCloserDriver is a minimal Driver that explicitly does NOT
// implement Closer. Used to exercise Client.Close when the
// underlying driver is a caller-owned single-conn adapter
// (the Client.Close path that type-asserts to Closer and
// falls through to a no-op).
type noCloserDriver struct{}

func (d *noCloserDriver) Query(_ context.Context, _ string, _ ...any) (QueryResult, error) {
	return QueryResult{}, nil
}

func (d *noCloserDriver) Rollback(_ context.Context) error      { return nil }
func (d *noCloserDriver) IsInsufficientPrivilege(_ error) bool { return false }

func TestClient_Transaction_BeginAndRollback(t *testing.T) {
	d := &recordingDriver{}
	c := NewClient(d)

	err := c.Transaction(context.Background(), func(_ context.Context) error {
		return nil
	})
	if err != nil {
		t.Fatalf("Transaction returned error: %v", err)
	}
	if len(d.calls) != 1 || d.calls[0].sql != "BEGIN" {
		t.Errorf("first call should be BEGIN, got %#v", d.calls)
	}
	if d.rollbackCalls != 1 {
		t.Errorf("Rollback should be called once, got %d", d.rollbackCalls)
	}
}

func TestClient_Transaction_PropagatesBodyError(t *testing.T) {
	d := &recordingDriver{}
	c := NewClient(d)

	want := errors.New("body failed")
	got := c.Transaction(context.Background(), func(_ context.Context) error {
		return want
	})
	if !errors.Is(got, want) {
		t.Errorf("got %v, want body error wrapped/equal to %v", got, want)
	}
	// Rollback must still happen.
	if d.rollbackCalls != 1 {
		t.Errorf("Rollback should be called once even on body error, got %d", d.rollbackCalls)
	}
}

func TestClient_Transaction_BodyErrorShadowsRollbackError(t *testing.T) {
	d := &recordingDriver{rollbackErr: errors.New("rollback failed")}
	c := NewClient(d)

	bodyErr := errors.New("body failed")
	got := c.Transaction(context.Background(), func(_ context.Context) error {
		return bodyErr
	})
	// Body error wins — surfacing a rollback error from a
	// doomed transaction would shadow the real error.
	if !errors.Is(got, bodyErr) {
		t.Errorf("got %v, want body error %v", got, bodyErr)
	}
}

func TestClient_Transaction_RollbackErrorSurfacedOnCleanBody(t *testing.T) {
	d := &recordingDriver{rollbackErr: errors.New("rollback failed")}
	c := NewClient(d)

	got := c.Transaction(context.Background(), func(_ context.Context) error {
		return nil
	})
	if got == nil || got.Error() != "rollback failed" {
		t.Errorf("got %v, want rollback failed", got)
	}
}

func TestClient_Transaction_BeginError(t *testing.T) {
	d := &recordingDriver{failAt: map[int]error{0: errors.New("begin failed")}}
	c := NewClient(d)

	called := false
	got := c.Transaction(context.Background(), func(_ context.Context) error {
		called = true
		return nil
	})
	if got == nil || got.Error() != "begin failed" {
		t.Errorf("got %v, want begin failed", got)
	}
	if called {
		t.Error("body must not run when BEGIN fails")
	}
	if d.rollbackCalls != 0 {
		t.Error("Rollback must not run when BEGIN fails")
	}
}

func TestClient_Exec_PassesSQLAndParams(t *testing.T) {
	d := &recordingDriver{}
	c := NewClient(d)

	err := c.Exec(context.Background(), "UPDATE t SET x = $1 WHERE id = $2", 42, "abc")
	if err != nil {
		t.Fatalf("Exec returned error: %v", err)
	}
	if len(d.calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(d.calls))
	}
	if d.calls[0].sql != "UPDATE t SET x = $1 WHERE id = $2" {
		t.Errorf("sql = %q", d.calls[0].sql)
	}
	if len(d.calls[0].params) != 2 || d.calls[0].params[0] != 42 || d.calls[0].params[1] != "abc" {
		t.Errorf("params = %#v", d.calls[0].params)
	}
}

func TestClient_Exec_PropagatesDriverError(t *testing.T) {
	want := errors.New("driver oops")
	d := &recordingDriver{failAt: map[int]error{0: want}}
	c := NewClient(d)

	got := c.Exec(context.Background(), "SELECT 1")
	if !errors.Is(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestClient_FetchAll_ReturnsRows(t *testing.T) {
	d := &recordingDriver{
		respondQueue: []QueryResult{
			{Rows: []map[string]any{
				{"id": int64(1), "tenant_id": "t1"},
				{"id": int64(2), "tenant_id": "t2"},
			}, Command: "SELECT", RowCount: 2},
		},
	}
	c := NewClient(d)

	rows, err := c.FetchAll(context.Background(), "SELECT id, tenant_id FROM t")
	if err != nil {
		t.Fatalf("FetchAll returned error: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("expected 2 rows, got %d", len(rows))
	}
	if rows[0]["tenant_id"] != "t1" {
		t.Errorf("rows[0][tenant_id] = %v, want t1", rows[0]["tenant_id"])
	}
}

func TestClient_FetchAll_PropagatesDriverError(t *testing.T) {
	want := errors.New("driver oops")
	d := &recordingDriver{failAt: map[int]error{0: want}}
	c := NewClient(d)

	_, got := c.FetchAll(context.Background(), "SELECT 1")
	if !errors.Is(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestClient_AsRole_WireSequence_CleanExit_NoClaims(t *testing.T) {
	d := &recordingDriver{
		respondQueue: []QueryResult{
			// Capture row: outer is "postgres" with no claims.
			{Rows: []map[string]any{
				{"current_user": "postgres", "claims": nil},
			}, Command: "SELECT", RowCount: 1},
		},
	}
	c := NewClient(d)

	err := c.AsRole(context.Background(), "app_authenticated", nil, func(_ context.Context) error {
		return nil
	})
	if err != nil {
		t.Fatalf("AsRole returned error: %v", err)
	}

	want := []string{
		`SELECT current_user, current_setting`,
		`SAVEPOINT pgrls_actor_`,
		`SET LOCAL ROLE app_authenticated`,
		`RELEASE SAVEPOINT pgrls_actor_`,
		`SET LOCAL ROLE postgres`,
	}
	if len(d.calls) != len(want) {
		t.Fatalf("expected %d calls, got %d: %#v", len(want), len(d.calls), d.calls)
	}
	for i, prefix := range want {
		if !strings.HasPrefix(d.calls[i].sql, prefix) {
			t.Errorf("call[%d] sql %q does not start with %q", i, d.calls[i].sql, prefix)
		}
	}
}

func TestClient_AsRole_WireSequence_CleanExit_WithClaims(t *testing.T) {
	d := &recordingDriver{
		respondQueue: []QueryResult{
			// Outer is "postgres" with no claims.
			{Rows: []map[string]any{
				{"current_user": "postgres", "claims": nil},
			}, Command: "SELECT", RowCount: 1},
		},
	}
	c := NewClient(d)

	err := c.AsRole(
		context.Background(),
		"app_authenticated",
		&AsRoleOptions{Claims: map[string]any{"sub": "user-a", "tenant_id": "t1"}},
		func(_ context.Context) error { return nil },
	)
	if err != nil {
		t.Fatalf("AsRole returned error: %v", err)
	}

	// Sequence: capture, SAVEPOINT, SET LOCAL ROLE,
	// set_config('request.jwt.claims', JSON, true), RELEASE
	// SAVEPOINT, SET LOCAL ROLE postgres, set_config(...NULL,
	// true).
	if len(d.calls) != 7 {
		t.Fatalf("expected 7 calls, got %d: %#v", len(d.calls), d.calls)
	}
	if !strings.HasPrefix(d.calls[3].sql, "SELECT set_config('request.jwt.claims', $1, true)") {
		t.Errorf("call[3] sql = %q", d.calls[3].sql)
	}
	// Claims JSON arg must contain both fields.
	claimsArg, ok := d.calls[3].params[0].(string)
	if !ok {
		t.Fatalf("claims arg is not a string: %T", d.calls[3].params[0])
	}
	if !strings.Contains(claimsArg, `"sub":"user-a"`) {
		t.Errorf("claims JSON missing sub: %q", claimsArg)
	}
	if !strings.Contains(claimsArg, `"tenant_id":"t1"`) {
		t.Errorf("claims JSON missing tenant_id: %q", claimsArg)
	}
	// Final call clears the GUC.
	if !strings.Contains(d.calls[6].sql, "set_config('request.jwt.claims', NULL, true)") {
		t.Errorf("call[6] sql = %q (expected NULL clear)", d.calls[6].sql)
	}
}

func TestClient_AsRole_WireSequence_CleanExit_RestoresOuterClaims(t *testing.T) {
	d := &recordingDriver{
		respondQueue: []QueryResult{
			// Outer is "alice" with claims JSON already set.
			{Rows: []map[string]any{
				{"current_user": "alice", "claims": `{"sub":"outer"}`},
			}, Command: "SELECT", RowCount: 1},
		},
	}
	c := NewClient(d)

	err := c.AsRole(
		context.Background(),
		"app_authenticated",
		&AsRoleOptions{Claims: map[string]any{"sub": "inner"}},
		func(_ context.Context) error { return nil },
	)
	if err != nil {
		t.Fatalf("AsRole returned error: %v", err)
	}

	// Last call must restore the outer claims (string passed as $1).
	last := d.calls[len(d.calls)-1]
	if !strings.HasPrefix(last.sql, "SELECT set_config('request.jwt.claims', $1, true)") {
		t.Errorf("last call sql = %q, want set_config restore", last.sql)
	}
	if got, _ := last.params[0].(string); got != `{"sub":"outer"}` {
		t.Errorf("restore param = %q, want outer claims JSON", got)
	}
}

func TestClient_AsRole_WireSequence_BodyError_RollsBackSavepoint(t *testing.T) {
	d := &recordingDriver{
		respondQueue: []QueryResult{
			{Rows: []map[string]any{
				{"current_user": "postgres", "claims": nil},
			}, Command: "SELECT", RowCount: 1},
		},
	}
	c := NewClient(d)

	bodyErr := errors.New("body failed")
	got := c.AsRole(
		context.Background(),
		"app_authenticated",
		&AsRoleOptions{Claims: map[string]any{"sub": "user-a"}},
		func(_ context.Context) error { return bodyErr },
	)
	if !errors.Is(got, bodyErr) {
		t.Errorf("got %v, want body error", got)
	}

	// Last call must be ROLLBACK TO SAVEPOINT.
	last := d.calls[len(d.calls)-1]
	if !strings.HasPrefix(last.sql, "ROLLBACK TO SAVEPOINT pgrls_actor_") {
		t.Errorf("last call sql = %q, want ROLLBACK TO SAVEPOINT", last.sql)
	}
	// RELEASE must NOT have been issued on the error path.
	for _, call := range d.calls {
		if strings.HasPrefix(call.sql, "RELEASE SAVEPOINT") {
			t.Errorf("RELEASE SAVEPOINT must not run on body error; call = %q", call.sql)
		}
	}
}

func TestClient_AsRole_QuotesReservedRoleName(t *testing.T) {
	d := &recordingDriver{
		respondQueue: []QueryResult{
			{Rows: []map[string]any{
				{"current_user": "postgres", "claims": nil},
			}, Command: "SELECT", RowCount: 1},
		},
	}
	c := NewClient(d)

	err := c.AsRole(context.Background(), "order", nil, func(_ context.Context) error {
		return nil
	})
	if err != nil {
		t.Fatalf("AsRole returned error: %v", err)
	}

	// The SET LOCAL ROLE call must double-quote the reserved
	// keyword.
	var sawQuotedSet bool
	for _, call := range d.calls {
		if call.sql == `SET LOCAL ROLE "order"` {
			sawQuotedSet = true
			break
		}
	}
	if !sawQuotedSet {
		t.Errorf("did not see `SET LOCAL ROLE \"order\"`; calls = %#v", d.calls)
	}
}

func TestClient_AsRole_QuotesCapturedReservedRole(t *testing.T) {
	// If the captured `current_user` is itself a reserved
	// keyword, the restore must quote it too. Real Postgres
	// never returns a bare reserved keyword from
	// `SELECT current_user` (the system catalog accepts only
	// non-reserved identifiers as role names), but mocks /
	// custom drivers could; pin the defensive behavior.
	d := &recordingDriver{
		respondQueue: []QueryResult{
			{Rows: []map[string]any{
				{"current_user": "order", "claims": nil},
			}, Command: "SELECT", RowCount: 1},
		},
	}
	c := NewClient(d)

	err := c.AsRole(context.Background(), "app", nil, func(_ context.Context) error {
		return nil
	})
	if err != nil {
		t.Fatalf("AsRole returned error: %v", err)
	}

	// Final SET LOCAL ROLE on clean exit must be the quoted form.
	last := d.calls[len(d.calls)-1]
	if last.sql != `SET LOCAL ROLE "order"` {
		t.Errorf("restore sql = %q, want `SET LOCAL ROLE \"order\"`", last.sql)
	}
}

func TestClient_AsRole_InvalidRoleFailsBeforeAnyWire(t *testing.T) {
	d := &recordingDriver{}
	c := NewClient(d)

	err := c.AsRole(context.Background(), "", nil, func(_ context.Context) error {
		t.Error("body must not run on invalid role")
		return nil
	})
	if err == nil {
		t.Fatal("expected error for empty role")
	}
	if !errors.Is(err, ErrAPIError) {
		t.Errorf("error %v does not match ErrAPIError sentinel", err)
	}
	if len(d.calls) != 0 {
		t.Errorf("no driver calls should fire on invalid role; got %d", len(d.calls))
	}
}

func TestClient_AsRole_EmptyClaimsMapIsSent(t *testing.T) {
	// Empty non-nil map => set_config('request.jwt.claims',
	// '{}', true). nil claims => skip set_config entirely.
	d := &recordingDriver{
		respondQueue: []QueryResult{
			{Rows: []map[string]any{
				{"current_user": "postgres", "claims": nil},
			}, Command: "SELECT", RowCount: 1},
		},
	}
	c := NewClient(d)

	err := c.AsRole(
		context.Background(),
		"app",
		&AsRoleOptions{Claims: map[string]any{}},
		func(_ context.Context) error { return nil },
	)
	if err != nil {
		t.Fatalf("AsRole returned error: %v", err)
	}

	// Find the set_config call.
	var saw bool
	for _, call := range d.calls {
		if strings.HasPrefix(call.sql, "SELECT set_config('request.jwt.claims', $1, true)") {
			if got, _ := call.params[0].(string); got == "{}" {
				saw = true
				break
			}
		}
	}
	if !saw {
		t.Errorf("did not see set_config with `{}`; calls = %#v", d.calls)
	}
}

func TestClient_AsRole_NoCaptureRowIsError(t *testing.T) {
	d := &recordingDriver{
		respondQueue: []QueryResult{
			{Rows: nil, Command: "SELECT", RowCount: 0},
		},
	}
	c := NewClient(d)

	err := c.AsRole(context.Background(), "app", nil, func(_ context.Context) error {
		t.Error("body must not run when capture returns no row")
		return nil
	})
	if err == nil {
		t.Fatal("expected error when capture returns no row")
	}
	if !errors.Is(err, ErrAPIError) {
		t.Errorf("error %v does not match ErrAPIError sentinel", err)
	}
}

func TestClient_Seed_EmptyRowsIsNoop(t *testing.T) {
	d := &recordingDriver{}
	c := NewClient(d)

	err := c.Seed(context.Background(), "app.invoices", nil)
	if err != nil {
		t.Fatalf("Seed returned error: %v", err)
	}
	if len(d.calls) != 0 {
		t.Errorf("expected no driver calls; got %d", len(d.calls))
	}
}

func TestClient_Seed_InsertEachRow(t *testing.T) {
	d := &recordingDriver{}
	c := NewClient(d)

	rows := []map[string]any{
		{"tenant_id": "t1", "amount": 100},
		{"tenant_id": "t2", "amount": 200},
	}
	err := c.Seed(context.Background(), "app.invoices", rows)
	if err != nil {
		t.Fatalf("Seed returned error: %v", err)
	}
	if len(d.calls) != 2 {
		t.Fatalf("expected 2 INSERT calls, got %d", len(d.calls))
	}
	// SQL is deterministic across calls — same columns, same
	// placeholders.
	if d.calls[0].sql != d.calls[1].sql {
		t.Errorf("calls have different SQL: %q vs %q", d.calls[0].sql, d.calls[1].sql)
	}
	// Column order is sorted alphabetically.
	expected := `INSERT INTO app.invoices (amount, tenant_id) VALUES ($1, $2)`
	if d.calls[0].sql != expected {
		t.Errorf("call[0] sql = %q, want %q", d.calls[0].sql, expected)
	}
	// Params for the first row.
	if d.calls[0].params[0] != 100 || d.calls[0].params[1] != "t1" {
		t.Errorf("call[0] params = %#v, want [100, t1]", d.calls[0].params)
	}
}

func TestClient_Seed_QuotesReservedTableAndSchema(t *testing.T) {
	d := &recordingDriver{}
	c := NewClient(d)

	rows := []map[string]any{{"select": 1}}
	err := c.Seed(context.Background(), "order.user", rows)
	if err != nil {
		t.Fatalf("Seed returned error: %v", err)
	}
	if len(d.calls) != 1 {
		t.Fatalf("expected 1 INSERT call, got %d", len(d.calls))
	}
	// Both schema and table are reserved, must be quoted.
	// Column `select` is reserved, must be quoted.
	expected := `INSERT INTO "order"."user" ("select") VALUES ($1)`
	if d.calls[0].sql != expected {
		t.Errorf("sql = %q, want %q", d.calls[0].sql, expected)
	}
}

func TestClient_Seed_MismatchedKeysIsError(t *testing.T) {
	d := &recordingDriver{}
	c := NewClient(d)

	rows := []map[string]any{
		{"tenant_id": "t1", "amount": 100},
		{"tenant_id": "t2"}, // missing `amount`
	}
	err := c.Seed(context.Background(), "app.invoices", rows)
	if err == nil {
		t.Fatal("expected error for inconsistent keys")
	}
	if !errors.Is(err, ErrAPIError) {
		t.Errorf("error %v does not match ErrAPIError sentinel", err)
	}
	if len(d.calls) != 0 {
		t.Errorf("no driver calls should fire on inconsistent keys; got %d", len(d.calls))
	}
}

func TestClient_Seed_MismatchedKeysByNameIsError(t *testing.T) {
	// Same key count, different key names: still inconsistent.
	d := &recordingDriver{}
	c := NewClient(d)

	rows := []map[string]any{
		{"tenant_id": "t1", "amount": 100},
		{"tenant_id": "t2", "name": "x"}, // wrong second key
	}
	err := c.Seed(context.Background(), "app.invoices", rows)
	if err == nil {
		t.Fatal("expected error for inconsistent keys by name")
	}
}

func TestClient_Seed_RejectsMultiDotTable(t *testing.T) {
	d := &recordingDriver{}
	c := NewClient(d)

	err := c.Seed(context.Background(), "db.schema.table", []map[string]any{{"x": 1}})
	if err == nil {
		t.Fatal("expected error for multi-dot table name")
	}
	if !errors.Is(err, ErrAPIError) {
		t.Errorf("error %v does not match ErrAPIError sentinel", err)
	}
	if !strings.Contains(err.Error(), "more than one dot") {
		t.Errorf("error %q does not mention multi-dot", err.Error())
	}
}

func TestClient_Seed_UnqualifiedTableQuotedIfReserved(t *testing.T) {
	d := &recordingDriver{}
	c := NewClient(d)

	err := c.Seed(context.Background(), "user", []map[string]any{{"x": 1}})
	if err != nil {
		t.Fatalf("Seed returned error: %v", err)
	}
	// Unqualified reserved table → quoted.
	if !regexp.MustCompile(`^INSERT INTO "user" \(.+\) VALUES \(.+\)$`).MatchString(d.calls[0].sql) {
		t.Errorf("sql = %q, want quoted user", d.calls[0].sql)
	}
}

func TestClient_Close_ForwardsToCloser(t *testing.T) {
	d := &recordingDriver{}
	c := NewClient(d)

	if err := c.Close(context.Background()); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}
	if d.closeCalls != 1 {
		t.Errorf("Close should be called once, got %d", d.closeCalls)
	}
}

func TestClient_Close_NoopWhenNotCloser(t *testing.T) {
	d := &noCloserDriver{}
	c := NewClient(d)

	// Must not panic, must return nil.
	if err := c.Close(context.Background()); err != nil {
		t.Errorf("Close on non-Closer driver should return nil, got %v", err)
	}
}

func TestClient_Close_PropagatesCloserError(t *testing.T) {
	want := errors.New("close failed")
	d := &recordingDriver{closeErr: want}
	c := NewClient(d)

	got := c.Close(context.Background())
	if !errors.Is(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestClient_Driver_ReturnsUnderlying(t *testing.T) {
	d := &recordingDriver{}
	c := NewClient(d)

	if c.Driver() != d {
		t.Error("Driver() must return the underlying driver instance")
	}
}

func TestClient_AsRole_ReleaseSavepointErrorOnCleanExitSurfacedToCaller(t *testing.T) {
	// Defensive: if the RELEASE SAVEPOINT call fails on clean
	// exit, the error must reach the caller — without this, a
	// leaked savepoint would silently accumulate (PostgreSQL
	// allows nested savepoints, but the transaction-wide
	// state-bloat is a real problem).
	d := &recordingDriver{
		respondQueue: []QueryResult{
			{Rows: []map[string]any{{"current_user": "postgres", "claims": nil}}, Command: "SELECT"},
		},
		// Call indices: 0=SELECT capture, 1=SAVEPOINT,
		// 2=SET LOCAL ROLE, 3=RELEASE SAVEPOINT (fails here),
		// then we never reach 4 (restore SET LOCAL).
		failAt: map[int]error{3: errors.New("release failed")},
	}
	c := NewClient(d)

	err := c.AsRole(context.Background(), "app", nil, func(_ context.Context) error {
		return nil
	})
	if err == nil {
		t.Fatal("expected RELEASE SAVEPOINT error to surface")
	}
	if !strings.Contains(err.Error(), "release failed") {
		t.Errorf("error %v does not mention release failure", err)
	}
}

// TestClient_AsRole_SavepointNamesFreshAcrossCalls pins that
// each AsRole invocation uses a fresh savepoint name. Without
// fresh names, nested AsRole calls would step on each other (the
// inner RELEASE would close the outer's savepoint scope, or
// PostgreSQL would reject the duplicate name).
func TestClient_AsRole_SavepointNamesFreshAcrossCalls(t *testing.T) {
	d := &recordingDriver{
		respondQueue: []QueryResult{
			{Rows: []map[string]any{{"current_user": "postgres", "claims": nil}}, Command: "SELECT"},
			{Rows: []map[string]any{{"current_user": "postgres", "claims": nil}}, Command: "SELECT"},
		},
	}
	c := NewClient(d)

	for i := 0; i < 2; i++ {
		err := c.AsRole(context.Background(), "app", nil, func(_ context.Context) error {
			return nil
		})
		if err != nil {
			t.Fatalf("AsRole iter %d: %v", i, err)
		}
	}

	// Collect all SAVEPOINT calls and assert they're distinct.
	var names []string
	for _, call := range d.calls {
		if strings.HasPrefix(call.sql, "SAVEPOINT pgrls_actor_") {
			names = append(names, strings.TrimPrefix(call.sql, "SAVEPOINT "))
		}
	}
	if len(names) != 2 {
		t.Fatalf("expected 2 SAVEPOINTs, got %d", len(names))
	}
	if names[0] == names[1] {
		t.Errorf("SAVEPOINT names must be distinct, got %q twice", names[0])
	}
}

// Compile-time pin: *Client embeds the right shapes. A future
// signature change to Driver / Closer breaks this file's
// compilation rather than just an individual assertion.
var (
	_ Driver = (*recordingDriver)(nil)
	_ Closer = (*recordingDriver)(nil)
	_ Driver = (*noCloserDriver)(nil)
)

