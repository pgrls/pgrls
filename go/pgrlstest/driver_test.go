package pgrlstest

import (
	"context"
	"errors"
	"testing"
)

// fakeDriver is a hand-rolled in-memory Driver used to exercise
// the interface contract without spinning up a real Postgres.
// The pgx and lib/pq adapter implementations land in step 3
// (v0.7.2); this file's job is purely to lock the interface
// shape so step 3 has a concrete contract to mirror.
type fakeDriver struct {
	queryFn     func(ctx context.Context, sql string, params ...any) (QueryResult, error)
	rollbackFn  func(ctx context.Context) error
	privilegeFn func(err error) bool
}

func (f *fakeDriver) Query(ctx context.Context, sql string, params ...any) (QueryResult, error) {
	if f.queryFn != nil {
		return f.queryFn(ctx, sql, params...)
	}
	return QueryResult{}, nil
}

func (f *fakeDriver) Rollback(ctx context.Context) error {
	if f.rollbackFn != nil {
		return f.rollbackFn(ctx)
	}
	return nil
}

func (f *fakeDriver) IsInsufficientPrivilege(err error) bool {
	if f.privilegeFn != nil {
		return f.privilegeFn(err)
	}
	return false
}

// fakeDriverWithClose adds the optional `Close` method, used to
// pin the Closer type-assertion pattern callers use.
type fakeDriverWithClose struct {
	fakeDriver
	closeFn func(ctx context.Context) error
}

func (f *fakeDriverWithClose) Close(ctx context.Context) error {
	if f.closeFn != nil {
		return f.closeFn(ctx)
	}
	return nil
}

func TestDriver_QueryResultZeroValueIsUsable(t *testing.T) {
	// The zero `QueryResult` should compile and behave like
	// "no rows, no command, zero count" — useful for drivers
	// to return on no-op operations without constructing a
	// fresh struct.
	var qr QueryResult
	if qr.Rows != nil {
		t.Errorf("zero Rows should be nil, got %v", qr.Rows)
	}
	if qr.Command != "" {
		t.Errorf("zero Command should be empty, got %q", qr.Command)
	}
	if qr.RowCount != 0 {
		t.Errorf("zero RowCount should be 0, got %d", qr.RowCount)
	}
}

func TestDriver_QueryResultCanHoldRows(t *testing.T) {
	// Pin the row shape: string-keyed maps, ANY values. A
	// future API change that constrains the value type
	// (e.g. to `string`) would silently break user code; the
	// `any` shape matches what the TS and Python ports
	// expose.
	qr := QueryResult{
		Rows: []map[string]any{
			{"id": 1, "name": "alice"},
			{"id": 2, "name": "bob"},
		},
		Command:  "SELECT",
		RowCount: 2,
	}
	if len(qr.Rows) != 2 {
		t.Fatalf("expected 2 rows, got %d", len(qr.Rows))
	}
	if qr.Rows[0]["name"] != "alice" {
		t.Errorf("Rows[0][name] = %v, want alice", qr.Rows[0]["name"])
	}
}

func TestDriver_InterfaceSatisfiedByFake(t *testing.T) {
	// Compile-time assertion: any *fakeDriver is a Driver.
	// If a future refactor adds a method to the Driver
	// interface, this assignment fails to compile and the
	// breakage is caught at build time. (Go's standard
	// pattern for pinning interface satisfaction.)
	var _ Driver = (*fakeDriver)(nil)
	var _ Driver = (*fakeDriverWithClose)(nil)
}

func TestDriver_OptionalCloserNotImplementedByBaseDriver(t *testing.T) {
	// A plain *fakeDriver does NOT satisfy Closer. The type
	// assertion the client will use must return ok=false so
	// the no-op branch fires for drivers without explicit
	// teardown (e.g. a future *sql.DB-backed adapter).
	var d Driver = &fakeDriver{}
	_, ok := d.(Closer)
	if ok {
		t.Error("*fakeDriver should NOT satisfy Closer (no Close method)")
	}
}

func TestDriver_OptionalCloserImplementedByExtendedDriver(t *testing.T) {
	// The fakeDriverWithClose embeds *fakeDriver and adds
	// Close — it must satisfy BOTH Driver and Closer. This
	// pins the type-assertion pattern the client uses:
	// `if c, ok := driver.(Closer); ok { c.Close(ctx) }`.
	var d Driver = &fakeDriverWithClose{}
	c, ok := d.(Closer)
	if !ok {
		t.Fatal("*fakeDriverWithClose should satisfy Closer")
	}
	if err := c.Close(context.Background()); err != nil {
		t.Errorf("Close() returned unexpected error: %v", err)
	}
}

func TestDriver_QueryCalledWithContextAndParams(t *testing.T) {
	// Sanity: the Driver.Query signature accepts a context and
	// variadic params, and the params reach the implementation.
	// Pin the variadic shape so a future refactor to
	// `params []any` (slice, not variadic) breaks this test
	// rather than silently changing the call sites in steps 4/5.
	captured := struct {
		ctx    context.Context
		sql    string
		params []any
	}{}
	d := &fakeDriver{
		queryFn: func(ctx context.Context, sql string, params ...any) (QueryResult, error) {
			captured.ctx = ctx
			captured.sql = sql
			captured.params = params
			return QueryResult{Command: "SELECT"}, nil
		},
	}
	ctx := context.Background()
	_, err := d.Query(ctx, "SELECT $1::int, $2::text", 42, "x")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if captured.sql != "SELECT $1::int, $2::text" {
		t.Errorf("sql captured incorrectly: %q", captured.sql)
	}
	if len(captured.params) != 2 || captured.params[0] != 42 || captured.params[1] != "x" {
		t.Errorf("params captured incorrectly: %v", captured.params)
	}
}

func TestDriver_IsInsufficientPrivilegeDelegatesToImpl(t *testing.T) {
	// The predicate must hide the underlying driver's error
	// shape; adapters implement it differently (pgx uses
	// `*pgconn.PgError`, lib/pq uses `*pq.Error`). Pin the
	// boolean-returning contract here; step 3 adapters supply
	// real implementations.
	d := &fakeDriver{
		privilegeFn: func(err error) bool {
			// Adapters should map nil → false — there's
			// nothing to classify. This fake mirrors the
			// real-adapter contract documented on
			// `Driver.IsInsufficientPrivilege`.
			if err == nil {
				return false
			}
			return err.Error() == "rls denied"
		},
	}
	if !d.IsInsufficientPrivilege(errors.New("rls denied")) {
		t.Error("expected true for rls-denied input")
	}
	if d.IsInsufficientPrivilege(errors.New("other")) {
		t.Error("expected false for non-rls input")
	}
	if d.IsInsufficientPrivilege(nil) {
		t.Error("expected false for nil input")
	}
}

func TestDriver_RollbackContextPropagates(t *testing.T) {
	// Context cancellation must reach the Rollback impl —
	// adapters use it to honor timeouts on shutdown / panic
	// recovery paths. Pin the contract.
	type key string
	ctx := context.WithValue(context.Background(), key("trace"), "v0.7.1")
	d := &fakeDriver{
		rollbackFn: func(ctx context.Context) error {
			if ctx.Value(key("trace")) != "v0.7.1" {
				return errors.New("context value not propagated")
			}
			return nil
		},
	}
	if err := d.Rollback(ctx); err != nil {
		t.Errorf("Rollback failed to propagate context: %v", err)
	}
}
