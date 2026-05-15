package pgrlstest_test

// Cross-language Layer 1 conformance suite — the Go port of the
// TypeScript `ts/test/conformance/*.conformance.test.ts` files
// and the Python `tests/protocol/test_protocol_conformance.py`
// suite.
//
// `TestMain` boots one Postgres testcontainer
// (`postgres:17-alpine`) shared by `TestConformance_PgxAdapter`
// and `TestConformance_PqAdapter`, applies the cross-language
// fixture, then dispatches both adapter tests. Each subtest
// opens its own `Client.Transaction` and rolls back at the
// end, so the fixture is preserved across tests; per-subtest
// isolation lives at the `BEGIN`/`ROLLBACK` boundary, and
// per-`AsRole` nesting layered on top of that lives at the
// savepoint layer (matches the TS `beforeAll` strategy and
// amortizes the ~3-5s container startup over the conformance
// matrix).
//
// Subtest coverage per adapter:
//   - 4 Layer 1 criteria (`SET LOCAL ROLE` reset on rollback,
//     `set_config(..., true)` reset on rollback,
//     `InsufficientPrivilege` for `AssertRejected`, silent-drop
//     for `AssertSilentlyDropped`).
//   - 9 end-to-end public-API exercises (multi-tenant isolation,
//     nested AsRole restoring outer claims, AsRole with nil
//     claims skipping set_config, Seed + AssertRows, the
//     AssertSilentlyDropped verb-gate on a real driver,
//     AssertRejected returning *AssertionError on success,
//     AssertVisible + AssertInvisible against the
//     tenant-isolation fixture, plus two additional AsRole
//     nested-restore cases — case 4 (inner-no-claims preserves
//     outer) and case 2 (inner-on-empty-outer clears on exit
//     via explicit `set_config(NULL, true)`)).
//
// Total: 13 subtests per adapter × 2 adapters = 26 conformance
// subtests against real Postgres.
//
// Fixture source: the Go port reads the same
// `tests/protocol/{schema,seed}.sql` files the Python
// conformance suite (`tests/protocol/test_protocol_conformance.py`)
// consumes — Python ↔ Go fixture sharing. The TypeScript port
// hand-rolls its own `FIXTURE_SQL` in `ts/test/conformance/
// _helpers.ts` covering the same four Layer 1 criteria; that
// divergence is a deliberate fork-in-the-road documented in
// `AGENTS.md` (which lists three valid patterns: manifest reuse,
// full hand-roll, and this Go hybrid).
//
// Docker availability: when any setup step fails (Docker not
// reachable, image pull / port-allocation rejection, DSN
// derivation, `sql.Open`, or fixture install), `TestMain`
// swallows the error to stderr, leaves `containerDSN` empty,
// and both `TestConformance_*` parent tests Skip on entry via
// `skipUnlessDocker`. The package's other unit tests stay
// runnable in Docker-less environments — only this file's
// tests opt out.

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/lib/pq"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/pgrls/pgrls/go/pgrlstest"
	pgxdriver "github.com/pgrls/pgrls/go/pgrlstest/drivers/pgx"
	pqdriver "github.com/pgrls/pgrls/go/pgrlstest/drivers/pq"
)

// containerDSN is set by TestMain when Docker is available;
// otherwise the conformance tests Skip on entry.
var containerDSN string

func TestMain(m *testing.M) {
	os.Exit(runTestMain(m))
}

// runTestMain is the body of TestMain extracted so deferred
// cleanups (container terminate, sql.DB close, context
// cancel) actually run — os.Exit terminates without invoking
// deferred functions, so the cleanup has to happen before the
// final `return code`.
func runTestMain(m *testing.M) int {
	// `testing.Short()` reads a flag that must be parsed first;
	// in TestMain the parse hasn't happened yet, so call it
	// explicitly. `go test` at this stage has already
	// registered the testing flags via testdeps; `flag.Parse()`
	// alone is enough.
	flag.Parse()

	if testing.Short() {
		// `-short` skips the conformance suite even when Docker
		// is available — useful for local iteration where you
		// don't want to wait for the testcontainer startup.
		return m.Run()
	}

	// Local-dev shortcut: if `PGRLS_CONFORMANCE_DSN` is set,
	// trust the caller has pointed it at a Postgres reachable
	// from the test process. Skips testcontainers entirely.
	// CI uses the testcontainers path; the env-var fallback is
	// for developers running `go test` inside a Docker harness
	// where testcontainers' default host-bridge address won't
	// route between sibling containers.
	if dsn := os.Getenv("PGRLS_CONFORMANCE_DSN"); dsn != "" {
		if err := setupConformanceFromDSN(dsn); err != nil {
			fmt.Fprintf(os.Stderr, "[conformance] fixture install from PGRLS_CONFORMANCE_DSN failed; "+
				"conformance tests will skip: %v\n", err)
			return m.Run()
		}
		// Set containerDSN only AFTER successful fixture
		// install; if install fails we leave it empty so
		// `skipUnlessDocker` routes the subtests to t.Skip
		// instead of running them against an unprepared DB.
		containerDSN = dsn
		return m.Run()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	pg, err := tcpostgres.Run(
		ctx,
		"postgres:17-alpine",
		tcpostgres.WithDatabase("pgrls_conformance"),
		tcpostgres.WithUsername("pgrls"),
		tcpostgres.WithPassword("pgrls"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(60*time.Second),
		),
	)
	if err != nil {
		// Docker unavailable or container start failed; the
		// rest of the suite still runs with conformance tests
		// skipping individually (containerDSN stays empty).
		fmt.Fprintf(os.Stderr, "[conformance] testcontainer startup failed; "+
			"conformance tests will skip: %v\n", err)
		return m.Run()
	}
	defer func() {
		// Explicit teardown — Ryuk reaps leaked containers in
		// the default config, but disabling Ryuk (some Docker-
		// in-Docker harnesses) requires us to terminate
		// ourselves. Deferred so a failure later in setup still
		// runs the cleanup.
		_ = pg.Terminate(context.Background())
	}()

	dsn, err := pg.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		fmt.Fprintf(os.Stderr, "[conformance] could not derive DSN: %v\n", err)
		return m.Run()
	}

	// Apply the cross-language fixture schema before any test
	// runs so every conformance test sees the same starting
	// state. Use lib/pq to install — picks no fight with pgx's
	// connection pooling for the setup statement.
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[conformance] sql.Open failed: %v\n", err)
		return m.Run()
	}
	defer db.Close()

	if err := applyFixtureSQL(ctx, db); err != nil {
		fmt.Fprintf(os.Stderr, "[conformance] fixture install failed: %v\n", err)
		// containerDSN stays empty so subtests skip rather
		// than run against an unprepared DB.
		return m.Run()
	}
	// Set containerDSN only AFTER successful fixture install
	// (same rationale as the env-var path above).
	containerDSN = dsn

	return m.Run()
}

// setupConformanceFromDSN installs the protocol-conformance
// schema + seed against the DSN supplied via env. Used by the
// `PGRLS_CONFORMANCE_DSN` env-var path in TestMain.
func setupConformanceFromDSN(dsn string) error {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return fmt.Errorf("sql.Open: %w", err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return applyFixtureSQL(ctx, db)
}

// fixtureTeardownSQL is run before applying the schema so the
// fixture install stays idempotent under re-runs against a
// persistent database (the `PGRLS_CONFORMANCE_DSN` path against
// a developer-supplied Postgres). The testcontainers path
// always gets a fresh container so the teardown is a no-op
// there. Order matters: drop dependent objects first.
const fixtureTeardownSQL = `
DROP TABLE IF EXISTS protocol_invoices CASCADE;
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'pgrls_protocol_actor') THEN
    EXECUTE 'REVOKE ALL ON SCHEMA public FROM pgrls_protocol_actor';
    -- DROP OWNED BY catches any lingering default-priv grants
    -- from prior runs; safe no-op when the role owns nothing.
    EXECUTE 'DROP OWNED BY pgrls_protocol_actor';
    EXECUTE 'DROP ROLE pgrls_protocol_actor';
  END IF;
END $$;
`

// applyFixtureSQL installs the protocol-conformance schema +
// seed against the freshly-booted container. The shared
// fixture lives at `tests/protocol/{schema,seed}.sql` — the
// same files the Python conformance suite reads. The Go suite
// reads the files at runtime rather than embedding them so a
// single edit propagates to both Python and Go conformance
// runs without recompilation; the TypeScript port maintains
// its own `FIXTURE_SQL` in `ts/test/conformance/_helpers.ts`.
func applyFixtureSQL(ctx context.Context, db *sql.DB) error {
	// Make the install idempotent for the env-var path; a
	// no-op (no existing schema) for the testcontainers path.
	if _, err := db.ExecContext(ctx, fixtureTeardownSQL); err != nil {
		return fmt.Errorf("teardown stale fixture: %w", err)
	}
	// Locate the fixture relative to this file's location
	// rather than the test process cwd. `go test` runs with
	// cwd = package dir; the fixture at
	// `<repo>/tests/protocol/` is reached by two `..` segments
	// (pgrlstest → go → repo-root, then into tests/protocol).
	// `runtime.Caller(0)` keeps the suite robust against
	// re-locating the test file or running it from a different
	// working directory.
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return errors.New("runtime.Caller(0) unavailable; can't locate fixture files")
	}
	thisDir := filepath.Dir(thisFile)
	fixtureDir := filepath.Join(thisDir, "..", "..", "tests", "protocol")
	for _, name := range []string{"schema.sql", "seed.sql"} {
		fixturePath := filepath.Join(fixtureDir, name)
		data, err := os.ReadFile(fixturePath)
		if err != nil {
			return fmt.Errorf("read %s: %w", fixturePath, err)
		}
		if _, err := db.ExecContext(ctx, string(data)); err != nil {
			return fmt.Errorf("apply %s: %w", fixturePath, err)
		}
	}
	return nil
}

// skipUnlessDocker fast-skips when TestMain couldn't boot a
// container. Every conformance test calls this on entry.
func skipUnlessDocker(t *testing.T) {
	t.Helper()
	if containerDSN == "" {
		t.Skip("Postgres testcontainer unavailable (Docker not reachable?); see TestMain output")
	}
}

// newPgxClient builds a Client over the pgx adapter against
// the conformance container's DSN. Each conformance test gets
// its own pool so tests don't share connection state.
//
// The cleanup closes the *Client first (which releases the
// pgx-adapter's pinned connection back to the pool via the
// `Closer` interface) and then closes the pool. Closing in the
// other order would hang: `pgxpool.Pool.Close()` waits for all
// outstanding acquisitions to be returned, and the adapter
// holds one until its `Close(ctx)` runs.
func newPgxClient(t *testing.T) (*pgrlstest.Client, func()) {
	t.Helper()
	skipUnlessDocker(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, containerDSN)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	c := pgrlstest.NewClient(pgxdriver.Pool(pool))
	cleanup := func() {
		_ = c.Close(context.Background())
		pool.Close()
	}
	return c, cleanup
}

// newPqClient builds a Client over the lib/pq adapter against
// the conformance container's DSN.
//
// Same cleanup-ordering rule as newPgxClient: close the
// *Client first (releases the adapter's pinned *sql.Conn back
// to the *sql.DB pool), then close the *sql.DB.
func newPqClient(t *testing.T) (*pgrlstest.Client, func()) {
	t.Helper()
	skipUnlessDocker(t)

	db, err := sql.Open("postgres", containerDSN)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	c := pgrlstest.NewClient(pqdriver.DB(db))
	cleanup := func() {
		_ = c.Close(context.Background())
		_ = db.Close()
	}
	return c, cleanup
}

// runConformance runs the shared Layer 1 conformance matrix
// against the given Client. Each criterion is its own t.Run
// subtest so the failures point at the right criterion.
func runConformance(t *testing.T, c *pgrlstest.Client) {
	ctx := context.Background()

	t.Run("Criterion1_SetLocalRoleResetsOnRollback", func(t *testing.T) {
		// `SET LOCAL ROLE x` inside a transaction reverts on
		// ROLLBACK. This is the foundation of the
		// savepoint-per-actor protocol.
		var beforeRows []map[string]any
		var err error
		beforeRows, err = c.FetchAll(ctx, "SELECT current_user")
		if err != nil {
			t.Fatalf("capture current_user before: %v", err)
		}
		beforeUser := coerceString(t, beforeRows[0]["current_user"])

		err = c.Transaction(ctx, func(ctx context.Context) error {
			if err := c.Exec(ctx, "SET LOCAL ROLE pgrls_protocol_actor"); err != nil {
				return err
			}
			rows, err := c.FetchAll(ctx, "SELECT current_user")
			if err != nil {
				return err
			}
			got := coerceString(t, rows[0]["current_user"])
			if got != "pgrls_protocol_actor" {
				t.Errorf("inside-tx current_user = %q, want pgrls_protocol_actor", got)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("Transaction returned error: %v", err)
		}

		afterRows, err := c.FetchAll(ctx, "SELECT current_user")
		if err != nil {
			t.Fatalf("capture current_user after: %v", err)
		}
		afterUser := coerceString(t, afterRows[0]["current_user"])
		if afterUser != beforeUser {
			t.Errorf("after-tx current_user = %q, want %q (rollback failed to reset role)", afterUser, beforeUser)
		}
	})

	t.Run("Criterion2_SetConfigResetsOnRollback", func(t *testing.T) {
		// `set_config('request.jwt.claims', …, true)` inside
		// a transaction reverts on ROLLBACK.
		err := c.Transaction(ctx, func(ctx context.Context) error {
			if err := c.Exec(
				ctx,
				"SELECT set_config('request.jwt.claims', $1, true)",
				`{"tenant_id":"t-conf"}`,
			); err != nil {
				return err
			}
			rows, err := c.FetchAll(
				ctx,
				"SELECT current_setting('request.jwt.claims', true) AS claims",
			)
			if err != nil {
				return err
			}
			got := coerceString(t, rows[0]["claims"])
			if !strings.Contains(got, "t-conf") {
				t.Errorf("inside-tx claims = %q, want to contain t-conf", got)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("Transaction: %v", err)
		}

		afterRows, err := c.FetchAll(ctx, "SELECT current_setting('request.jwt.claims', true) AS claims")
		if err != nil {
			t.Fatalf("capture claims after: %v", err)
		}
		afterClaims := coerceString(t, afterRows[0]["claims"])
		if afterClaims != "" {
			t.Errorf("after-tx claims = %q, want empty (rollback failed to clear GUC)", afterClaims)
		}
	})

	t.Run("Criterion3_InsufficientPrivilegeOnPolicyViolation", func(t *testing.T) {
		// A WITH CHECK violation under RLS surfaces as SQLSTATE
		// 42501 — AssertRejected catches it.
		err := c.Transaction(ctx, func(ctx context.Context) error {
			return c.AsRole(ctx, "pgrls_protocol_actor",
				&pgrlstest.AsRoleOptions{Claims: map[string]any{"tenant_id": "tenant-a"}},
				func(ctx context.Context) error {
					// tenant-a tries to insert a tenant-b row →
					// WITH CHECK fails → 42501.
					return c.AssertRejected(
						ctx,
						"INSERT INTO protocol_invoices (tenant_id, amount) VALUES ('tenant-b', 999)",
					)
				})
		})
		if err != nil {
			t.Errorf("Transaction with AssertRejected returned: %v", err)
		}
	})

	t.Run("Criterion4_SilentDropOnUpdateReturning", func(t *testing.T) {
		// UPDATE … RETURNING returns 0 rows when USING filters
		// them all out.
		err := c.Transaction(ctx, func(ctx context.Context) error {
			return c.AsRole(ctx, "pgrls_protocol_actor",
				&pgrlstest.AsRoleOptions{Claims: map[string]any{"tenant_id": "tenant-a"}},
				func(ctx context.Context) error {
					// tenant-a can't see tenant-b rows; UPDATE
					// where tenant_id = 'tenant-b' returns 0
					// rows after USING filters.
					return c.AssertSilentlyDropped(
						ctx,
						"UPDATE protocol_invoices SET amount = 0 WHERE tenant_id = 'tenant-b' RETURNING id",
					)
				})
		})
		if err != nil {
			t.Errorf("Transaction with AssertSilentlyDropped returned: %v", err)
		}
	})

	t.Run("PublicAPI_TenantIsolation", func(t *testing.T) {
		// End-to-end: tenant-a sees exactly 2 rows (per
		// fixture seed); tenant-b sees 3.
		err := c.Transaction(ctx, func(ctx context.Context) error {
			if err := c.AsRole(ctx, "pgrls_protocol_actor",
				&pgrlstest.AsRoleOptions{Claims: map[string]any{"tenant_id": "tenant-a"}},
				func(ctx context.Context) error {
					return c.AssertRows(
						ctx,
						"SELECT id FROM protocol_invoices",
						&pgrlstest.AssertRowsOptions{Count: 2},
					)
				}); err != nil {
				return err
			}
			return c.AsRole(ctx, "pgrls_protocol_actor",
				&pgrlstest.AsRoleOptions{Claims: map[string]any{"tenant_id": "tenant-b"}},
				func(ctx context.Context) error {
					return c.AssertRows(
						ctx,
						"SELECT id FROM protocol_invoices",
						&pgrlstest.AssertRowsOptions{Count: 3},
					)
				})
		})
		if err != nil {
			t.Errorf("Transaction: %v", err)
		}
	})

	t.Run("PublicAPI_NestedAsRoleRestoresOuterClaims", func(t *testing.T) {
		err := c.Transaction(ctx, func(ctx context.Context) error {
			return c.AsRole(ctx, "pgrls_protocol_actor",
				&pgrlstest.AsRoleOptions{Claims: map[string]any{"tenant_id": "outer"}},
				func(ctx context.Context) error {
					if err := c.AsRole(ctx, "pgrls_protocol_actor",
						&pgrlstest.AsRoleOptions{Claims: map[string]any{"tenant_id": "inner"}},
						func(ctx context.Context) error {
							rows, err := c.FetchAll(ctx, "SELECT current_setting('request.jwt.claims', true) AS claims")
							if err != nil {
								return err
							}
							got := coerceString(t, rows[0]["claims"])
							if !strings.Contains(got, "inner") {
								t.Errorf("inner claims = %q, want to contain inner", got)
							}
							return nil
						}); err != nil {
						return err
					}
					rows, err := c.FetchAll(ctx, "SELECT current_setting('request.jwt.claims', true) AS claims")
					if err != nil {
						return err
					}
					got := coerceString(t, rows[0]["claims"])
					if !strings.Contains(got, "outer") {
						t.Errorf("post-inner outer claims = %q, want to contain outer", got)
					}
					return nil
				})
		})
		if err != nil {
			t.Errorf("Transaction: %v", err)
		}
	})

	t.Run("PublicAPI_AsRoleNoClaimsSkipsSetConfig", func(t *testing.T) {
		// `Claims: nil` skips set_config; the role-switch
		// alone exercises SET LOCAL ROLE without touching the
		// GUC.
		err := c.Transaction(ctx, func(ctx context.Context) error {
			return c.AsRole(ctx, "pgrls_protocol_actor", nil,
				func(ctx context.Context) error {
					rows, err := c.FetchAll(ctx, "SELECT current_user")
					if err != nil {
						return err
					}
					got := coerceString(t, rows[0]["current_user"])
					if got != "pgrls_protocol_actor" {
						t.Errorf("current_user under AsRole = %q, want pgrls_protocol_actor", got)
					}
					guc, err := c.FetchAll(ctx, "SELECT current_setting('request.jwt.claims', true) AS claims")
					if err != nil {
						return err
					}
					claims := coerceString(t, guc[0]["claims"])
					if claims != "" {
						t.Errorf("claims GUC = %q, want empty (set_config skipped)", claims)
					}
					return nil
				})
		})
		if err != nil {
			t.Errorf("Transaction: %v", err)
		}
	})

	t.Run("PublicAPI_SeedAndAssertRows", func(t *testing.T) {
		err := c.Transaction(ctx, func(ctx context.Context) error {
			// Seed a few rows in protocol_invoices as the admin
			// connection (the transaction will roll back anyway).
			if err := c.Seed(ctx, "protocol_invoices", []map[string]any{
				{"tenant_id": "tenant-seed-1", "amount": 11},
				{"tenant_id": "tenant-seed-1", "amount": 22},
			}); err != nil {
				return err
			}
			return c.AsRole(ctx, "pgrls_protocol_actor",
				&pgrlstest.AsRoleOptions{Claims: map[string]any{"tenant_id": "tenant-seed-1"}},
				func(ctx context.Context) error {
					return c.AssertRows(
						ctx,
						"SELECT id FROM protocol_invoices WHERE tenant_id = 'tenant-seed-1'",
						&pgrlstest.AssertRowsOptions{Count: 2},
					)
				})
		})
		if err != nil {
			t.Errorf("Transaction: %v", err)
		}
	})

	t.Run("PublicAPI_AssertSilentlyDroppedRejectsSelect", func(t *testing.T) {
		// Verb-gate contract on a real driver: SELECT must
		// produce a misuse error (*Error / ErrAPIError).
		err := c.Transaction(ctx, func(ctx context.Context) error {
			got := c.AssertSilentlyDropped(ctx, "SELECT 1 AS x FROM protocol_invoices")
			if got == nil {
				t.Error("AssertSilentlyDropped on SELECT should return misuse error")
				return nil
			}
			if !errors.Is(got, pgrlstest.ErrAPIError) {
				t.Errorf("misuse error %v does not match ErrAPIError", got)
			}
			return nil
		})
		if err != nil {
			t.Errorf("Transaction: %v", err)
		}
	})

	t.Run("PublicAPI_AssertRejectedFailsOnSuccess", func(t *testing.T) {
		// AssertRejected against a SELECT that succeeds must
		// return AssertionError (matches ErrAssertion).
		err := c.Transaction(ctx, func(ctx context.Context) error {
			return c.AsRole(ctx, "pgrls_protocol_actor",
				&pgrlstest.AsRoleOptions{Claims: map[string]any{"tenant_id": "tenant-a"}},
				func(ctx context.Context) error {
					got := c.AssertRejected(ctx, "SELECT 1 AS x")
					if got == nil {
						t.Error("AssertRejected on succeeding SELECT should return AssertionError")
						return nil
					}
					if !errors.Is(got, pgrlstest.ErrAssertion) {
						t.Errorf("error %v does not match ErrAssertion", got)
					}
					return nil
				})
		})
		if err != nil {
			t.Errorf("Transaction: %v", err)
		}
	})

	t.Run("PublicAPI_AssertVisibleAndAssertInvisible", func(t *testing.T) {
		// End-to-end exercise of AssertVisible + AssertInvisible
		// on real Postgres under tenant isolation. tenant-a sees
		// its own row (Visible); tenant-a does NOT see a
		// tenant-b row (Invisible).
		err := c.Transaction(ctx, func(ctx context.Context) error {
			return c.AsRole(ctx, "pgrls_protocol_actor",
				&pgrlstest.AsRoleOptions{Claims: map[string]any{"tenant_id": "tenant-a"}},
				func(ctx context.Context) error {
					if err := c.AssertVisible(
						ctx,
						"SELECT id FROM protocol_invoices WHERE tenant_id = 'tenant-a'",
					); err != nil {
						return fmt.Errorf("AssertVisible on tenant-a: %w", err)
					}
					return c.AssertInvisible(
						ctx,
						"SELECT id FROM protocol_invoices WHERE tenant_id = 'tenant-b'",
					)
				})
		})
		if err != nil {
			t.Errorf("Transaction: %v", err)
		}
	})

	t.Run("PublicAPI_NestedAsRoleInnerNoClaimsPreservesOuter", func(t *testing.T) {
		// AsRole restore case 4 (TS parity): outer sets claims,
		// inner passes nil claims. On inner exit, outer claims
		// must still be active — the protocol doesn't issue
		// set_config(NULL, true) on the inner-no-claims path, so
		// the outer's set_config value persists (set_config
		// scope is transaction-local).
		err := c.Transaction(ctx, func(ctx context.Context) error {
			return c.AsRole(ctx, "pgrls_protocol_actor",
				&pgrlstest.AsRoleOptions{Claims: map[string]any{"tenant_id": "outer"}},
				func(ctx context.Context) error {
					if err := c.AsRole(ctx, "pgrls_protocol_actor", nil,
						func(ctx context.Context) error {
							// Inner didn't set claims; outer value
							// persists because set_config is
							// transaction-local.
							rows, err := c.FetchAll(ctx, "SELECT current_setting('request.jwt.claims', true) AS claims")
							if err != nil {
								return err
							}
							got := coerceString(t, rows[0]["claims"])
							if !strings.Contains(got, "outer") {
								t.Errorf("inner-no-claims block sees claims = %q, want to contain outer", got)
							}
							return nil
						}); err != nil {
						return err
					}
					rows, err := c.FetchAll(ctx, "SELECT current_setting('request.jwt.claims', true) AS claims")
					if err != nil {
						return err
					}
					got := coerceString(t, rows[0]["claims"])
					if !strings.Contains(got, "outer") {
						t.Errorf("post-inner outer claims = %q, want to contain outer", got)
					}
					return nil
				})
		})
		if err != nil {
			t.Errorf("Transaction: %v", err)
		}
	})

	t.Run("PublicAPI_InnerSetsClaimsOnEmptyOuterClearsOnExit", func(t *testing.T) {
		// AsRole restore case 2 (TS parity): no outer AsRole
		// (claims unset), inner sets claims. On inner exit,
		// set_config('request.jwt.claims', NULL, true) is
		// issued to clear the GUC — without it, the inner's
		// claims would leak to the outer scope (RELEASE
		// SAVEPOINT merges the inner's SET LOCAL into the
		// outer transaction).
		err := c.Transaction(ctx, func(ctx context.Context) error {
			// No outer AsRole — claims start unset.
			if err := c.AsRole(ctx, "pgrls_protocol_actor",
				&pgrlstest.AsRoleOptions{Claims: map[string]any{"tenant_id": "inner-only"}},
				func(ctx context.Context) error {
					rows, err := c.FetchAll(ctx, "SELECT current_setting('request.jwt.claims', true) AS claims")
					if err != nil {
						return err
					}
					got := coerceString(t, rows[0]["claims"])
					if !strings.Contains(got, "inner-only") {
						t.Errorf("inner claims = %q, want to contain inner-only", got)
					}
					return nil
				}); err != nil {
				return err
			}
			rows, err := c.FetchAll(ctx, "SELECT current_setting('request.jwt.claims', true) AS claims")
			if err != nil {
				return err
			}
			got := coerceString(t, rows[0]["claims"])
			// set_config(NULL, true) collapses to "" on a
			// touched GUC; nil pre-touch also possible.
			if got != "" {
				t.Errorf("post-inner claims = %q, want empty (set_config NULL clear)", got)
			}
			return nil
		})
		if err != nil {
			t.Errorf("Transaction: %v", err)
		}
	})
}

// coerceString reads a row-map cell as a string, accepting
// either string or []byte (lib/pq surfaces name-typed columns
// as []byte). Mirrors the Client.AsRole capture-coercion logic.
func coerceString(t *testing.T, v any) string {
	t.Helper()
	switch x := v.(type) {
	case string:
		return x
	case []byte:
		return string(x)
	case nil:
		return ""
	default:
		t.Fatalf("expected string/[]byte/nil, got %T: %v", v, v)
		return ""
	}
}

func TestConformance_PgxAdapter(t *testing.T) {
	c, cleanup := newPgxClient(t)
	defer cleanup()
	runConformance(t, c)
}

func TestConformance_PqAdapter(t *testing.T) {
	c, cleanup := newPqClient(t)
	defer cleanup()
	runConformance(t, c)
}

// Compile-time pin: the conformance suite reaches into both
// adapter packages and the Client API; a future breaking
// signature change to any of them breaks this file's build,
// not just an assertion at runtime.
var (
	_ pgrlstest.Driver = (pgxdriver.Pool(nil))
	_ pgrlstest.Driver = (pqdriver.DB(nil))
	_ pgrlstest.Driver = (pgxdriver.Conn(nil))
	_ pgrlstest.Driver = (pqdriver.Conn(nil))
)
