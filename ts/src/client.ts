/**
 * `PgrlsTestClient` — the public entry point of `pgrls-test`.
 *
 * Direct port of `pgrls.testing.PgrlsTestClient` (Python). The
 * wire-level sequence is identical: same SAVEPOINT name format,
 * same SET LOCAL ROLE / set_config call, same restoration logic
 * on clean exit, same ROLLBACK TO SAVEPOINT on exception.
 * Documented at https://github.com/pgrls/pgrls/blob/main/docs/pgrls-test-protocol.md
 * as the cross-language wire contract.
 *
 * Usage with `pg`:
 *
 * ```ts
 * import { Client } from 'pg';
 * import { PgrlsTestClient, pgDriver } from 'pgrls-test';
 *
 * const pg = new Client({ connectionString: process.env.DATABASE_URL });
 * await pg.connect();
 * const client = new PgrlsTestClient(pgDriver(pg));
 *
 * await client.transaction(async () => {
 *   await client.seed('app.invoices', [
 *     { tenant_id: 't1', amount: 100 },
 *     { tenant_id: 't2', amount: 200 },
 *   ]);
 *   await client.asRole(
 *     'app_authenticated',
 *     { claims: { sub: 'user-a', tenant_id: 't1' } },
 *     async () => {
 *       await client.assertRows(
 *         'SELECT id FROM app.invoices',
 *         { count: 1 },
 *       );
 *     },
 *   );
 * });
 * ```
 *
 * The `Driver` parameter (see `./drivers/types.ts`) is the
 * abstraction over the user's Postgres client; same client
 * constructor accepts a `pg` driver or a `postgres.js` driver.
 */
import { newSavepointName } from './_savepoint.js';
import {
  assertInvisible as _assertInvisible,
  assertRejected as _assertRejected,
  assertRows as _assertRows,
  assertSilentlyDropped as _assertSilentlyDropped,
  assertVisible as _assertVisible,
} from './assertions.js';
import type { Driver } from './drivers/types.js';
import { PgrlsTestError } from './errors.js';
import { quoteIdent, quoteQualified } from './idents.js';

/**
 * Options passed to `client.asRole`.
 */
export interface AsRoleOptions {
  /**
   * JWT claims to set in the `request.jwt.claims` GUC for the
   * duration of the block.
   *
   * `null` means "don't touch the GUC" (different from `{}`,
   * which deliberately sets it to the empty JSON object — an
   * "actor with no claims" request). The protocol distinguishes
   * the two: `null` doesn't issue `set_config(...)`, `{}` does.
   *
   * Omitting the `claims` key entirely has the same effect as
   * passing `null`. With `exactOptionalPropertyTypes: true`
   * (the recommended TS config and the one this package uses),
   * `claims: undefined` is rejected at compile time — pass
   * `null` explicitly or drop the key.
   */
  claims?: Record<string, unknown> | null;
}

/**
 * pgrls-test's main client. Wraps a `Driver` with per-test
 * transactions, role+claims switching, simple seeding, and
 * RLS-specific assertions.
 *
 * Construct directly with a Driver (`pgDriver(...)` or
 * `postgresJsDriver(...)`). Mirrors the Python
 * `PgrlsTestClient(connection)` shape — the connection is
 * supplied externally so users keep their connection-management
 * patterns intact.
 */
export class PgrlsTestClient {
  /**
   * @internal — exposed for the assertion helpers in
   * `./assertions.ts`. Not part of the public API; subject to
   * change between minor versions.
   */
  public readonly driver: Driver;

  constructor(driver: Driver) {
    this.driver = driver;
  }

  /**
   * Run `body` inside a transaction; ROLLBACK on exit (always).
   *
   * Per-test isolation: the body seeds data, switches roles,
   * asserts. The trailing `ROLLBACK` ensures nothing persists.
   * Exceptions from the body propagate; the rollback runs in
   * the `finally` so cleanup always happens.
   *
   * Issues an explicit `BEGIN` at entry and `ROLLBACK` at exit.
   * Works regardless of the driver's autocommit setting — being
   * explicit means the same code runs whether the user's
   * `pg.Client` is autocommit=true or autocommit=false, and
   * whether they're using a Pool client (autocommit by default)
   * or a dedicated session.
   */
  async transaction<T>(body: () => Promise<T>): Promise<T> {
    // Begin an explicit transaction so the rollback at the end
    // unwinds the test's writes. We don't rely on the driver's
    // autocommit setting — being explicit means the same code
    // works whether the user's pg.Client is autocommit=true or
    // autocommit=false, and whether they're using a Pool client
    // (which is autocommit by default) or a session.
    await this.driver.query('BEGIN');
    try {
      return await body();
    } finally {
      // Always rollback. Errors from the body propagate (we're
      // in finally, not catch); if the rollback itself errors,
      // we let that surface too.
      await this.driver.rollback();
    }
  }

  /**
   * Execute a single SQL statement.
   *
   * Discards rows. For SELECT or RETURNING-bearing DML where
   * the rows matter, use `fetchAll` instead.
   *
   * Mirrors Python's `client.exec(sql, params=[...])`.
   */
  async exec(sql: string, params: readonly unknown[] = []): Promise<void> {
    await this.driver.query(sql, params);
  }

  /**
   * Execute a query and return rows as plain objects.
   *
   * Both drivers return rows as `Record<string, unknown>` (key
   * = column name, value = the driver's deserialized JS value).
   * Type the result with a generic for ergonomics — both
   * `interface` and `type` declarations work:
   *
   * ```ts
   * interface Invoice { id: number; tenant_id: string; amount: number }
   * const rows = await client.fetchAll<Invoice>('SELECT * FROM invoices');
   * ```
   *
   * The generic is a *type cast* — there's no runtime validation.
   * Mirrors Python's `client.fetchall(sql, params=[...])` which
   * also returns un-validated dicts.
   *
   * Note: the generic has no `extends Record<string, unknown>`
   * constraint deliberately. That constraint would force users
   * to declare row types as `type` aliases (which have implicit
   * index signatures) and reject `interface` declarations
   * (which don't, under TS's structural typing rules). Since
   * the cast is unchecked anyway, the constraint adds friction
   * without safety.
   */
  async fetchAll<TRow = Record<string, unknown>>(
    sql: string,
    params: readonly unknown[] = [],
  ): Promise<TRow[]> {
    const result = await this.driver.query(sql, params);
    return result.rows as TRow[];
  }

  /**
   * Switch role + claims for the duration of `body`.
   *
   * Implements the Layer 1 protocol's "scenario block":
   *
   * 1. Capture current role + claims via SELECT.
   * 2. SAVEPOINT pgrls_actor_<random>.
   * 3. SET LOCAL ROLE <quoted role>.
   * 4. If claims is non-null, set_config('request.jwt.claims',
   *    <json>, true).
   * 5. await body().
   * 6. On clean exit: RELEASE SAVEPOINT, then explicitly
   *    restore the captured prior role + claims (RELEASE
   *    SAVEPOINT keeps inner SET LOCAL changes merged into the
   *    outer transaction; explicit restore is required for
   *    nested asRole to work).
   * 7. On exception: ROLLBACK TO SAVEPOINT (auto-restores SET
   *    LOCAL state).
   *
   * Mirrors Python's `as_role` contextmanager. See the protocol
   * doc for the full rationale on every step.
   *
   * @param role The Postgres role name (any identifier — quoted
   *   automatically if it contains special chars or is a
   *   reserved keyword).
   * @param options.claims JWT claims object, or `null` to skip
   *   the claims set_config. Empty object `{}` is a deliberate
   *   "actor with no claims" — distinct from `null`.
   * @param body Async function to run while the role is active.
   */
  async asRole<T>(
    role: string,
    options: AsRoleOptions,
    body: () => Promise<T>,
  ): Promise<T> {
    const claims = options.claims ?? null;
    const savepoint = newSavepointName('pgrls_actor');

    // 1. Capture state BEFORE the savepoint so we can restore
    // it on clean exit. RELEASE SAVEPOINT keeps SET LOCAL
    // changes merged into the outer transaction; without
    // explicit restoration, nested asRole blocks would lose
    // the outer role.
    const captureRows = await this.driver.query(
      "SELECT current_user, current_setting('request.jwt.claims', true) AS claims",
    );
    const captureRow = captureRows.rows[0];
    if (captureRow === undefined) {
      // Defensive: SELECT current_user always returns one row,
      // but a custom driver could violate that contract.
      throw new PgrlsTestError(
        'asRole: failed to capture current role/claims ' +
          '(SELECT current_user returned no row — driver in unexpected state)',
      );
    }
    // Prior role: pg returns lowercase column names by default;
    // both columns are present.
    const prevUser = String(captureRow.current_user);
    const prevClaimsRaw = captureRow.claims;
    const prevClaims =
      typeof prevClaimsRaw === 'string' && prevClaimsRaw !== '' ? prevClaimsRaw : null;

    // 2. SAVEPOINT. Name is locally generated random hex —
    // safe to interpolate without quoting.
    await this.driver.query(`SAVEPOINT ${savepoint}`);

    // SAVEPOINT now exists — every subsequent failure path
    // must run ROLLBACK TO SAVEPOINT, so move the role +
    // claims setup inside the try.
    let ok = false;
    try {
      // 3. Switch role. quoteIdent handles reserved keywords
      // and special characters.
      await this.driver.query(`SET LOCAL ROLE ${quoteIdent(role)}`);

      // 4. Set claims if provided. `null` skips the call.
      // `{}` is a deliberate "actor with no claims" request
      // and IS sent (as the JSON string `"{}"`).
      if (claims !== null) {
        await this.driver.query("SELECT set_config('request.jwt.claims', $1, true)", [
          JSON.stringify(claims),
        ]);
      }

      // 5. Run the test body.
      const result = await body();
      ok = true;
      return result;
    } finally {
      if (ok) {
        // 6a. Clean exit. RELEASE SAVEPOINT, then explicitly
        // restore prior role + claims (RELEASE keeps SET
        // LOCAL changes merged into the outer transaction;
        // without restoration, nested asRole blocks would
        // see the inner role on return).
        await this.driver.query(`RELEASE SAVEPOINT ${savepoint}`);
        await this.driver.query(`SET LOCAL ROLE ${quoteIdent(prevUser)}`);
        if (prevClaims !== null) {
          // Outer had claims; restore them whether or not
          // inner changed them (a no-op set is cheap).
          await this.driver.query("SELECT set_config('request.jwt.claims', $1, true)", [
            prevClaims,
          ]);
        } else if (claims !== null) {
          // Outer had no claims; inner set some. Clear the
          // GUC value via `set_config(name, NULL, true)`.
          // Postgres collapses NULL to '' on custom GUCs once
          // they've been touched in the session — so
          // `current_setting('request.jwt.claims', true)`
          // returns `''` rather than NULL — but the inner-
          // block JSON is gone, so a downstream policy doing
          // `current_setting(...)::jsonb` raises `invalid
          // input syntax for type json` instead of silently
          // authorizing as the inner-block actor.
          await this.driver.query("SELECT set_config('request.jwt.claims', NULL, true)");
        }
        // else: outer had no claims and inner didn't set any —
        // the GUC was never touched, no restore needed.
      } else {
        // 6b. Exception path. ROLLBACK TO SAVEPOINT restores
        // SET LOCAL state from before the savepoint —
        // role and GUC both revert automatically.
        await this.driver.query(`ROLLBACK TO SAVEPOINT ${savepoint}`);
      }
    }
  }

  /**
   * Bulk-insert rows into `table` in the current (admin) context.
   *
   * All rows must have the same keys (the column set). Empty
   * list is a no-op. Identifiers are double-quoted via
   * `quoteIdent` / `quoteQualified`, so reserved keywords and
   * mixed-case names are handled correctly.
   *
   * Schema-qualified table names work: pass `"app.invoices"`
   * and the helper splits on the rightmost dot, quoting each
   * segment independently. Names with more than one dot are
   * rejected — cross-database refs aren't supported.
   *
   * Mirrors Python's `client.seed(table, rows)`. For richer
   * factory needs (sequencing, faker integration, post-insert
   * hooks), use the JS factory framework the project already
   * has — `pgrls-test`'s seeder is intentionally tiny.
   *
   * @throws {PgrlsTestError} If rows have inconsistent keys, the
   *   table name has multiple dots, or any identifier is
   *   invalid.
   */
  async seed(table: string, rows: readonly Record<string, unknown>[]): Promise<void> {
    if (rows.length === 0) {
      return;
    }

    const firstRow = rows[0];
    if (firstRow === undefined) {
      // Unreachable — rows.length > 0 guarantees rows[0]
      // exists — but TypeScript's noUncheckedIndexedAccess
      // can't prove that without a runtime check.
      return;
    }
    const keys = Object.keys(firstRow);
    const keySet = new Set(keys);
    for (let i = 1; i < rows.length; i++) {
      const row = rows[i];
      if (row === undefined) continue;
      const rowKeys = Object.keys(row);
      if (rowKeys.length !== keys.length || !rowKeys.every((k) => keySet.has(k))) {
        throw new PgrlsTestError(
          `seed rows must all have the same keys; row 0 has ` +
            `${JSON.stringify([...keys].sort())}, row ${i} has ` +
            `${JSON.stringify(rowKeys.sort())}`,
        );
      }
    }

    // Right-split on `.` so a single dot means schema.table;
    // absent dot means an unqualified name in the current
    // search_path. Mirror the Python helper's exception types.
    let quotedTable: string;
    try {
      const dotCount = (table.match(/\./g) ?? []).length;
      if (dotCount > 1) {
        throw new PgrlsTestError(
          `seed: table name ${JSON.stringify(table)} contains more ` +
            `than one dot. Cross-database table references aren't ` +
            `supported — pass an unqualified name (uses search_path) ` +
            `or a qualified 'schema.table'.`,
        );
      }
      if (dotCount === 1) {
        const lastDot = table.lastIndexOf('.');
        const schema = table.slice(0, lastDot);
        const name = table.slice(lastDot + 1);
        quotedTable = quoteQualified(schema, name);
      } else {
        quotedTable = quoteIdent(table);
      }
    } catch (exc) {
      // Wrap quoteIdent's bare Error into a PgrlsTestError so
      // the seed helper raises a uniform error type.
      if (exc instanceof PgrlsTestError) throw exc;
      const message = exc instanceof Error ? exc.message : String(exc);
      throw new PgrlsTestError(
        `seed: invalid table name ${JSON.stringify(table)}: ${message}`,
      );
    }

    const cols = keys.map((k) => quoteIdent(k)).join(', ');
    const placeholders = keys.map((_, i) => `$${i + 1}`).join(', ');
    const sql = `INSERT INTO ${quotedTable} (${cols}) VALUES (${placeholders})`;

    // Postgres doesn't have a multi-row $-parameterized form
    // that fits both pg and postgres.js cleanly, so issue one
    // INSERT per row. Same as the Python `executemany` shape.
    // This is a test-time helper; bulk-loading isn't the
    // performance hot path.
    for (const row of rows) {
      const values = keys.map((k) => row[k]);
      await this.driver.query(sql, values);
    }
  }

  /**
   * Assert the query returns exactly `count` rows.
   *
   * @throws {PgrlsTestAssertionError} If the count doesn't match.
   */
  async assertRows(sql: string, options: { count: number }): Promise<void> {
    await _assertRows(this, sql, options);
  }

  /**
   * Assert the query returns at least one row.
   *
   * @throws {PgrlsTestAssertionError} If zero rows returned.
   */
  async assertVisible(sql: string): Promise<void> {
    await _assertVisible(this, sql);
  }

  /**
   * Assert the query returns zero rows.
   *
   * @throws {PgrlsTestAssertionError} If any rows returned.
   */
  async assertInvisible(sql: string): Promise<void> {
    await _assertInvisible(this, sql);
  }

  /**
   * Assert that running `sql` raises Postgres `InsufficientPrivilege`
   * (SQLSTATE 42501).
   *
   * Wraps in a savepoint so the failure doesn't poison
   * subsequent queries. See `assertions.ts` for full details.
   *
   * @throws {PgrlsTestAssertionError} If the query succeeded
   *   or raised a different error.
   */
  async assertRejected(sql: string): Promise<void> {
    await _assertRejected(this, sql);
  }

  /**
   * Assert that a DML with RETURNING returns zero rows
   * (UPDATE/DELETE only — INSERT raises 42501 instead).
   *
   * @throws {PgrlsTestError} If the SQL is not an UPDATE/DELETE.
   * @throws {PgrlsTestAssertionError} If RETURNING yields rows.
   */
  async assertSilentlyDropped(sql: string): Promise<void> {
    await _assertSilentlyDropped(this, sql);
  }
}
