/**
 * The `Driver` interface — the abstraction `PgrlsTestClient`
 * uses to talk to Postgres without coupling to a specific
 * client library. One adapter per supported driver lives
 * alongside this file (`./pg.ts`, `./postgres-js.ts`); each
 * exports a factory that wraps a user-supplied client into
 * this shape.
 *
 * Why an interface instead of importing `pg` directly:
 *
 * * Two drivers have meaningfully different APIs (pg's
 *   `client.query(text, values)` vs postgres.js's
 *   `sql.unsafe(text, params)`); pinning to one would force
 *   users on the other to maintain a fork or a wrapper.
 * * The error-class shape differs (pg's `Error.code`,
 *   postgres.js's `Error.code`) — the
 *   `isInsufficientPrivilege` predicate hides that detail
 *   so the client doesn't carry conditionals.
 * * Future drivers (Bun's native pg, Cloudflare's hyperdrive
 *   binding) plug in without touching client code.
 *
 * The interface is deliberately small. The Python client
 * reaches into psycopg for cursors and savepoints; the TS
 * port issues savepoint SQL via `query()` so the driver
 * doesn't need a separate savepoint API.
 */

/**
 * Result of a single SQL execution.
 *
 * Mirrors the union of what `pg.QueryResult` and a
 * `postgres.Sql` result expose, normalized to the fields
 * the client actually needs.
 */
export interface QueryResult {
  /**
   * Rows returned, as plain `Record<string, unknown>`.
   *
   * For `SELECT` and any RETURNING clause: the result rows.
   * For `UPDATE`/`DELETE`/`INSERT` without RETURNING: empty
   * array (drivers don't synthesize rows for these).
   */
  rows: readonly Record<string, unknown>[];

  /**
   * The command verb returned by Postgres in the command tag.
   *
   * Postgres emits "UPDATE 5", "DELETE 0", "SELECT 12" etc.;
   * both drivers parse the first token. Used by
   * `assertSilentlyDropped` to gate on UPDATE/DELETE — a
   * `SELECT` with zero rows isn't a "silent drop", it's just
   * an empty SELECT.
   *
   * Always upper-case. Empty string when the driver can't
   * determine the verb (defensive — shouldn't happen in
   * practice).
   *
   * Type is a known-verb union widened with `(string & {})`
   * — the union gives editor autocomplete for the verbs we
   * actually care about, while the intersection keeps the
   * field assignable from any string (CREATE, ALTER, DO,
   * etc., plus any Postgres tag we haven't enumerated). The
   * pattern is a standard TypeScript idiom for "literal
   * suggestions without restricting to those literals."
   */
  command:
    | 'SELECT'
    | 'INSERT'
    | 'UPDATE'
    | 'DELETE'
    | 'BEGIN'
    | 'COMMIT'
    | 'ROLLBACK'
    | 'SAVEPOINT'
    | 'RELEASE'
    | ''
    | (string & {});

  /**
   * Affected-row count from the command tag.
   *
   * For `SELECT` and any RETURNING clause: number of rows
   * returned (matches `rows.length`).
   * For `UPDATE`/`DELETE`/`INSERT` without RETURNING: number
   * of rows touched.
   *
   * Always non-negative integer.
   */
  rowCount: number;
}

/**
 * Driver-agnostic Postgres client.
 *
 * `PgrlsTestClient` accepts a Driver in its constructor and
 * issues all SQL through it. Adapter factories
 * (`pgDriver`, `postgresJsDriver`) wrap the user's existing
 * client into this shape so users keep their existing
 * connection-management patterns (pools, instrumentation,
 * etc.) untouched.
 */
export interface Driver {
  /**
   * Run a parameterized query and return rows + command tag.
   *
   * `params` is a positional list; both `pg` and
   * `postgres.js` use `$1, $2, ...` placeholders. Adapters
   * bridge that to their native API.
   *
   * Errors thrown by the underlying driver propagate
   * unchanged — the client uses `isInsufficientPrivilege`
   * to classify them.
   */
  query(sql: string, params?: readonly unknown[]): Promise<QueryResult>;

  /**
   * Roll back the current transaction.
   *
   * Used by `PgrlsTestClient.transaction()`'s finally block
   * to discard the test's writes. Must be safe to call
   * even when the driver is in an aborted-transaction state
   * (Postgres's "current transaction is aborted" condition);
   * adapters typically issue `ROLLBACK` directly via the
   * driver's lower-level escape hatch rather than `query()`.
   */
  rollback(): Promise<void>;

  /**
   * Predicate: was `error` a Postgres SQLSTATE 42501
   * (insufficient_privilege)?
   *
   * RLS policy violations surface as 42501 — both
   * `WITH CHECK` failures and `USING` rejections on
   * non-RETURNING DML. `assertRejected` uses this to tell
   * the right-shape failure (RLS rejected the write) apart
   * from any other Postgres error (typo, missing column,
   * etc.).
   *
   * Adapters check the driver's error shape (`error.code`
   * for both `pg` and `postgres.js`); the predicate hides
   * that detail.
   */
  isInsufficientPrivilege(error: unknown): boolean;

  /**
   * Release any resources the driver acquired lazily.
   *
   * Optional — adapters whose underlying client doesn't need
   * explicit release (e.g. `pg.Client`, which the caller
   * already owns) can omit this. The `postgres.js` adapter
   * implements it because it lazily reserves a pool
   * connection on first `query()` and must release that
   * reservation back to the pool when the test finishes.
   *
   * `PgrlsTestClient.close()` forwards to this when present.
   * Calling `close()` more than once is a no-op; subsequent
   * `query()` / `rollback()` calls after `close()` may
   * re-acquire a fresh connection (adapter-specific).
   */
  close?(): Promise<void>;
}
