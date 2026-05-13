/**
 * RLS-specific assertion helpers.
 *
 * Each helper takes a `PgrlsTestClient` and a SQL string;
 * `PgrlsTestClient` exposes them as instance methods (passing
 * `this`) — but they're equally usable standalone in
 * non-pgrls-test contexts.
 *
 * Failure mode: every helper throws `PgrlsTestAssertionError`
 * so Vitest renders the failure with its standard error
 * machinery.
 *
 * Direct port of `src/pgrls/testing/assertions.py`.
 */
import { newSavepointName } from './_savepoint.js';
import type { PgrlsTestClient } from './client.js';
import { PgrlsTestAssertionError, PgrlsTestError } from './errors.js';

/**
 * Assert the query returns exactly `count` rows.
 *
 * @throws {PgrlsTestAssertionError} If the count doesn't match.
 */
export async function assertRows(
  client: PgrlsTestClient,
  sql: string,
  options: { count: number },
): Promise<void> {
  const result = await client.driver.query(sql);
  const actual = result.rows.length;
  if (actual !== options.count) {
    throw new PgrlsTestAssertionError(
      `assertRows: expected ${options.count} row(s), got ${actual} ` +
        `for query: ${JSON.stringify(sql)}`,
    );
  }
}

/**
 * Assert the query returns at least one row.
 *
 * @throws {PgrlsTestAssertionError} If zero rows returned.
 */
export async function assertVisible(client: PgrlsTestClient, sql: string): Promise<void> {
  const result = await client.driver.query(sql);
  if (result.rows.length === 0) {
    throw new PgrlsTestAssertionError(
      `assertVisible: expected at least 1 row, got 0 ` +
        `for query: ${JSON.stringify(sql)}`,
    );
  }
}

/**
 * Assert the query returns zero rows.
 *
 * @throws {PgrlsTestAssertionError} If any rows returned.
 */
export async function assertInvisible(
  client: PgrlsTestClient,
  sql: string,
): Promise<void> {
  const result = await client.driver.query(sql);
  if (result.rows.length !== 0) {
    throw new PgrlsTestAssertionError(
      `assertInvisible: expected 0 rows, got ${result.rows.length} ` +
        `for query: ${JSON.stringify(sql)}`,
    );
  }
}

/**
 * Assert that running `sql` raises Postgres `InsufficientPrivilege`
 * (SQLSTATE 42501).
 *
 * Wraps the query in a savepoint so a failure (which puts the
 * transaction in 'aborted' state until rollback) doesn't poison
 * subsequent queries in the same test. On success (the query
 * raised the expected error), the savepoint is rolled back; on
 * failure (the query succeeded or raised a different error), a
 * `PgrlsTestAssertionError` is thrown.
 *
 * Mirrors Python's `assert_rejected` — the savepoint
 * convention, the "wrong-error-class" message, and the
 * "succeeded but expected rejection" message all align.
 */
export async function assertRejected(
  client: PgrlsTestClient,
  sql: string,
): Promise<void> {
  const savepoint = newSavepointName('pgrls_check');
  await client.driver.query(`SAVEPOINT ${savepoint}`);

  let rejectedAsExpected = false;
  let succeededWithoutError = false;
  let unexpectedError: unknown = undefined;

  try {
    await client.driver.query(sql);
    succeededWithoutError = true;
  } catch (exc) {
    if (client.driver.isInsufficientPrivilege(exc)) {
      rejectedAsExpected = true;
    } else {
      unexpectedError = exc;
    }
  }

  // Always roll back the savepoint — the SQL ran (success or
  // failure). On the rejection-as-expected path the transaction
  // is in aborted state and ROLLBACK TO is the only way to
  // recover.
  if (rejectedAsExpected || unexpectedError !== undefined) {
    await client.driver.query(`ROLLBACK TO SAVEPOINT ${savepoint}`);
  } else {
    // Successful query — release rather than rollback so the
    // (possibly side-effecting) successful statement stays
    // committed within the outer transaction. The assertion is
    // about to throw, so the outer `transaction()` will
    // ROLLBACK the whole thing anyway, but releasing the
    // savepoint matches Python's exact sequence and makes the
    // intent crystal clear.
    await client.driver.query(`RELEASE SAVEPOINT ${savepoint}`);
  }

  if (succeededWithoutError) {
    throw new PgrlsTestAssertionError(
      `assertRejected: query succeeded but expected RLS rejection: ` +
        `${JSON.stringify(sql)}`,
    );
  }
  if (unexpectedError !== undefined) {
    let message: string;
    if (unexpectedError instanceof Error) {
      message = `${unexpectedError.constructor.name}: ${unexpectedError.message}`;
    } else if (
      typeof unexpectedError === 'string' ||
      typeof unexpectedError === 'number' ||
      typeof unexpectedError === 'boolean'
    ) {
      // Primitive — String() does the right thing.
      message = String(unexpectedError);
    } else {
      // Object / array / null / undefined — JSON for clarity.
      // The eslint no-base-to-string rule forbids letting this
      // hit the default `[object Object]`; JSON is the closest
      // honest answer.
      message = JSON.stringify(unexpectedError);
    }
    throw new PgrlsTestAssertionError(
      `assertRejected: expected InsufficientPrivilege (SQLSTATE 42501), ` +
        `got ${message}`,
    );
  }
  // rejectedAsExpected — pass.
}

/**
 * Assert that a DML with RETURNING returns zero rows.
 *
 * Models the Postgres RLS shape where an UPDATE or DELETE
 * finds no rows because the policy's USING expression filters
 * them all out — the operation succeeds with no error and
 * RETURNING yields zero rows. This is distinct from a
 * permission rejection (which raises InsufficientPrivilege)
 * and from a missing-row case (which is just an empty SELECT).
 *
 * Note on INSERT: in Postgres, `INSERT ... RETURNING` does NOT
 * silently drop. When a SELECT policy's USING fails on the new
 * row, the engine raises "new row violates row-level security
 * policy" rather than returning zero rows. The silent-drop
 * shape only happens for UPDATE/DELETE … RETURNING, where
 * USING acts as a pre-operation row filter.
 *
 * Distinct from `assertRejected` (which expects the write to
 * raise InsufficientPrivilege) and `assertInvisible` (which is
 * a SELECT-side check). The helper requires the SQL to contain
 * RETURNING — without it, the row count is not the relevant
 * signal.
 *
 * @throws {PgrlsTestError} If the SQL is not an UPDATE or DELETE.
 * @throws {PgrlsTestAssertionError} If RETURNING yields any rows.
 */
export async function assertSilentlyDropped(
  client: PgrlsTestClient,
  sql: string,
): Promise<void> {
  const result = await client.driver.query(sql);

  // Gate on the verb so a SELECT (which produces a result set
  // whether or not it returns rows) can't silently masquerade
  // as the silent-drop shape — `assertSilentlyDropped("SELECT *
  // FROM t WHERE 1=0")` would otherwise pass with zero rows
  // even though no RLS-aware DML ran.
  const verb = result.command;
  if (verb !== 'UPDATE' && verb !== 'DELETE') {
    throw new PgrlsTestError(
      `assertSilentlyDropped is for UPDATE/DELETE … RETURNING ` +
        `(USING acts as a row pre-filter); INSERT … RETURNING does ` +
        `NOT silently drop — Postgres raises InsufficientPrivilege ` +
        `on a WITH CHECK violation. Use assertInvisible for SELECT ` +
        `and assertRejected for INSERT. Got command verb ` +
        `${verb ? JSON.stringify(verb) : "'(unknown)'"} for query: ` +
        `${JSON.stringify(sql)}`,
    );
  }

  // Require a RETURNING clause. Python's `assert_silently_dropped`
  // catches `psycopg.ProgrammingError` from `cur.fetchall()` when
  // there's no result set; both `pg` and `postgres.js` instead
  // synthesize an empty rows array, so we can't distinguish
  // "RETURNING returned 0 rows" from "no RETURNING at all" by
  // looking at the result. Detect the missing-RETURNING case
  // upfront via a literal-keyword check — false positives
  // (RETURNING inside a comment / string) are not the helper's
  // problem to handle; the helper's contract is "the SQL has
  // RETURNING and we're checking its row count".
  //
  // Without this gate, `assertSilentlyDropped("UPDATE t SET x = 1")`
  // (no RETURNING) silently passes whenever RLS happens to filter
  // every row, even though there's no RLS-aware signal in the
  // empty result. The Python helper explicitly warns about this
  // case in its docstring.
  if (!/\bRETURNING\b/i.test(sql)) {
    throw new PgrlsTestError(
      `assertSilentlyDropped requires the SQL to use RETURNING — ` +
        `the helper checks that the affected row was hidden from ` +
        `the current role by counting RETURNING's output. Without ` +
        `RETURNING, the row count is not the relevant signal. ` +
        `Query: ${JSON.stringify(sql)}`,
    );
  }

  if (result.rows.length > 0) {
    throw new PgrlsTestAssertionError(
      `assertSilentlyDropped: expected RETURNING to yield 0 rows, ` +
        `got ${result.rows.length} row(s) for query: ${JSON.stringify(sql)}`,
    );
  }
}
