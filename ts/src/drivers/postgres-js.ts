/**
 * `postgres.js` adapter for `pgrls-test`.
 *
 * Usage:
 *
 * ```ts
 * import postgres from 'postgres';
 * import { PgrlsTestClient, postgresJsDriver } from 'pgrls-test';
 *
 * const sql = postgres(process.env.DATABASE_URL);
 * const client = new PgrlsTestClient(postgresJsDriver(sql));
 * // ... run tests ...
 * await client.close();   // releases the pinned pool connection
 * ```
 *
 * The adapter exists because `postgres.js`'s primary API is
 * tagged-template literals (`sql\`SELECT * FROM x\``), which
 * doesn't fit the "execute this raw SQL string with these
 * positional params" shape `pgrls-test` needs. Internally we
 * use `sql.unsafe(text, params)` — postgres.js's escape hatch
 * for exactly that. Users keep their existing `postgres()`
 * connection pool and tagged-template usage everywhere else;
 * the escape hatch is confined to this adapter.
 *
 * **Connection pinning** (v0.6.2): `postgres.js` is a pool by
 * default (10 connections). `PgrlsTestClient.transaction()`
 * issues `BEGIN`, queries, and `ROLLBACK` as separate driver
 * calls — if those land on different pool connections, the
 * transaction breaks and `ROLLBACK` undoes nothing. The
 * adapter now lazily calls `sql.reserve()` on the first
 * `query()` to pin a single connection for the lifetime of
 * the driver, and releases it via `close()` (forwarded from
 * `PgrlsTestClient.close()`). The fix means users no longer
 * need the `{ max: 1 }` workaround the conformance suite
 * previously carried.
 *
 * `postgres` is a peer dependency. Users who don't use it
 * never pull it in.
 */
import type { Driver, QueryResult } from './types.js';

/**
 * Subset of `postgres.Sql` the adapter needs. Defined
 * structurally so we don't have to `import postgres from
 * 'postgres'` at module-load time (that would make `postgres`
 * a runtime dep instead of a peer dep).
 *
 * `postgres.js`'s `unsafe(text, params)` returns a
 * `PendingQuery<Row[]>` — awaiting it yields an array of rows
 * with `command` and `count` properties attached. Modeling
 * that shape here.
 *
 * `reserve()` (postgres.js v3.4+) pins one pool connection
 * and returns a `ReservedSql` that has the same `unsafe`
 * interface plus a `release()` method to give the connection
 * back to the pool. The adapter uses this to keep every
 * `query()` call on the same connection so transaction state
 * (BEGIN, SET LOCAL, ROLLBACK) is preserved.
 */
export interface PostgresJsSql {
  unsafe<TRow = Record<string, unknown>>(
    text: string,
    params?: readonly unknown[],
  ): Promise<PostgresJsResult<TRow>>;
  reserve(): Promise<PostgresJsReservedSql>;
}

/**
 * The reserved-connection variant of `PostgresJsSql`. Has the
 * same `unsafe(text, params)` interface plus an explicit
 * `release()` method. Returned by `sql.reserve()`.
 */
export interface PostgresJsReservedSql extends PostgresJsSql {
  release(): void;
}

/**
 * Result shape postgres.js returns from `sql.unsafe(...)`.
 *
 * The result IS the array of rows (numerically indexed) but
 * also has `command` and `count` properties tacked on — a
 * postgres.js convention. We treat it as both via a hybrid
 * type.
 */
export type PostgresJsResult<TRow> = readonly TRow[] & {
  command?: string;
  count?: number;
};

/**
 * Wrap a `postgres.Sql` instance (or any object satisfying
 * `PostgresJsSql`) into the `Driver` shape the rest of
 * `pgrls-test` consumes.
 *
 * The adapter lazily reserves a pool connection on the first
 * `query()` call and uses that reserved connection for every
 * subsequent call. Without this pinning, transaction-aware
 * code (e.g. `PgrlsTestClient.transaction()` running BEGIN /
 * SET LOCAL / queries / ROLLBACK across multiple `query()`
 * calls) would scatter across the pool and lose state.
 *
 * Call `client.close()` (or the returned driver's `close()`)
 * at the end of the test to release the pinned connection
 * back to the pool. If you forget, the connection is held
 * until `sql.end()` is called — fine for one-off scripts,
 * leaky for long-lived test suites.
 *
 * Idempotency: `close()` may be called more than once; the
 * second call is a no-op. A `query()` after `close()`
 * re-acquires a fresh connection from the pool — useful for
 * test harnesses that recycle the driver across test cases.
 */
export function postgresJsDriver(sql: PostgresJsSql): Driver {
  // The pinned-connection promise. `null` means "no reservation
  // in flight yet"; `query()` lazily kicks off `sql.reserve()`
  // on first use and stores the promise (NOT the resolved value)
  // so concurrent callers all await the same promise instead of
  // each kicking off their own reservation. Storing only the
  // resolved value would race: two concurrent `pinnedSql()` calls
  // could both observe `reserved === null`, both call
  // `sql.reserve()`, and the second reservation would leak (its
  // `release()` never called). The promise variant is atomic by
  // construction. After `close()` (or a rejected reservation),
  // this returns to `null` so a subsequent `query()` re-pins.
  let reservedPromise: Promise<PostgresJsReservedSql> | null = null;

  function pinnedSql(): Promise<PostgresJsReservedSql> {
    // The `.catch` clears the cached promise on rejection so the
    // next `pinnedSql()` retries `sql.reserve()` instead of
    // replaying the rejection forever. Without this, a transient
    // failure (timeout, connection blip during initial handshake,
    // pool just-closed-and-reopened) would permanently jam the
    // driver.
    //
    // The clear is **conditional** on `reservedPromise` still
    // pointing at the rejecting promise. Without this guard, a
    // subtle race leaks reservations:
    //   1. query1() triggers P1 = sql.reserve() that will reject.
    //   2. close() copies P1, sets reservedPromise = null, awaits.
    //   3. query2() runs before P1's .catch fires: observes
    //      reservedPromise = null, kicks off P2 = sql.reserve()
    //      that succeeds. reservedPromise = P2.
    //   4. P1's .catch fires LATE, unconditionally writes
    //      reservedPromise = null — clobbering P2. P2's
    //      reservation is now untracked → a later close() can't
    //      release it. LEAK.
    // The `reservedPromise === guarded` identity check prevents
    // step 4 from touching reservedPromise when a different
    // reservation has taken over.
    if (reservedPromise === null) {
      const guarded: Promise<PostgresJsReservedSql> = sql
        .reserve()
        .catch((err: unknown) => {
          if (reservedPromise === guarded) {
            reservedPromise = null;
          }
          throw err;
        });
      reservedPromise = guarded;
    }
    return reservedPromise;
  }

  return {
    async query(sqlText: string, params?: readonly unknown[]): Promise<QueryResult> {
      const conn = await pinnedSql();
      const result = await conn.unsafe<Record<string, unknown>>(sqlText, params);
      // postgres.js's result is an array-like with `command`
      // and `count` extras. Spread into a plain array so
      // callers can't mutate the underlying driver state, and
      // surface command/count under the QueryResult shape.
      const rows: Record<string, unknown>[] = Array.from(result);
      return {
        rows,
        command: (result.command ?? '').toUpperCase(),
        // For SELECT and RETURNING-bearing DML, count is the
        // number of rows. For plain UPDATE/DELETE/INSERT, count
        // is the affected-row count. Map an explicit `undefined`
        // (defensive — postgres.js sets it on every result) to
        // rows.length as the safest fallback.
        rowCount: result.count ?? rows.length,
      };
    },

    async rollback(): Promise<void> {
      // ROLLBACK accepted in any transaction state, including
      // an aborted one. Route through the pinned connection
      // so the BEGIN issued earlier (on the same connection)
      // is the one being rolled back.
      const conn = await pinnedSql();
      await conn.unsafe('ROLLBACK');
    },

    isInsufficientPrivilege(error: unknown): boolean {
      // postgres.js wraps server errors as `PostgresError`
      // instances with `code` set to the 5-char SQLSTATE.
      // 42501 is insufficient_privilege.
      return (
        typeof error === 'object' &&
        error !== null &&
        'code' in error &&
        (error as { code?: unknown }).code === '42501'
      );
    },

    async close(): Promise<void> {
      // Idempotent: noop on second call. A `query()` after
      // `close()` re-acquires (see `pinnedSql`). Awaits any
      // in-flight reservation before releasing so a concurrent
      // `close()` + first-`query()` race resolves to "reserve
      // then immediately release" rather than leaving the
      // reservation orphaned.
      //
      // Rejection handling: if `sql.reserve()` failed there's
      // nothing to release. Swallow that rejection in `close()`
      // so it doesn't mask the original error in
      // `try { ... } finally { await client.close() }` — the
      // caller already saw the rejection from their `query()`
      // call. `release()` is synchronous in postgres.js v3.4+
      // but the method signature returns `Promise<void>` to
      // match the optional `Driver.close()` contract (other
      // adapters may need async teardown — e.g. a future
      // Bun.sql adapter could `await sql.end()` here).
      if (reservedPromise !== null) {
        const inFlight = reservedPromise;
        reservedPromise = null;
        let reservation: PostgresJsReservedSql | null = null;
        try {
          reservation = await inFlight;
        } catch {
          // Reservation never succeeded — nothing to release.
          return;
        }
        reservation.release();
      }
    },
  };
}
