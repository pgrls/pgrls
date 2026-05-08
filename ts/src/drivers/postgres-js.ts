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
 */
export interface PostgresJsSql {
  unsafe<TRow = Record<string, unknown>>(
    text: string,
    params?: readonly unknown[],
  ): Promise<PostgresJsResult<TRow>>;
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
 */
export function postgresJsDriver(sql: PostgresJsSql): Driver {
  return {
    async query(sqlText: string, params?: readonly unknown[]): Promise<QueryResult> {
      const result = await sql.unsafe<Record<string, unknown>>(sqlText, params);
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
      // an aborted one.
      await sql.unsafe('ROLLBACK');
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
  };
}
