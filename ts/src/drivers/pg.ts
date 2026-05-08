/**
 * `pg` (node-postgres) adapter for `pgrls-test`.
 *
 * Usage:
 *
 * ```ts
 * import { Client } from 'pg';
 * import { PgrlsTestClient, pgDriver } from 'pgrls-test';
 *
 * const pg = new Client({ connectionString: process.env.DATABASE_URL });
 * await pg.connect();
 * const client = new PgrlsTestClient(pgDriver(pg));
 * ```
 *
 * The adapter is a thin wrapper that:
 * 1. Maps `query(sql, params)` → `client.query(sql, values)` and
 *    normalizes the result shape to `QueryResult`.
 * 2. Maps `rollback()` → `client.query('ROLLBACK')` (works even
 *    in aborted-transaction state — Postgres always accepts
 *    `ROLLBACK`).
 * 3. Maps `isInsufficientPrivilege(err)` → `err.code === '42501'`.
 *
 * `pg` is a peer dependency. Users who don't use it never pull
 * it in; users who do use it get type-checked construction.
 */
import type { Driver, QueryResult } from './types.js';

/**
 * Subset of `pg.Client` (or a `pg.Pool` wrapper) that the
 * adapter needs. We deliberately don't `import { Client } from
 * 'pg'` here — that would force `pg` to be a runtime dep. The
 * structural interface is enough for the adapter and lets users
 * pass a Pool client, a connection-checked-out client, or any
 * compatible shape.
 */
export interface PgQueryable {
  query(
    text: string,
    values?: readonly unknown[],
  ): Promise<{
    rows: Record<string, unknown>[];
    command: string;
    rowCount: number | null;
  }>;
}

/**
 * Wrap a `pg.Client` (or any object satisfying `PgQueryable`)
 * into the `Driver` shape the rest of `pgrls-test` consumes.
 */
export function pgDriver(client: PgQueryable): Driver {
  return {
    async query(sql: string, params?: readonly unknown[]): Promise<QueryResult> {
      const result = await client.query(sql, params);
      return {
        rows: result.rows,
        // pg returns the command verb as the first whitespace-
        // delimited token in the command tag (e.g. "UPDATE 5").
        // It already strips the count, so result.command is
        // exactly the verb like "UPDATE", "SELECT", "INSERT".
        // Upper-case it defensively in case some pg fork or
        // future version changes the casing.
        command: (result.command || '').toUpperCase(),
        // pg returns `rowCount: null` for commands that don't
        // produce a count (rare — utility statements). Map to
        // 0 so callers don't have to null-check.
        rowCount: result.rowCount ?? 0,
      };
    },

    async rollback(): Promise<void> {
      // ROLLBACK is accepted in any transaction state — including
      // the "current transaction is aborted" state that follows
      // a SQL error. Issuing it via the same query path keeps the
      // adapter to one entry point.
      await client.query('ROLLBACK');
    },

    isInsufficientPrivilege(error: unknown): boolean {
      // pg attaches the SQLSTATE as a string `code` property on
      // the thrown error. 42501 is "insufficient_privilege" —
      // the class RLS policy rejections surface as.
      return (
        typeof error === 'object' &&
        error !== null &&
        'code' in error &&
        (error as { code?: unknown }).code === '42501'
      );
    },
  };
}
