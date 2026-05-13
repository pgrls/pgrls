/**
 * Test helper: a recording `Driver` mock.
 *
 * Captures every SQL string and parameter list that flows
 * through `query()` plus the `rollback()` calls. Tests can
 * register `on(sqlSubstring, responseFn)` to program canned
 * responses for specific queries (e.g. the `SELECT current_user,
 * current_setting(...)` query `asRole` emits at entry).
 *
 * Shared between `test/client.test.ts` and
 * `test/assertions.test.ts` because both suites want the same
 * mock shape — moving it here keeps the two suites in sync when
 * the `Driver` interface grows.
 */
import { vi } from 'vitest';

import type { Driver, QueryResult } from '../src/index.js';

export interface RecordedCall {
  sql: string;
  params: readonly unknown[];
}

export type ResponseFn = (sql: string, params: readonly unknown[]) => QueryResult | Error;

export interface RecordingDriver extends Driver {
  calls: RecordedCall[];
  /**
   * Register a canned response for queries whose SQL contains
   * `sqlSubstring`. The first matching responder wins. Default
   * (no responder matched): empty result, `command: 'SELECT'`,
   * `rowCount: 0`.
   *
   * Return an `Error` from the responder to make `query()`
   * throw it — exercises the catch path in `assertRejected`.
   */
  on(sqlSubstring: string, response: ResponseFn): void;
}

/**
 * Build a fresh `RecordingDriver`. Per-test instances are
 * isolated — `calls` and responders are local to the returned
 * object.
 */
export function makeRecordingDriver(): RecordingDriver {
  const calls: RecordedCall[] = [];
  const responders: { match: string; fn: ResponseFn }[] = [];
  return {
    calls,
    on(sqlSubstring, response) {
      responders.push({ match: sqlSubstring, fn: response });
    },
    query: vi.fn(async (sql: string, params: readonly unknown[] = []) => {
      calls.push({ sql, params });
      for (const { match, fn } of responders) {
        if (sql.includes(match)) {
          const result = fn(sql, params);
          if (result instanceof Error) throw result;
          return await Promise.resolve(result);
        }
      }
      return await Promise.resolve({
        rows: [],
        command: 'SELECT',
        rowCount: 0,
      } satisfies QueryResult);
    }),
    rollback: vi.fn(async () => {
      calls.push({ sql: 'ROLLBACK', params: [] });
      await Promise.resolve();
    }),
    isInsufficientPrivilege(error: unknown): boolean {
      return (
        typeof error === 'object' &&
        error !== null &&
        'code' in error &&
        (error as { code?: unknown }).code === '42501'
      );
    },
  };
}

/**
 * Build a canned `QueryResult` for the `asRole` entry-capture
 * query (`SELECT current_user, current_setting(...)`). Shared
 * helper so tests don't all hand-roll the row shape.
 */
export function captureResponse(user: string, claims: string | null): QueryResult {
  return {
    rows: [{ current_user: user, claims: claims ?? '' }],
    command: 'SELECT',
    rowCount: 1,
  };
}

/**
 * Build a canned `QueryResult` containing the given rows under
 * the `SELECT` command tag. Convenience for assertion tests
 * that care about row counts rather than the underlying tag.
 */
export function selectRows(...rows: Record<string, unknown>[]): QueryResult {
  return { rows, command: 'SELECT', rowCount: rows.length };
}
