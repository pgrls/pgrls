/**
 * Unit tests for the `postgres.js` driver adapter.
 *
 * Driven by a hand-rolled mock that satisfies `PostgresJsSql`,
 * not by a real Postgres. Conformance suite in step 6
 * exercises the same adapter end-to-end.
 *
 * The postgres.js result is array-like (numerically indexed)
 * with `command` and `count` properties tacked on; the mock
 * mimics that shape so the adapter's `Array.from()`
 * normalization is exercised end-to-end.
 */
import { describe, expect, it, vi } from 'vitest';

import {
  postgresJsDriver,
  type PostgresJsResult,
  type PostgresJsSql,
} from '../../src/index.js';

/**
 * Build a postgres.js-shaped result: an array with `.command`
 * and `.count` attached. Must NOT subclass Array — postgres.js
 * uses a real Array with extras tacked on; tests should
 * exercise the Array.from() path the adapter relies on.
 */
function makeResult<T extends Record<string, unknown>>(
  rows: readonly T[],
  command: string,
  count?: number,
): PostgresJsResult<T> {
  const arr = [...rows] as PostgresJsResult<T>;
  // Cast through `unknown` rather than `any` so eslint stays
  // happy under `recommended-type-checked`.
  (arr as unknown as { command: string }).command = command;
  if (count !== undefined) {
    (arr as unknown as { count: number }).count = count;
  }
  return arr;
}

/**
 * Build a mock postgres.js Sql that returns a canned result.
 * Records every call.
 */
function makeMockSql(
  canned: PostgresJsResult<Record<string, unknown>>,
): PostgresJsSql & { calls: { text: string; params?: readonly unknown[] }[] } {
  const calls: { text: string; params?: readonly unknown[] }[] = [];
  return {
    calls,
    unsafe: vi.fn(async (text: string, params?: readonly unknown[]) => {
      calls.push(params === undefined ? { text } : { text, params });
      return await Promise.resolve(canned);
    }) as unknown as PostgresJsSql['unsafe'],
  };
}

describe('postgresJsDriver — query', () => {
  it('forwards SQL + params to sql.unsafe', async () => {
    const mock = makeMockSql(makeResult([], 'SELECT', 0));
    const driver = postgresJsDriver(mock);

    await driver.query('SELECT $1::int', [42]);

    expect(mock.calls).toHaveLength(1);
    expect(mock.calls[0]).toEqual({ text: 'SELECT $1::int', params: [42] });
  });

  it('omits params when none passed', async () => {
    const mock = makeMockSql(makeResult([], 'SELECT', 0));
    const driver = postgresJsDriver(mock);

    await driver.query('SELECT 1');

    expect(mock.calls[0]).toEqual({ text: 'SELECT 1' });
  });

  it('normalizes the array-like result into a plain rows array', async () => {
    const mock = makeMockSql(
      makeResult(
        [
          { id: 1, name: 'a' },
          { id: 2, name: 'b' },
        ],
        'SELECT',
        2,
      ),
    );
    const driver = postgresJsDriver(mock);

    const result = await driver.query('SELECT * FROM t');

    // Plain array — not a postgres.js result with extras.
    // Pin via JSON-equality so a future refactor that returns
    // the raw result (a postgres.js Result object) breaks the
    // test loudly.
    expect(result.rows).toEqual([
      { id: 1, name: 'a' },
      { id: 2, name: 'b' },
    ]);
    expect(Array.isArray(result.rows)).toBe(true);
  });

  it('upper-cases command tag', async () => {
    const mock = makeMockSql(makeResult([], 'select', 0));
    const driver = postgresJsDriver(mock);

    const result = await driver.query('SELECT 1');

    expect(result.command).toBe('SELECT');
  });

  it('handles missing command property (defensive)', async () => {
    // postgres.js sets command on every result, but a custom
    // wrapper could omit it. Don't crash.
    const mock = makeMockSql(makeResult([], '', 0));
    const driver = postgresJsDriver(mock);

    const result = await driver.query('-- empty');

    expect(result.command).toBe('');
  });

  it('uses count for rowCount when present', async () => {
    const mock = makeMockSql(makeResult([], 'UPDATE', 5));
    const driver = postgresJsDriver(mock);

    const result = await driver.query('UPDATE t SET x = 1');

    expect(result.rowCount).toBe(5);
  });

  it('falls back to rows.length when count is undefined', async () => {
    // Defensive — postgres.js always sets count, but a custom
    // wrapper may not. The fallback prevents NaN propagating.
    const mock = makeMockSql(makeResult([{ id: 1 }, { id: 2 }, { id: 3 }], 'SELECT'));
    const driver = postgresJsDriver(mock);

    const result = await driver.query('SELECT * FROM t');

    expect(result.rowCount).toBe(3);
  });
});

describe('postgresJsDriver — rollback', () => {
  it('issues ROLLBACK via sql.unsafe', async () => {
    const mock = makeMockSql(makeResult([], 'ROLLBACK', 0));
    const driver = postgresJsDriver(mock);

    await driver.rollback();

    expect(mock.calls).toEqual([{ text: 'ROLLBACK' }]);
  });
});

describe('postgresJsDriver — isInsufficientPrivilege', () => {
  it('returns true for SQLSTATE 42501', () => {
    const driver = postgresJsDriver(makeMockSql(makeResult([], 'SELECT', 0)));

    const err = Object.assign(new Error('permission denied'), {
      code: '42501',
    });

    expect(driver.isInsufficientPrivilege(err)).toBe(true);
  });

  it('returns false for other SQLSTATEs', () => {
    const driver = postgresJsDriver(makeMockSql(makeResult([], 'SELECT', 0)));

    expect(
      driver.isInsufficientPrivilege(
        Object.assign(new Error('syntax'), { code: '42601' }),
      ),
    ).toBe(false);
  });

  it('returns false for non-Error inputs', () => {
    const driver = postgresJsDriver(makeMockSql(makeResult([], 'SELECT', 0)));

    expect(driver.isInsufficientPrivilege(null)).toBe(false);
    expect(driver.isInsufficientPrivilege(undefined)).toBe(false);
    expect(driver.isInsufficientPrivilege('42501')).toBe(false);
    expect(driver.isInsufficientPrivilege({ code: 42501 })).toBe(false);
  });
});
