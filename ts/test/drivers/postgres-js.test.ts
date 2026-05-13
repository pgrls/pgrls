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
/* eslint-disable @typescript-eslint/unbound-method --
 * Test-only: vi.Mock spies are read directly off the mock
 * object to assert `toHaveBeenCalled` etc. The unbound-method
 * rule's "the method might forget its `this`" concern doesn't
 * apply — these are vi spies, not the original methods, and
 * the test never invokes them through the read reference.
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
 * Records every call. `reserve()` returns a reserved-shaped
 * proxy that forwards `unsafe` to the same recorder and
 * exposes a `release()` we can spy on (v0.6.2+: the adapter
 * lazily reserves a connection on first query).
 */
function makeMockSql(canned: PostgresJsResult<Record<string, unknown>>): PostgresJsSql & {
  calls: { text: string; params?: readonly unknown[] }[];
  released: { count: number };
} {
  const calls: { text: string; params?: readonly unknown[] }[] = [];
  const released = { count: 0 };
  const unsafe = vi.fn(async (text: string, params?: readonly unknown[]) => {
    calls.push(params === undefined ? { text } : { text, params });
    return await Promise.resolve(canned);
  }) as unknown as PostgresJsSql['unsafe'];
  // Reserved variant: same `unsafe` recorder + a chained
  // `reserve()` (the postgres.js type extends Sql, so a
  // ReservedSql is itself a Sql with `release()` tacked on)
  // and a `release()` that increments the counter. Arrow
  // functions (not `vi.fn`) so the lint rule that warns
  // about unbound method scoping doesn't fire on the mock —
  // these are test plumbing, not assertion subjects.
  const reserved = {
    calls,
    released,
    unsafe,
    reserve: () => Promise.resolve(reserved),
    release: () => {
      released.count += 1;
    },
  };
  return {
    calls,
    released,
    unsafe,
    reserve: vi.fn(() => Promise.resolve(reserved)),
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

describe('postgresJsDriver — connection pinning (v0.6.2+)', () => {
  it('lazily reserves a connection on first query', async () => {
    const mock = makeMockSql(makeResult([], 'SELECT', 0));
    const driver = postgresJsDriver(mock);

    // Before any query, no reservation yet.
    expect(mock.reserve).not.toHaveBeenCalled();

    await driver.query('SELECT 1');

    // One reservation, used for the first query.
    expect(mock.reserve).toHaveBeenCalledTimes(1);
  });

  it('reuses the reserved connection across multiple queries', async () => {
    const mock = makeMockSql(makeResult([], 'SELECT', 0));
    const driver = postgresJsDriver(mock);

    await driver.query('SELECT 1');
    await driver.query('SELECT 2');
    await driver.query('SELECT 3');

    // One reserve call total — the adapter caches the
    // reservation and reuses it. Without this caching,
    // BEGIN/queries/ROLLBACK would scatter across pool
    // connections and the transaction would break.
    expect(mock.reserve).toHaveBeenCalledTimes(1);
  });

  it('rollback uses the same pinned connection', async () => {
    const mock = makeMockSql(makeResult([], 'ROLLBACK', 0));
    const driver = postgresJsDriver(mock);

    await driver.query('BEGIN');
    await driver.rollback();

    // One reservation, two queries (BEGIN + ROLLBACK) on the
    // same pinned connection.
    expect(mock.reserve).toHaveBeenCalledTimes(1);
    expect(mock.calls.map((c) => c.text)).toEqual(['BEGIN', 'ROLLBACK']);
  });

  it('close() releases the reserved connection', async () => {
    const mock = makeMockSql(makeResult([], 'SELECT', 0));
    const driver = postgresJsDriver(mock);

    await driver.query('SELECT 1');
    expect(mock.released.count).toBe(0);

    await driver.close!();
    expect(mock.released.count).toBe(1);
  });

  it('close() is idempotent', async () => {
    const mock = makeMockSql(makeResult([], 'SELECT', 0));
    const driver = postgresJsDriver(mock);

    await driver.query('SELECT 1');
    await driver.close!();
    await driver.close!();
    await driver.close!();

    // First close released the reservation; subsequent
    // closes are no-ops.
    expect(mock.released.count).toBe(1);
  });

  it('close() without any prior query is a no-op', async () => {
    const mock = makeMockSql(makeResult([], 'SELECT', 0));
    const driver = postgresJsDriver(mock);

    await driver.close!();

    expect(mock.reserve).not.toHaveBeenCalled();
    expect(mock.released.count).toBe(0);
  });

  it('query after close re-reserves a fresh connection', async () => {
    const mock = makeMockSql(makeResult([], 'SELECT', 0));
    const driver = postgresJsDriver(mock);

    await driver.query('SELECT 1');
    await driver.close!();
    await driver.query('SELECT 2');

    // Two reservations: one before close, one after. Useful
    // for test harnesses that recycle a driver across cases.
    expect(mock.reserve).toHaveBeenCalledTimes(2);
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
