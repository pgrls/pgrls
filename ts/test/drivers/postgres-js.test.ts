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

  it('concurrent first-queries share one reservation (race-safe)', async () => {
    // Two queries start before either reservation resolves.
    // The naive `reserved ??= await sql.reserve()` pattern would
    // race: both observers see `null`, both call `reserve()`, the
    // second reservation leaks. The promise-based pinning stores
    // the in-flight promise so both awaits see the same one.
    const mock = makeMockSql(makeResult([], 'SELECT', 0));
    const driver = postgresJsDriver(mock);

    await Promise.all([driver.query('SELECT 1'), driver.query('SELECT 2')]);

    // Exactly one reserve call across both concurrent queries.
    expect(mock.reserve).toHaveBeenCalledTimes(1);
  });

  it('close while reservation is in flight releases on settle', async () => {
    // Edge case: close() called before the lazy reserve has
    // resolved. The implementation should await the in-flight
    // promise and then release, not orphan the reservation.
    const mock = makeMockSql(makeResult([], 'SELECT', 0));
    const driver = postgresJsDriver(mock);

    // Kick off a query but don't await it yet.
    const inFlight = driver.query('SELECT 1');
    // Close immediately. The reservation promise is in flight.
    const closing = driver.close!();
    // Both settle.
    await Promise.all([inFlight, closing]);

    expect(mock.released.count).toBe(1);
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

  it('rejected sql.reserve() does not jam the driver — next query retries', async () => {
    // If `sql.reserve()` rejects (closed pool, timeout, etc.)
    // the rejection must propagate out of the failing `query()`
    // call AND the cached promise must be cleared so the next
    // `query()` retries `sql.reserve()` instead of replaying
    // the same rejection forever.
    const mock = makeMockSql(makeResult([], 'SELECT', 0));
    // Override reserve to reject once, then resolve.
    const reserved = await mock.reserve();
    let callCount = 0;
    const reserveSpy = vi.fn(() => {
      callCount += 1;
      if (callCount === 1) {
        return Promise.reject(new Error('connection refused'));
      }
      return Promise.resolve(reserved);
    });
    mock.reserve = reserveSpy;

    const driver = postgresJsDriver(mock);

    // First query fails with the reservation error.
    await expect(driver.query('SELECT 1')).rejects.toThrow('connection refused');

    // Second query succeeds — the driver retried.
    await driver.query('SELECT 2');

    expect(reserveSpy).toHaveBeenCalledTimes(2);
  });

  it('late rejection of P1 does not clobber a P2 reservation taken after close', async () => {
    // Subtle race regression caught in iter 4:
    //   1. query1() kicks off P1 = sql.reserve() that will reject.
    //   2. close() copies P1, sets reservedPromise = null, awaits.
    //   3. query2() runs BEFORE P1's .catch fires: sees
    //      reservedPromise = null, kicks off P2 = sql.reserve()
    //      that succeeds; reservedPromise = P2.
    //   4. P1's .catch fires LATE. Without the identity guard it
    //      would unconditionally write reservedPromise = null,
    //      clobbering P2. A later close() would then see
    //      reservedPromise === null and not release P2 → leak.
    // The fix's identity check makes P1's .catch a no-op when
    // reservedPromise no longer points at the rejecting promise.
    const mock = makeMockSql(makeResult([], 'SELECT', 0));
    const reserved = await mock.reserve();
    // Hold the rejection back via a settler so we can sequence
    // the catch firing AFTER P2 is in place. Initial assignment
    // is a noop-throw so TypeScript sees a definite assignment
    // without needing `let rejectP1!: ...`.
    let rejectP1: (err: Error) => void = () => {
      throw new Error('rejectP1 not yet assigned');
    };
    const p1 = new Promise<typeof reserved>((_, reject) => {
      rejectP1 = reject;
    });
    let callCount = 0;
    mock.reserve = vi.fn(() => {
      callCount += 1;
      if (callCount === 1) {
        return p1;
      }
      return Promise.resolve(reserved);
    });

    const driver = postgresJsDriver(mock);

    // 1. Start query1 → kicks off P1 (pending).
    const query1 = driver.query('SELECT 1');
    // 2. close() copies P1, clears reservedPromise, awaits P1.
    const close1 = driver.close!();
    // 3. query2 starts before P1 settles → kicks off P2.
    const query2 = driver.query('SELECT 2');
    // 4. Now reject P1. Its catch fires AFTER P2 is in place.
    rejectP1(new Error('connection refused'));

    // query1 sees its rejection; close1 swallows it.
    await expect(query1).rejects.toThrow('connection refused');
    await expect(close1).resolves.toBeUndefined();
    // query2 must succeed against P2.
    await query2;

    // Now close() must release P2. If the identity guard were
    // missing, P1's late .catch would have nulled reservedPromise
    // and this close() would be a no-op → released.count stays 0.
    await driver.close!();
    expect(mock.released.count).toBe(1);
  });

  it('close() after rejected reservation swallows the rejection', async () => {
    // `try { exec(...) } finally { await close() }` is the
    // recommended usage pattern. If the original exec failed
    // because reserve rejected, close() must NOT re-throw the
    // same rejection — that would mask the original error.
    const mock = makeMockSql(makeResult([], 'SELECT', 0));
    mock.reserve = vi.fn(() => Promise.reject(new Error('reserve failed')));

    const driver = postgresJsDriver(mock);

    // Provoke a rejected query without awaiting.
    const queryPromise = driver.query('SELECT 1');
    // close() must resolve, not throw the reservation error.
    await expect(driver.close!()).resolves.toBeUndefined();
    // The original query still rejects with its actual error.
    await expect(queryPromise).rejects.toThrow('reserve failed');
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
