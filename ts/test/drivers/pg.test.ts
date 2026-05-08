/**
 * Unit tests for the `pg` (node-postgres) driver adapter.
 *
 * Driven by a hand-rolled mock that satisfies `PgQueryable`,
 * not by a real Postgres. The conformance suite in step 6
 * exercises the same adapter end-to-end against a real DB
 * to pin wire-level behaviour; these tests pin the
 * normalization layer (command tag → uppercase, null
 * rowCount → 0, error-code predicate, etc.).
 */
import { describe, expect, it, vi } from 'vitest';

import { pgDriver, type PgQueryable } from '../../src/index.js';

/**
 * Build a mock pg client whose `query` returns the given
 * canned result. Records every call for assertion access.
 */
function makeMockClient(canned: {
  rows?: Record<string, unknown>[];
  command?: string;
  rowCount?: number | null;
}): PgQueryable & { calls: { text: string; values?: readonly unknown[] }[] } {
  const calls: { text: string; values?: readonly unknown[] }[] = [];
  return {
    calls,
    query: vi.fn(async (text: string, values?: readonly unknown[]) => {
      calls.push(values === undefined ? { text } : { text, values });
      return await Promise.resolve({
        rows: canned.rows ?? [],
        command: canned.command ?? '',
        rowCount: canned.rowCount ?? null,
      });
    }),
  };
}

describe('pgDriver — query', () => {
  it('forwards SQL + params to client.query', async () => {
    const mock = makeMockClient({});
    const driver = pgDriver(mock);

    await driver.query('SELECT $1::int', [42]);

    expect(mock.calls).toHaveLength(1);
    expect(mock.calls[0]).toEqual({ text: 'SELECT $1::int', values: [42] });
  });

  it('omits values when no params passed', async () => {
    const mock = makeMockClient({});
    const driver = pgDriver(mock);

    await driver.query('SELECT 1');

    expect(mock.calls[0]).toEqual({ text: 'SELECT 1' });
  });

  it('returns rows verbatim', async () => {
    const mock = makeMockClient({
      rows: [
        { id: 1, name: 'a' },
        { id: 2, name: 'b' },
      ],
      command: 'SELECT',
      rowCount: 2,
    });
    const driver = pgDriver(mock);

    const result = await driver.query('SELECT * FROM t');

    expect(result.rows).toEqual([
      { id: 1, name: 'a' },
      { id: 2, name: 'b' },
    ]);
  });

  it('upper-cases command tag (defensive against pg forks)', async () => {
    const mock = makeMockClient({ command: 'select', rowCount: 0 });
    const driver = pgDriver(mock);

    const result = await driver.query('SELECT 1');

    expect(result.command).toBe('SELECT');
  });

  it('handles empty command string defensively', async () => {
    const mock = makeMockClient({ command: '', rowCount: 0 });
    const driver = pgDriver(mock);

    const result = await driver.query('-- empty');

    expect(result.command).toBe('');
  });

  it('maps null rowCount → 0 (utility-statement case)', async () => {
    const mock = makeMockClient({ command: 'COMMIT', rowCount: null });
    const driver = pgDriver(mock);

    const result = await driver.query('COMMIT');

    expect(result.rowCount).toBe(0);
  });

  it('preserves numeric rowCount for UPDATE/DELETE', async () => {
    const mock = makeMockClient({ command: 'UPDATE', rowCount: 5 });
    const driver = pgDriver(mock);

    const result = await driver.query('UPDATE t SET x = 1');

    expect(result.rowCount).toBe(5);
  });
});

describe('pgDriver — rollback', () => {
  it('issues ROLLBACK via client.query', async () => {
    const mock = makeMockClient({});
    const driver = pgDriver(mock);

    await driver.rollback();

    expect(mock.calls).toEqual([{ text: 'ROLLBACK' }]);
  });
});

describe('pgDriver — isInsufficientPrivilege', () => {
  it('returns true for SQLSTATE 42501', () => {
    const driver = pgDriver(makeMockClient({}));

    const err = Object.assign(new Error('permission denied'), {
      code: '42501',
    });

    expect(driver.isInsufficientPrivilege(err)).toBe(true);
  });

  it('returns false for any other SQLSTATE', () => {
    const driver = pgDriver(makeMockClient({}));

    expect(
      driver.isInsufficientPrivilege(
        Object.assign(new Error('syntax'), { code: '42601' }),
      ),
    ).toBe(false);
    expect(
      driver.isInsufficientPrivilege(
        Object.assign(new Error('serialization'), { code: '40001' }),
      ),
    ).toBe(false);
  });

  it('returns false when error has no code', () => {
    const driver = pgDriver(makeMockClient({}));
    expect(driver.isInsufficientPrivilege(new Error('plain'))).toBe(false);
  });

  it('returns false for non-Error inputs', () => {
    const driver = pgDriver(makeMockClient({}));
    expect(driver.isInsufficientPrivilege(null)).toBe(false);
    expect(driver.isInsufficientPrivilege(undefined)).toBe(false);
    expect(driver.isInsufficientPrivilege('42501')).toBe(false);
    expect(driver.isInsufficientPrivilege({ code: 42501 })).toBe(false);
    expect(driver.isInsufficientPrivilege({ code: '42501', sneaky: 1 })).toBe(true);
  });

  it('rejects numeric 42501 (must be the string)', () => {
    // Pin the type-strict comparison: pg always stringifies
    // SQLSTATE codes; a numeric 42501 sneaking through means
    // someone is forging an error and we shouldn't accept it.
    const driver = pgDriver(makeMockClient({}));
    expect(driver.isInsufficientPrivilege({ code: 42501 })).toBe(false);
  });
});
