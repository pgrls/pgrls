/**
 * Unit tests for `PgrlsTestClient`.
 *
 * Driven by a "recording driver" — a mock `Driver` that
 * captures every SQL string and parameter list, plus lets each
 * test program canned responses to specific queries (e.g.
 * `SELECT current_user, current_setting(...)` returns
 * `[{ current_user: 'admin', claims: '' }]`).
 *
 * Conformance suite in step 6 exercises the same client against
 * a real Postgres testcontainer to pin wire-level behaviour;
 * these tests pin the SQL the client emits and the order it
 * emits it in.
 */
import { describe, expect, it } from 'vitest';

import { PgrlsTestClient, PgrlsTestError } from '../src/index.js';

import { captureResponse, makeRecordingDriver } from './_recording-driver.js';

describe('PgrlsTestClient — transaction', () => {
  it('issues BEGIN before body, ROLLBACK after', async () => {
    const driver = makeRecordingDriver();
    const client = new PgrlsTestClient(driver);

    await client.transaction(async () => {
      await client.exec('SELECT 1');
    });

    expect(driver.calls.map((c) => c.sql)).toEqual(['BEGIN', 'SELECT 1', 'ROLLBACK']);
  });

  it('rolls back even when body throws', async () => {
    const driver = makeRecordingDriver();
    const client = new PgrlsTestClient(driver);

    const err = new Error('oops');
    await expect(
      client.transaction(async () => {
        await client.exec('SELECT 1');
        throw err;
      }),
    ).rejects.toThrow(err);

    expect(driver.calls.at(-1)?.sql).toBe('ROLLBACK');
  });

  it('returns the body result on clean exit', async () => {
    const driver = makeRecordingDriver();
    const client = new PgrlsTestClient(driver);

    const result = await client.transaction(() => Promise.resolve(42));

    expect(result).toBe(42);
  });
});

describe('PgrlsTestClient — exec', () => {
  it('forwards SQL + params to the driver', async () => {
    const driver = makeRecordingDriver();
    const client = new PgrlsTestClient(driver);

    await client.exec('UPDATE t SET x = $1 WHERE id = $2', [1, 2]);

    expect(driver.calls).toEqual([
      { sql: 'UPDATE t SET x = $1 WHERE id = $2', params: [1, 2] },
    ]);
  });

  it('defaults to empty params', async () => {
    const driver = makeRecordingDriver();
    const client = new PgrlsTestClient(driver);

    await client.exec('SELECT 1');

    expect(driver.calls[0]?.params).toEqual([]);
  });
});

describe('PgrlsTestClient — fetchAll', () => {
  it('returns the driver rows as a typed array', async () => {
    const driver = makeRecordingDriver();
    driver.on('SELECT * FROM users', () => ({
      rows: [
        { id: 1, name: 'a' },
        { id: 2, name: 'b' },
      ],
      command: 'SELECT',
      rowCount: 2,
    }));
    const client = new PgrlsTestClient(driver);

    const rows = await client.fetchAll<{ id: number; name: string }>(
      'SELECT * FROM users',
    );

    expect(rows).toEqual([
      { id: 1, name: 'a' },
      { id: 2, name: 'b' },
    ]);
  });

  it('returns empty array when no rows', async () => {
    const driver = makeRecordingDriver();
    const client = new PgrlsTestClient(driver);

    const rows = await client.fetchAll('SELECT 1 WHERE false');

    expect(rows).toEqual([]);
  });
});

describe('PgrlsTestClient — asRole (entry sequence)', () => {
  it('emits SELECT capture, SAVEPOINT, SET LOCAL ROLE, body, RELEASE, restore', async () => {
    const driver = makeRecordingDriver();
    driver.on('SELECT current_user', () => captureResponse('admin', null));
    const client = new PgrlsTestClient(driver);

    await client.asRole('app_authenticated', { claims: null }, async () => {
      await client.exec('SELECT * FROM t');
    });

    const sqls = driver.calls.map((c) => c.sql);
    // 1. capture
    expect(sqls[0]).toMatch(/SELECT current_user/);
    // 2. SAVEPOINT pgrls_actor_<random>
    expect(sqls[1]).toMatch(/^SAVEPOINT pgrls_actor_[0-9a-f]{8}$/);
    // 3. SET LOCAL ROLE app_authenticated
    expect(sqls[2]).toBe('SET LOCAL ROLE app_authenticated');
    // 4. body
    expect(sqls[3]).toBe('SELECT * FROM t');
    // 5. RELEASE SAVEPOINT pgrls_actor_<random>
    expect(sqls[4]).toMatch(/^RELEASE SAVEPOINT pgrls_actor_[0-9a-f]{8}$/);
    // 6. restore prior role
    expect(sqls[5]).toBe('SET LOCAL ROLE admin');
    // 7. no claims to restore (prior had none, inner didn't set any)
    expect(sqls).toHaveLength(6);
  });

  it('quotes role names that need it', async () => {
    const driver = makeRecordingDriver();
    driver.on('SELECT current_user', () => captureResponse('admin', null));
    const client = new PgrlsTestClient(driver);

    await client.asRole('select', { claims: null }, async () => {
      await Promise.resolve();
    });

    // 'select' is reserved → quoted.
    const setRole = driver.calls.find((c) => c.sql.startsWith('SET LOCAL ROLE'));
    expect(setRole?.sql).toBe('SET LOCAL ROLE "select"');
  });

  it('sets claims when claims is non-null', async () => {
    const driver = makeRecordingDriver();
    driver.on('SELECT current_user', () => captureResponse('admin', null));
    const client = new PgrlsTestClient(driver);

    await client.asRole(
      'app_authenticated',
      { claims: { sub: 'user-a', tenant_id: 't1' } },
      async () => {
        await Promise.resolve();
      },
    );

    const setConfig = driver.calls.find(
      (c) => c.sql.includes('set_config') && c.sql.includes('request.jwt.claims'),
    );
    expect(setConfig).toBeDefined();
    expect(setConfig?.params).toEqual([
      JSON.stringify({ sub: 'user-a', tenant_id: 't1' }),
    ]);
  });

  it('sends `{}` (not omits) when claims is the empty object', async () => {
    // Pin the protocol distinction: `{}` is "actor with no
    // claims", `null` is "don't touch the GUC".
    const driver = makeRecordingDriver();
    driver.on('SELECT current_user', () => captureResponse('admin', null));
    const client = new PgrlsTestClient(driver);

    await client.asRole('app_authenticated', { claims: {} }, async () => {
      await Promise.resolve();
    });

    const setConfig = driver.calls.find((c) => c.sql.includes('set_config'));
    expect(setConfig).toBeDefined();
    expect(setConfig?.params).toEqual(['{}']);
  });

  it('skips set_config when claims is null', async () => {
    const driver = makeRecordingDriver();
    driver.on('SELECT current_user', () => captureResponse('admin', null));
    const client = new PgrlsTestClient(driver);

    await client.asRole('app_authenticated', { claims: null }, async () => {
      await Promise.resolve();
    });

    const setConfig = driver.calls.find(
      (c) =>
        c.sql.includes('set_config') &&
        c.sql.includes('request.jwt.claims') &&
        // Filter out the *clearing* call (which DOES use
        // set_config but with NULL value, not the JSON form).
        c.params.length === 1,
    );
    expect(setConfig).toBeUndefined();
  });

  it('treats undefined claims like null (skips set_config)', async () => {
    const driver = makeRecordingDriver();
    driver.on('SELECT current_user', () => captureResponse('admin', null));
    const client = new PgrlsTestClient(driver);

    // No claims property at all.
    await client.asRole('app_authenticated', {}, async () => {
      await Promise.resolve();
    });

    const setConfig = driver.calls.find(
      (c) => c.sql.includes('set_config') && c.params.length === 1,
    );
    expect(setConfig).toBeUndefined();
  });
});

describe('PgrlsTestClient — asRole (clean-exit restore)', () => {
  it('restores prior claims when outer had claims', async () => {
    const driver = makeRecordingDriver();
    driver.on('SELECT current_user', () =>
      captureResponse('admin', '{"sub":"outer-user"}'),
    );
    const client = new PgrlsTestClient(driver);

    await client.asRole(
      'app_authenticated',
      { claims: { sub: 'inner-user' } },
      async () => {
        await Promise.resolve();
      },
    );

    // After RELEASE SAVEPOINT, two restore calls: SET LOCAL
    // ROLE admin, then set_config('request.jwt.claims',
    // '{"sub":"outer-user"}', true).
    const releaseIdx = driver.calls.findIndex((c) =>
      c.sql.startsWith('RELEASE SAVEPOINT'),
    );
    expect(releaseIdx).toBeGreaterThan(-1);
    const after = driver.calls.slice(releaseIdx + 1);
    expect(after[0]?.sql).toBe('SET LOCAL ROLE admin');
    expect(after[1]?.sql).toContain('set_config');
    expect(after[1]?.params).toEqual(['{"sub":"outer-user"}']);
  });

  it('clears claims when outer had none but inner set them', async () => {
    const driver = makeRecordingDriver();
    driver.on('SELECT current_user', () => captureResponse('admin', null));
    const client = new PgrlsTestClient(driver);

    await client.asRole(
      'app_authenticated',
      { claims: { sub: 'inner-user' } },
      async () => {
        await Promise.resolve();
      },
    );

    // Look for the clearing call: set_config('request.jwt.claims', NULL, true)
    const clearCall = driver.calls.find(
      (c) =>
        c.sql.includes('set_config') &&
        c.sql.includes('request.jwt.claims') &&
        c.sql.includes('NULL'),
    );
    expect(clearCall).toBeDefined();
  });

  it('issues no claims-restore when both outer and inner had no claims', async () => {
    const driver = makeRecordingDriver();
    driver.on('SELECT current_user', () => captureResponse('admin', null));
    const client = new PgrlsTestClient(driver);

    await client.asRole('app_authenticated', { claims: null }, async () => {
      await Promise.resolve();
    });

    // Only set_config calls would be the restoration. With
    // both ends having no claims, there should be none.
    const setConfigs = driver.calls.filter((c) => c.sql.includes('set_config'));
    expect(setConfigs).toEqual([]);
  });
});

describe('PgrlsTestClient — asRole (exception path)', () => {
  it('issues ROLLBACK TO SAVEPOINT instead of RELEASE on body throw', async () => {
    const driver = makeRecordingDriver();
    driver.on('SELECT current_user', () => captureResponse('admin', null));
    const client = new PgrlsTestClient(driver);

    const err = new Error('body failed');
    await expect(
      client.asRole('app_authenticated', { claims: null }, () => {
        return Promise.reject(err);
      }),
    ).rejects.toThrow(err);

    const lastSql = driver.calls.at(-1)?.sql;
    expect(lastSql).toMatch(/^ROLLBACK TO SAVEPOINT pgrls_actor_/);
    // No RELEASE on the exception path.
    expect(driver.calls.some((c) => c.sql.startsWith('RELEASE'))).toBe(false);
  });

  it('does not issue restore-role queries on exception path', async () => {
    // ROLLBACK TO SAVEPOINT auto-restores SET LOCAL state, so
    // we don't need (and shouldn't issue) explicit SET LOCAL
    // ROLE / set_config calls after.
    const driver = makeRecordingDriver();
    driver.on('SELECT current_user', () => captureResponse('admin', null));
    const client = new PgrlsTestClient(driver);

    await expect(
      client.asRole('app_authenticated', { claims: null }, () => {
        return Promise.reject(new Error('boom'));
      }),
    ).rejects.toThrow();

    // Only one SET LOCAL ROLE call — the entry one. No
    // restore call after rollback.
    const setRoles = driver.calls.filter((c) => c.sql.startsWith('SET LOCAL ROLE'));
    expect(setRoles).toHaveLength(1);
  });
});

describe('PgrlsTestClient — asRole (capture-row failures)', () => {
  it('throws PgrlsTestError when capture query returns no row', async () => {
    const driver = makeRecordingDriver();
    driver.on('SELECT current_user', () => ({
      rows: [],
      command: 'SELECT',
      rowCount: 0,
    }));
    const client = new PgrlsTestClient(driver);

    await expect(
      client.asRole('x', { claims: null }, async () => {
        await Promise.resolve();
      }),
    ).rejects.toThrow(PgrlsTestError);
  });
});

describe('PgrlsTestClient — seed', () => {
  it('issues one INSERT per row with positional params', async () => {
    const driver = makeRecordingDriver();
    const client = new PgrlsTestClient(driver);

    await client.seed('app.invoices', [
      { tenant_id: 't1', amount: 100 },
      { tenant_id: 't2', amount: 200 },
    ]);

    const inserts = driver.calls.filter((c) => c.sql.startsWith('INSERT'));
    expect(inserts).toHaveLength(2);
    expect(inserts[0]?.sql).toBe(
      'INSERT INTO app.invoices (tenant_id, amount) VALUES ($1, $2)',
    );
    expect(inserts[0]?.params).toEqual(['t1', 100]);
    expect(inserts[1]?.params).toEqual(['t2', 200]);
  });

  it('quotes mixed-case schema and table names', async () => {
    const driver = makeRecordingDriver();
    const client = new PgrlsTestClient(driver);

    await client.seed('app.MixedCase Table', [{ id: 1 }]);

    const insert = driver.calls.find((c) => c.sql.startsWith('INSERT'));
    expect(insert?.sql).toBe('INSERT INTO app."MixedCase Table" (id) VALUES ($1)');
  });

  it('quotes column names that need it', async () => {
    const driver = makeRecordingDriver();
    const client = new PgrlsTestClient(driver);

    await client.seed('users', [{ select: 'x', 'weird col': 'y' }]);

    const insert = driver.calls.find((c) => c.sql.startsWith('INSERT'));
    expect(insert?.sql).toBe('INSERT INTO users ("select", "weird col") VALUES ($1, $2)');
  });

  it('handles unqualified table names', async () => {
    const driver = makeRecordingDriver();
    const client = new PgrlsTestClient(driver);

    await client.seed('users', [{ id: 1 }]);

    const insert = driver.calls.find((c) => c.sql.startsWith('INSERT'));
    expect(insert?.sql).toBe('INSERT INTO users (id) VALUES ($1)');
  });

  it('is a no-op when rows is empty', async () => {
    const driver = makeRecordingDriver();
    const client = new PgrlsTestClient(driver);

    await client.seed('users', []);

    expect(driver.calls).toEqual([]);
  });

  it('throws PgrlsTestError when rows have inconsistent keys', async () => {
    const driver = makeRecordingDriver();
    const client = new PgrlsTestClient(driver);

    await expect(
      client.seed('users', [
        { a: 1, b: 2 },
        { a: 1, c: 3 },
      ]),
    ).rejects.toThrow(PgrlsTestError);
    await expect(client.seed('users', [{ a: 1 }, { a: 1, b: 2 }])).rejects.toThrow(
      PgrlsTestError,
    );
  });

  it('throws PgrlsTestError on multi-dot table name', async () => {
    const driver = makeRecordingDriver();
    const client = new PgrlsTestClient(driver);

    await expect(client.seed('db.schema.table', [{ id: 1 }])).rejects.toThrow(
      PgrlsTestError,
    );
    await expect(client.seed('db.schema.table', [{ id: 1 }])).rejects.toThrow(
      /Cross-database/,
    );
  });

  it('throws PgrlsTestError on empty schema or table component', async () => {
    const driver = makeRecordingDriver();
    const client = new PgrlsTestClient(driver);

    await expect(client.seed('.foo', [{ id: 1 }])).rejects.toThrow(PgrlsTestError);
    await expect(client.seed('foo.', [{ id: 1 }])).rejects.toThrow(PgrlsTestError);
    await expect(client.seed('', [{ id: 1 }])).rejects.toThrow(PgrlsTestError);
  });
});
