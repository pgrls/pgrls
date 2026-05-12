/**
 * Unit tests for the 5 RLS-specific assertion helpers.
 *
 * Mirrors `tests/testing/test_assertions.py` (Python). Pin
 * the same pass/fail semantics so cross-language tests can
 * compare exception flow byte-for-byte.
 */
import { describe, expect, it } from 'vitest';

import {
  PgrlsTestAssertionError,
  PgrlsTestClient,
  PgrlsTestError,
} from '../src/index.js';

import { makeRecordingDriver, selectRows as rows } from './_recording-driver.js';

describe('assertRows', () => {
  it('passes when count matches', async () => {
    const driver = makeRecordingDriver();
    driver.on('SELECT', () => rows({ id: 1 }, { id: 2 }));
    const client = new PgrlsTestClient(driver);

    await expect(
      client.assertRows('SELECT id FROM t', { count: 2 }),
    ).resolves.toBeUndefined();
  });

  it('throws PgrlsTestAssertionError on count mismatch', async () => {
    const driver = makeRecordingDriver();
    driver.on('SELECT', () => rows({ id: 1 }));
    const client = new PgrlsTestClient(driver);

    await expect(client.assertRows('SELECT id FROM t', { count: 2 })).rejects.toThrow(
      PgrlsTestAssertionError,
    );
    await expect(client.assertRows('SELECT id FROM t', { count: 2 })).rejects.toThrow(
      /expected 2 row\(s\), got 1/,
    );
  });

  it('count: 0 passes for empty result', async () => {
    const driver = makeRecordingDriver();
    const client = new PgrlsTestClient(driver);

    await expect(
      client.assertRows('SELECT 1 WHERE false', { count: 0 }),
    ).resolves.toBeUndefined();
  });
});

describe('assertVisible', () => {
  it('passes when at least one row', async () => {
    const driver = makeRecordingDriver();
    driver.on('SELECT', () => rows({ id: 1 }));
    const client = new PgrlsTestClient(driver);

    await expect(client.assertVisible('SELECT * FROM t')).resolves.toBeUndefined();
  });

  it('throws PgrlsTestAssertionError on empty result', async () => {
    const driver = makeRecordingDriver();
    const client = new PgrlsTestClient(driver);

    await expect(client.assertVisible('SELECT * FROM t')).rejects.toThrow(
      PgrlsTestAssertionError,
    );
    await expect(client.assertVisible('SELECT * FROM t')).rejects.toThrow(
      /expected at least 1 row/,
    );
  });
});

describe('assertInvisible', () => {
  it('passes when zero rows', async () => {
    const driver = makeRecordingDriver();
    const client = new PgrlsTestClient(driver);

    await expect(client.assertInvisible('SELECT * FROM t')).resolves.toBeUndefined();
  });

  it('throws PgrlsTestAssertionError when any rows present', async () => {
    const driver = makeRecordingDriver();
    driver.on('SELECT', () => rows({ id: 1 }, { id: 2 }));
    const client = new PgrlsTestClient(driver);

    await expect(client.assertInvisible('SELECT * FROM t')).rejects.toThrow(
      PgrlsTestAssertionError,
    );
    await expect(client.assertInvisible('SELECT * FROM t')).rejects.toThrow(
      /expected 0 rows, got 2/,
    );
  });
});

describe('assertRejected', () => {
  it('passes when query throws InsufficientPrivilege', async () => {
    const driver = makeRecordingDriver();
    const err = Object.assign(new Error('permission denied'), { code: '42501' });
    driver.on('INSERT', () => err);
    const client = new PgrlsTestClient(driver);

    await expect(
      client.assertRejected("INSERT INTO t VALUES ('x')"),
    ).resolves.toBeUndefined();

    // Pin the savepoint sequence: SAVEPOINT, INSERT, ROLLBACK TO SAVEPOINT.
    expect(driver.calls.map((c) => c.sql)).toEqual([
      expect.stringMatching(/^SAVEPOINT pgrls_check_/),
      "INSERT INTO t VALUES ('x')",
      expect.stringMatching(/^ROLLBACK TO SAVEPOINT pgrls_check_/),
    ]);
  });

  it('throws PgrlsTestAssertionError when query succeeds', async () => {
    const driver = makeRecordingDriver();
    const client = new PgrlsTestClient(driver);

    await expect(client.assertRejected("INSERT INTO t VALUES ('x')")).rejects.toThrow(
      PgrlsTestAssertionError,
    );
    await expect(client.assertRejected("INSERT INTO t VALUES ('x')")).rejects.toThrow(
      /succeeded but expected RLS rejection/,
    );

    // Successful path: SAVEPOINT, INSERT, RELEASE.
    const releases = driver.calls.filter((c) => c.sql.startsWith('RELEASE SAVEPOINT'));
    expect(releases.length).toBeGreaterThan(0);
  });

  it('throws PgrlsTestAssertionError on different error code', async () => {
    const driver = makeRecordingDriver();
    const err = Object.assign(new Error('syntax error'), { code: '42601' });
    driver.on('UPDATE', () => err);
    const client = new PgrlsTestClient(driver);

    await expect(client.assertRejected('UPDATE t SET x = 1')).rejects.toThrow(
      PgrlsTestAssertionError,
    );
    await expect(client.assertRejected('UPDATE t SET x = 1')).rejects.toThrow(
      /expected InsufficientPrivilege/,
    );

    // Wrong-error path still rolls back the savepoint so the
    // outer transaction can continue after.
    const rollbacks = driver.calls.filter((c) =>
      c.sql.startsWith('ROLLBACK TO SAVEPOINT'),
    );
    expect(rollbacks.length).toBeGreaterThan(0);
  });
});

describe('assertSilentlyDropped', () => {
  it('passes when UPDATE … RETURNING yields zero rows', async () => {
    const driver = makeRecordingDriver();
    driver.on('UPDATE', () => ({
      rows: [],
      command: 'UPDATE',
      rowCount: 0,
    }));
    const client = new PgrlsTestClient(driver);

    await expect(
      client.assertSilentlyDropped('UPDATE t SET x = 1 RETURNING id'),
    ).resolves.toBeUndefined();
  });

  it('passes when DELETE … RETURNING yields zero rows', async () => {
    const driver = makeRecordingDriver();
    driver.on('DELETE', () => ({
      rows: [],
      command: 'DELETE',
      rowCount: 0,
    }));
    const client = new PgrlsTestClient(driver);

    await expect(
      client.assertSilentlyDropped('DELETE FROM t RETURNING id'),
    ).resolves.toBeUndefined();
  });

  it('throws PgrlsTestAssertionError when UPDATE returns rows', async () => {
    const driver = makeRecordingDriver();
    driver.on('UPDATE', () => ({
      rows: [{ id: 1 }],
      command: 'UPDATE',
      rowCount: 1,
    }));
    const client = new PgrlsTestClient(driver);

    await expect(
      client.assertSilentlyDropped('UPDATE t SET x = 1 RETURNING id'),
    ).rejects.toThrow(PgrlsTestAssertionError);
    await expect(
      client.assertSilentlyDropped('UPDATE t SET x = 1 RETURNING id'),
    ).rejects.toThrow(/expected RETURNING to yield 0 rows, got 1/);
  });

  it('throws PgrlsTestError on SELECT', async () => {
    const driver = makeRecordingDriver();
    driver.on('SELECT', () => ({
      rows: [],
      command: 'SELECT',
      rowCount: 0,
    }));
    const client = new PgrlsTestClient(driver);

    await expect(client.assertSilentlyDropped('SELECT * FROM t')).rejects.toThrow(
      PgrlsTestError,
    );
    await expect(client.assertSilentlyDropped('SELECT * FROM t')).rejects.toThrow(
      /UPDATE\/DELETE/,
    );
  });

  it('throws PgrlsTestError on INSERT', async () => {
    const driver = makeRecordingDriver();
    driver.on('INSERT', () => ({
      rows: [{ id: 1 }],
      command: 'INSERT',
      rowCount: 1,
    }));
    const client = new PgrlsTestClient(driver);

    await expect(
      client.assertSilentlyDropped('INSERT INTO t VALUES (1) RETURNING id'),
    ).rejects.toThrow(PgrlsTestError);
    await expect(
      client.assertSilentlyDropped('INSERT INTO t VALUES (1) RETURNING id'),
    ).rejects.toThrow(/INSERT … RETURNING does NOT silently drop/);
  });

  it('error message includes the offending verb', async () => {
    const driver = makeRecordingDriver();
    driver.on('TRUNCATE', () => ({
      rows: [],
      command: 'TRUNCATE',
      rowCount: 0,
    }));
    const client = new PgrlsTestClient(driver);

    await expect(client.assertSilentlyDropped('TRUNCATE t')).rejects.toThrow(/TRUNCATE/);
  });

  it('throws PgrlsTestError when UPDATE has no RETURNING clause', async () => {
    // Pin the missing-RETURNING gate. Without this check, a
    // user typo "UPDATE t SET x = 1" (forgot to add `RETURNING
    // id`) would silently pass whenever RLS filtered all rows
    // — there's no RLS-aware signal in the empty result. Python
    // catches this via `psycopg.ProgrammingError` on
    // `cur.fetchall()`; both pg + postgres.js synthesize an
    // empty array instead, so we detect it via a SQL-regex
    // pre-check on the keyword.
    const driver = makeRecordingDriver();
    driver.on('UPDATE', () => ({
      rows: [],
      command: 'UPDATE',
      rowCount: 0,
    }));
    const client = new PgrlsTestClient(driver);

    await expect(client.assertSilentlyDropped('UPDATE t SET x = 1')).rejects.toThrow(
      PgrlsTestError,
    );
    await expect(client.assertSilentlyDropped('UPDATE t SET x = 1')).rejects.toThrow(
      /requires the SQL to use RETURNING/,
    );
  });

  it('throws PgrlsTestError when DELETE has no RETURNING clause', async () => {
    const driver = makeRecordingDriver();
    driver.on('DELETE', () => ({
      rows: [],
      command: 'DELETE',
      rowCount: 0,
    }));
    const client = new PgrlsTestClient(driver);

    await expect(client.assertSilentlyDropped('DELETE FROM t')).rejects.toThrow(
      PgrlsTestError,
    );
    await expect(client.assertSilentlyDropped('DELETE FROM t')).rejects.toThrow(
      /requires the SQL to use RETURNING/,
    );
  });

  it('RETURNING detection is case-insensitive', async () => {
    // Lowercase `returning` is valid Postgres SQL; the helper
    // must accept it.
    const driver = makeRecordingDriver();
    driver.on('UPDATE', () => ({ rows: [], command: 'UPDATE', rowCount: 0 }));
    const client = new PgrlsTestClient(driver);

    await expect(
      client.assertSilentlyDropped('UPDATE t SET x = 1 returning id'),
    ).resolves.toBeUndefined();
  });

  it('RETURNING detection uses word boundaries', async () => {
    // A column literally named "returning_col" must NOT fool
    // the regex. The `\bRETURNING\b` pattern requires a word
    // boundary on both sides.
    const driver = makeRecordingDriver();
    driver.on('UPDATE', () => ({ rows: [], command: 'UPDATE', rowCount: 0 }));
    const client = new PgrlsTestClient(driver);

    await expect(
      client.assertSilentlyDropped('UPDATE t SET returning_col = 1'),
    ).rejects.toThrow(/requires the SQL to use RETURNING/);
  });
});
