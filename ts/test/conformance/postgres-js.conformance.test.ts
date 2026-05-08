/**
 * Conformance suite — `postgres.js` driver.
 *
 * Same conformance matrix as the `pg` suite (same shared
 * `runConformanceTests` helper), wired around a `postgres.Sql`
 * instance instead of a `pg.Client`.
 *
 * postgres.js's tagged-template primary API doesn't fit our
 * raw-SQL-with-params shape; the adapter routes through
 * `sql.unsafe(text, params)`. The conformance suite thus
 * exercises that code path end-to-end against real Postgres.
 *
 * Spins up its own testcontainer (separate from the pg suite's
 * — not shared because Vitest's `fileParallelism: false`
 * serializes file execution but doesn't share state across
 * files).
 */
import {
  PostgreSqlContainer,
  type StartedPostgreSqlContainer,
} from '@testcontainers/postgresql';
import postgres from 'postgres';
import { afterAll, beforeAll, describe } from 'vitest';

import { PgrlsTestClient, postgresJsDriver } from '../../src/index.js';

import { runConformanceTests } from './_helpers.js';

let container: StartedPostgreSqlContainer | null = null;
let sql: ReturnType<typeof postgres> | null = null;

beforeAll(async () => {
  container = await new PostgreSqlContainer('postgres:17-alpine').start();
  // Single connection so the SET LOCAL ROLE / GUC state from
  // the conformance criteria 1+2 actually persists within a
  // transaction. postgres.js defaults to a pool of 10; force 1
  // to mirror the pg.Client semantics.
  sql = postgres(container.getConnectionUri(), { max: 1 });
}, 60_000);

afterAll(async () => {
  if (sql !== null) {
    await sql.end({ timeout: 5 });
  }
  if (container !== null) {
    await container.stop();
  }
});

describe('postgres.js driver — conformance', () => {
  runConformanceTests(() => {
    if (sql === null) {
      throw new Error('postgres.js sql not initialized');
    }
    return new PgrlsTestClient(postgresJsDriver(sql));
  });
});
