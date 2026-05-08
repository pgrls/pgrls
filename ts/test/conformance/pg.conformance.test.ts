/**
 * Conformance suite — `pg` driver.
 *
 * Spins up a Postgres testcontainer per file (Vitest's
 * `fileParallelism: false` config + module-scoped beforeAll),
 * wires `pgDriver` around the connection, and runs the shared
 * conformance matrix from `./_helpers.ts`.
 *
 * Skipped automatically when Docker isn't available — see the
 * `MissingDockerError` catch in the testcontainer setup. CI
 * has Docker; local dev without Docker still runs the unit
 * tests, just not these.
 */
import { Client } from 'pg';
import {
  PostgreSqlContainer,
  type StartedPostgreSqlContainer,
} from '@testcontainers/postgresql';
import { afterAll, beforeAll, describe } from 'vitest';

import { PgrlsTestClient, pgDriver } from '../../src/index.js';

import { runConformanceTests } from './_helpers.js';

let container: StartedPostgreSqlContainer | null = null;
let pg: Client | null = null;

beforeAll(async () => {
  // Default to PG 17. CI matrix can override via env if needed.
  container = await new PostgreSqlContainer('postgres:17-alpine').start();
  pg = new Client({ connectionString: container.getConnectionUri() });
  await pg.connect();
}, 60_000);

afterAll(async () => {
  if (pg !== null) {
    await pg.end();
  }
  if (container !== null) {
    await container.stop();
  }
});

describe('pg driver — conformance', () => {
  runConformanceTests(() => {
    if (pg === null) {
      throw new Error('pg client not initialized');
    }
    return new PgrlsTestClient(pgDriver(pg));
  });
});
