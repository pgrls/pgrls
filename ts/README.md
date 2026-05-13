# pgrls-test

> **Code-first RLS testing for Postgres** — TypeScript port of [`pgrls.testing`](https://github.com/pgrls/pgrls) (Python). Implements the cross-language [Layer 1 protocol](https://github.com/pgrls/pgrls/blob/main/docs/pgrls-test-protocol.md) (`PROTOCOL_VERSION = 1`).

`pgrls-test` lets you write RLS tests with idiomatic JS/TS ergonomics: per-test transactions, role + JWT-claims switching, parameterized SQL execution, and five RLS-specific assertion helpers — all in a small package that wraps your existing Postgres client (no replacement, no fork).

```ts
import { Client } from 'pg';
import { PgrlsTestClient, pgDriver } from 'pgrls-test';

const pg = new Client({ connectionString: process.env.DATABASE_URL });
await pg.connect();
const client = new PgrlsTestClient(pgDriver(pg));

await client.transaction(async () => {
  await client.seed('app.invoices', [
    { tenant_id: 'tenant-a', amount: 100 },
    { tenant_id: 'tenant-b', amount: 200 },
  ]);

  await client.asRole(
    'app_authenticated',
    { claims: { sub: 'user-a', tenant_id: 'tenant-a' } },
    async () => {
      await client.assertRows(
        'SELECT id FROM app.invoices',
        { count: 1 },
      );
      await client.assertRejected(
        "INSERT INTO app.invoices (tenant_id, amount) VALUES ('tenant-b', 999)",
      );
    },
  );
});
```

## Install

```sh
npm install --save-dev pgrls-test pg
# or
npm install --save-dev pgrls-test postgres
```

`pg` and `postgres` (postgres.js) are **optional peer dependencies** — install only the driver you actually use.

| Package | Node | TypeScript |
|---|---|---|
| `pgrls-test` | ≥ 20 | strict mode supported, ESM-only |

## Drivers

Both `pg` (node-postgres) and `postgres.js` are first-class:

```ts
// node-postgres:
import { Client } from 'pg';
import { PgrlsTestClient, pgDriver } from 'pgrls-test';

const pg = new Client({ connectionString: url });
await pg.connect();
const client = new PgrlsTestClient(pgDriver(pg));

// postgres.js (v0.6.2+ pins one pool connection internally
// via sql.reserve() — no need for { max: 1 } anymore):
import postgres from 'postgres';
import { PgrlsTestClient, postgresJsDriver } from 'pgrls-test';

const sql = postgres(url);
const client = new PgrlsTestClient(postgresJsDriver(sql));
try {
  // ... run tests ...
} finally {
  await client.close(); // release the pinned pool connection
}
```

The cross-language conformance suite runs the same tests against both adapters in CI.

### Drizzle ORM

Drizzle wraps either `pg.Pool` or `postgres.Sql` — `pgrls-test` works alongside either with no extra plumbing. Get a dedicated connection (or sql instance) for the test client; share the rest of your test setup with Drizzle:

```ts
// Drizzle on node-postgres
import { drizzle } from 'drizzle-orm/node-postgres';
import pg from 'pg';
import { PgrlsTestClient, pgDriver } from 'pgrls-test';

const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });
const db = drizzle(pool); // your app code keeps using this

// For pgrls-test: pull a dedicated client out of the pool so
// BEGIN / SET LOCAL ROLE / queries / ROLLBACK all land on one
// connection. `await pgClient.release()` when the test ends.
const pgClient = await pool.connect();
const test = new PgrlsTestClient(pgDriver(pgClient));
```

```ts
// Drizzle on postgres.js
import { drizzle } from 'drizzle-orm/postgres-js';
import postgres from 'postgres';
import { PgrlsTestClient, postgresJsDriver } from 'pgrls-test';

const sql = postgres(process.env.DATABASE_URL);
const db = drizzle(sql); // your app code keeps using this

// `pgrls-test`'s postgres.js adapter pins one pool connection
// internally; `test.close()` releases it. No `{ max: 1 }` config
// or separate sql instance needed.
const test = new PgrlsTestClient(postgresJsDriver(sql));
try {
  // ... assertions ...
} finally {
  await test.close();
}
```

The Drizzle `db` object and the `pgrls-test` client are independent — Drizzle owns the ORM surface, `pgrls-test` owns the raw-SQL test transaction. Both run against the same database; neither blocks the other.

## API

### Lifecycle

| Method | Behaviour |
|---|---|
| `new PgrlsTestClient(driver)` | Wrap a driver into the client surface. |
| `client.transaction(body)` | Run `body` inside a transaction; ROLLBACK on exit (always). |
| `client.close()` | Release driver-pinned resources (e.g. the postgres.js reserved connection). Idempotent. No-op for the `pg` adapter — the caller owns the `Client`. |

### SQL

| Method | Behaviour |
|---|---|
| `client.exec(sql, params?)` | Execute one statement; discard rows. |
| `client.fetchAll<T>(sql, params?)` | Execute and return rows as `T[]`. |
| `client.asRole(role, { claims }, body)` | Switch role + claims for the duration of `body`. Nests cleanly. |
| `client.seed(table, rows)` | Bulk-insert plain objects. |

### Assertions (five RLS-specific helpers)

| Method | Pass when… |
|---|---|
| `client.assertRows(sql, { count })` | Query returns exactly `count` rows. |
| `client.assertVisible(sql)` | Query returns at least one row. |
| `client.assertInvisible(sql)` | Query returns zero rows. |
| `client.assertRejected(sql)` | Query throws Postgres `InsufficientPrivilege` (SQLSTATE 42501). |
| `client.assertSilentlyDropped(sql)` | UPDATE/DELETE … RETURNING returns zero rows (USING filtered them out). |

All five are also exported as standalone functions taking a client argument first — usable from any test framework, not just Vitest.

## Vitest setup recipe

```ts
// vitest.setup.ts
import { afterAll, beforeAll } from 'vitest';
import { Client } from 'pg';
import { PgrlsTestClient, pgDriver } from 'pgrls-test';

let pg: Client;
let client: PgrlsTestClient;

beforeAll(async () => {
  pg = new Client({ connectionString: process.env.DATABASE_URL });
  await pg.connect();
  client = new PgrlsTestClient(pgDriver(pg));
});

afterAll(async () => {
  await pg.end();
});

export { client };
```

```ts
// my-feature.test.ts
import { describe, it } from 'vitest';
import { client } from './vitest.setup.js';

describe('invoices RLS', () => {
  it('a user can only see their tenant', async () => {
    await client.transaction(async () => {
      await client.seed('app.invoices', [
        { tenant_id: 't1', amount: 100 },
        { tenant_id: 't2', amount: 200 },
      ]);
      await client.asRole(
        'app_authenticated',
        { claims: { tenant_id: 't1' } },
        async () => {
          await client.assertRows('SELECT id FROM app.invoices', { count: 1 });
          await client.assertInvisible(
            "SELECT id FROM app.invoices WHERE tenant_id = 't2'",
          );
        },
      );
    });
  });
});
```

Each test runs inside `client.transaction(async () => …)`, which rolls back at the end — no fixture cleanup, no test order dependencies.

## Errors

The error hierarchy mirrors the Python client byte-for-byte:

```
Error
└── PgrlsTestError              — base for any pgrls-test error
    ├── PgrlsTestAssertionError — thrown by assert* helpers
    └── PgrlsTestConfigError    — thrown when the driver isn't usable
```

Catch any pgrls-test failure with `if (e instanceof PgrlsTestError) …`.

## Cross-language guarantee

`pgrls-test` and Python's `pgrls.testing` implement the same Layer 1 protocol. The wire-level sequence — `SET LOCAL ROLE`, `set_config('request.jwt.claims', …, true)`, `SAVEPOINT pgrls_actor_<random>`, the four-case claim restoration logic — is byte-for-byte equivalent.

The `RESERVED_KEYWORDS` set used for identifier quoting is also pinned across languages: `RESERVED_KEYWORDS.size === 78` matches Python's `len(_RESERVED_KEYWORDS)` (Postgres 16 fully-reserved keywords, appendix C). Each implementation's CI runs its own conformance suite against a Postgres testcontainer; drift protection comes from the shared protocol doc and matching wire-level test cases on both sides, not a single shared CI job.

## Comparison to Python

| Operation | Python (`pgrls.testing`) | TypeScript (`pgrls-test`) |
|---|---|---|
| Open client | `PgrlsTestClient(conn)` | `new PgrlsTestClient(driver)` |
| Per-test tx | `with client.transaction():` | `await client.transaction(async () => …)` |
| Switch role | `with client.as_role(r, claims=c):` | `await client.asRole(r, { claims: c }, async () => …)` |
| Bulk insert | `client.seed(table, rows)` | `await client.seed(table, rows)` |
| Assert rows | `client.assert_rows(sql, count=n)` | `await client.assertRows(sql, { count: n })` |
| Assert reject | `client.assert_rejected(sql)` | `await client.assertRejected(sql)` |

Naming follows JS conventions (camelCase) rather than mirroring snake_case — protocol invariants are language-neutral, but the surface API is per-language idiomatic.

## License

MIT. See [LICENSE](https://github.com/pgrls/pgrls/blob/main/LICENSE) at the repo root.

## Source

The TS port is developed alongside the Python client in the [pgrls/pgrls](https://github.com/pgrls/pgrls) repo, under `ts/`. Issues, PRs, and discussions for both clients live there.
