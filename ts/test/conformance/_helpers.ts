/**
 * Shared helpers for the conformance test suites.
 *
 * The two conformance suites (`pg.conformance.test.ts` and
 * `postgres-js.conformance.test.ts`) run *the same* test
 * matrix against *the same* schema. Only the driver wiring
 * differs. This module centralizes:
 *
 * 1. The fixture SQL — a tenant-scoped invoices table with a
 *    proper PERMISSIVE+RESTRICTIVE policy pair, plus the
 *    `app_authenticated` role test-bodies switch into.
 * 2. The protocol conformance test cases themselves
 *    (`runConformanceTests(client)`), so each driver suite
 *    invokes them with its own driver wired up.
 *
 * Why this shape: keeps the "I'm testing the protocol" code
 * driver-agnostic and the "I'm wiring up driver X" code in
 * one obvious place. A future third driver (Bun's native pg,
 * Cloudflare hyperdrive) would add a third `*.conformance.
 * test.ts` file that calls `runConformanceTests` — nothing
 * else changes.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import {
  PgrlsTestAssertionError,
  type PgrlsTestClient,
  PgrlsTestError,
} from '../../src/index.js';

/**
 * SQL applied to a fresh Postgres instance before each
 * conformance suite runs. Idempotent — `DROP SCHEMA IF EXISTS
 * conf_test CASCADE` at the top + `CREATE SCHEMA conf_test`
 * means the suite can re-run against the same DB.
 *
 * The fixture mirrors uc01 (`app.documents`) from the demo:
 * canonical PERMISSIVE+RESTRICTIVE pattern, tenant scoping
 * driven off a session GUC `conf_test.tenant`.
 */
export const FIXTURE_SQL = `
DROP SCHEMA IF EXISTS conf_test CASCADE;
CREATE SCHEMA conf_test;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'conf_app_authenticated') THEN
        CREATE ROLE conf_app_authenticated NOLOGIN;
    END IF;
END $$;

GRANT USAGE ON SCHEMA conf_test TO conf_app_authenticated;

CREATE TABLE conf_test.invoices (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    amount INT NOT NULL
);
GRANT SELECT, INSERT, UPDATE, DELETE ON conf_test.invoices TO conf_app_authenticated;
GRANT USAGE, SELECT ON SEQUENCE conf_test.invoices_id_seq TO conf_app_authenticated;
ALTER TABLE conf_test.invoices ENABLE ROW LEVEL SECURITY;
ALTER TABLE conf_test.invoices FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_access ON conf_test.invoices
    FOR ALL TO conf_app_authenticated
    USING (
        tenant_id = (SELECT current_setting('request.jwt.claims', true))::jsonb->>'tenant_id'
    )
    WITH CHECK (
        tenant_id = (SELECT current_setting('request.jwt.claims', true))::jsonb->>'tenant_id'
    );

CREATE POLICY tenant_isolation ON conf_test.invoices
    AS RESTRICTIVE FOR ALL TO PUBLIC
    USING (
        tenant_id = (SELECT current_setting('request.jwt.claims', true))::jsonb->>'tenant_id'
    )
    WITH CHECK (
        tenant_id = (SELECT current_setting('request.jwt.claims', true))::jsonb->>'tenant_id'
    );
`;

/**
 * Run the protocol conformance test suite against the supplied
 * client. Each driver's `*.conformance.test.ts` calls this in
 * a `describe` block of its own.
 *
 * The suite covers the four conformance criteria from
 * `docs/pgrls-test-protocol.md`:
 *
 * 1. SET LOCAL ROLE — transaction rollback resets the role.
 * 2. set_config(..., true) — rollback clears the GUC.
 * 3. InsufficientPrivilege (SQLSTATE 42501) for "rejected".
 * 4. UPDATE/DELETE … RETURNING returns 0 rows when USING
 *    filters them out (silent drop).
 *
 * Plus end-to-end tests of the public API on a real DB.
 */
export function runConformanceTests(getClient: () => PgrlsTestClient): void {
  let client: PgrlsTestClient;

  beforeAll(async () => {
    client = getClient();
    // Apply the fixture once per suite. The conformance tests
    // each run inside their own `transaction()`, which rolls
    // back at the end, so the fixture is preserved across tests.
    await client.exec(FIXTURE_SQL);
  });

  afterAll(async () => {
    // Best-effort cleanup. Errors here shouldn't fail the
    // suite — the schema can be left for inspection.
    try {
      await client.exec('DROP SCHEMA IF EXISTS conf_test CASCADE');
    } catch {
      // Ignore — caller will see the error if it matters.
    }
  });

  describe('Layer 1 protocol — conformance', () => {
    it('SET LOCAL ROLE inside a transaction; rollback resets role', async () => {
      // Conformance criterion 1: `SET LOCAL ROLE x` inside a
      // transaction reverts on ROLLBACK.
      const before = await client.fetchAll<{ current_user: string }>(
        'SELECT current_user',
      );
      await client.transaction(async () => {
        await client.exec('SET LOCAL ROLE conf_app_authenticated');
        const inside = await client.fetchAll<{ current_user: string }>(
          'SELECT current_user',
        );
        expect(inside[0]?.current_user).toBe('conf_app_authenticated');
      });
      // After transaction rollback, role is back to admin.
      const after = await client.fetchAll<{ current_user: string }>(
        'SELECT current_user',
      );
      expect(after[0]?.current_user).toBe(before[0]?.current_user);
    });

    it('set_config(..., true) for request.jwt.claims; rollback clears it', async () => {
      // Conformance criterion 2: `set_config('request.jwt.claims',
      // …, true)` inside a transaction reverts on ROLLBACK.
      await client.transaction(async () => {
        await client.exec("SELECT set_config('request.jwt.claims', $1, true)", [
          JSON.stringify({ tenant_id: 't-conf' }),
        ]);
        const inside = await client.fetchAll<{ claims: string | null }>(
          "SELECT current_setting('request.jwt.claims', true) AS claims",
        );
        expect(inside[0]?.claims).toContain('t-conf');
      });
      // After rollback, the GUC is empty (or never-set).
      const after = await client.fetchAll<{ claims: string | null }>(
        "SELECT current_setting('request.jwt.claims', true) AS claims",
      );
      const value = after[0]?.claims;
      expect(value === '' || value === null).toBe(true);
    });

    it('InsufficientPrivilege (SQLSTATE 42501) on policy violation', async () => {
      // Conformance criterion 3: a WITH CHECK violation under
      // RLS surfaces as SQLSTATE 42501 — `assertRejected`
      // catches it.
      await client.transaction(async () => {
        await client.asRole(
          'conf_app_authenticated',
          { claims: { tenant_id: 't-allowed' } },
          async () => {
            // Insert a row whose tenant_id doesn't match the
            // claim's tenant_id → WITH CHECK fails → 42501.
            await client.assertRejected(
              "INSERT INTO conf_test.invoices (tenant_id, amount) VALUES ('t-other', 100)",
            );
          },
        );
      });
    });

    it('UPDATE … RETURNING returns 0 rows when USING filters them out', async () => {
      // Conformance criterion 4: silent-drop shape on
      // UPDATE/DELETE … RETURNING.
      await client.transaction(async () => {
        // Seed a row in tenant A as admin.
        await client.exec(
          "INSERT INTO conf_test.invoices (tenant_id, amount) VALUES ('t-A', 100)",
        );
        await client.asRole(
          'conf_app_authenticated',
          { claims: { tenant_id: 't-B' } },
          async () => {
            // Tenant B can't see tenant A's row → USING filters
            // it out → UPDATE … RETURNING → 0 rows.
            await client.assertSilentlyDropped(
              'UPDATE conf_test.invoices SET amount = 999 RETURNING id',
            );
          },
        );
      });
    });
  });

  describe('Public API — end-to-end', () => {
    it('seed → assertRows → assertVisible → assertInvisible', async () => {
      await client.transaction(async () => {
        await client.seed('conf_test.invoices', [
          { tenant_id: 't-1', amount: 100 },
          { tenant_id: 't-1', amount: 200 },
          { tenant_id: 't-2', amount: 300 },
        ]);

        await client.asRole(
          'conf_app_authenticated',
          { claims: { tenant_id: 't-1' } },
          async () => {
            await client.assertRows('SELECT id FROM conf_test.invoices', { count: 2 });
            await client.assertVisible(
              "SELECT id FROM conf_test.invoices WHERE tenant_id = 't-1'",
            );
            await client.assertInvisible(
              "SELECT id FROM conf_test.invoices WHERE tenant_id = 't-2'",
            );
          },
        );
      });
    });

    it('asRole with no claims still works (skips set_config)', async () => {
      // Pin that `claims: null` doesn't fail the protocol —
      // the role-switch alone exercises the SET LOCAL ROLE
      // path with no `set_config` call. We don't run a query
      // that would error against the policy (that would
      // poison the savepoint and fail the clean-exit
      // RELEASE).
      await client.transaction(async () => {
        await client.asRole('conf_app_authenticated', { claims: null }, async () => {
          // current_user reflects the role-switch (proves
          // SET LOCAL ROLE happened) without invoking the
          // tenant policy.
          const rows = await client.fetchAll<{ current_user: string }>(
            'SELECT current_user',
          );
          expect(rows[0]?.current_user).toBe('conf_app_authenticated');
          // request.jwt.claims is empty (set_config was
          // never called) — pin that.
          const guc = await client.fetchAll<{ claims: string | null }>(
            "SELECT current_setting('request.jwt.claims', true) AS claims",
          );
          const value = guc[0]?.claims;
          expect(value === '' || value === null).toBe(true);
        });
      });
    });

    it('nested asRole restores outer role + claims', async () => {
      // Pin the protocol's nested-block contract.
      await client.transaction(async () => {
        await client.asRole(
          'conf_app_authenticated',
          { claims: { tenant_id: 'outer' } },
          async () => {
            await client.asRole(
              'conf_app_authenticated',
              { claims: { tenant_id: 'inner' } },
              async () => {
                const rows = await client.fetchAll<{ claims: string }>(
                  "SELECT current_setting('request.jwt.claims', true) AS claims",
                );
                expect(rows[0]?.claims).toContain('inner');
              },
            );
            // After inner block: outer claims restored.
            const rows = await client.fetchAll<{ claims: string }>(
              "SELECT current_setting('request.jwt.claims', true) AS claims",
            );
            expect(rows[0]?.claims).toContain('outer');
          },
        );
      });
    });

    it('assertSilentlyDropped throws PgrlsTestError on SELECT', async () => {
      // Pin the verb-gate contract on a real driver.
      await client.transaction(async () => {
        await expect(
          client.assertSilentlyDropped('SELECT 1 FROM conf_test.invoices'),
        ).rejects.toThrow(PgrlsTestError);
      });
    });

    it('assertRejected throws PgrlsTestAssertionError when query succeeds', async () => {
      await client.transaction(async () => {
        await client.asRole(
          'conf_app_authenticated',
          { claims: { tenant_id: 't-X' } },
          async () => {
            // SELECT under matching claims succeeds → assertion
            // about it being rejected fails.
            await expect(
              client.assertRejected(
                "SELECT 1 FROM conf_test.invoices WHERE tenant_id = 't-X'",
              ),
            ).rejects.toThrow(PgrlsTestAssertionError);
          },
        );
      });
    });
  });
}
