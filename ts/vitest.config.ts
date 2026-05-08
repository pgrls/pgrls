import { defineConfig } from 'vitest/config';

/**
 * Vitest config — paired with `tsconfig.json`.
 *
 * Two notable knobs:
 *   * `test.testTimeout` — bumped to 30s. Some integration tests
 *     spin up a Postgres testcontainer (~10s cold-start on a
 *     warm CI runner, longer on cold).
 *   * `test.fileParallelism: false` — protocol conformance tests
 *     share a single testcontainer to keep the cross-driver
 *     suite under 30s total. Within a file, tests still run
 *     serially (default), so the per-test transaction is the
 *     real isolation boundary.
 */
export default defineConfig({
  test: {
    testTimeout: 30_000,
    fileParallelism: false,
    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov'],
      include: ['src/**/*.ts'],
      // Exclude type-only files from coverage so 100% coverage
      // is achievable on the runtime surface.
      exclude: ['src/drivers/types.ts'],
    },
  },
});
