/**
 * pgrls-test — Code-first RLS testing for Postgres.
 *
 * TypeScript port of `pgrls.testing` (Python). Implements the
 * cross-language wire protocol at
 * https://github.com/pgrls/pgrls/blob/main/docs/pgrls-test-protocol.md.
 *
 * Re-exports the full public surface: `PgrlsTestClient`, the
 * five RLS-specific assertion helpers (standalone + as
 * methods on the client), the two driver factories
 * (`pgDriver` / `postgresJsDriver`), the error hierarchy,
 * identifier-quoting helpers, and the `PROTOCOL_VERSION`
 * constant.
 */

export {
  PgrlsTestAssertionError,
  PgrlsTestConfigError,
  PgrlsTestError,
} from './errors.js';

export { quoteIdent, quoteQualified, RESERVED_KEYWORDS } from './idents.js';

export type { Driver, QueryResult } from './drivers/types.js';
export { pgDriver, type PgQueryable } from './drivers/pg.js';
export {
  postgresJsDriver,
  type PostgresJsResult,
  type PostgresJsSql,
} from './drivers/postgres-js.js';

export { PgrlsTestClient, type AsRoleOptions } from './client.js';

export {
  assertInvisible,
  assertRejected,
  assertRows,
  assertSilentlyDropped,
  assertVisible,
} from './assertions.js';

/**
 * The version of the cross-language Layer 1 contract this
 * client implements. Bumped only when the wire-level sequence
 * (SQL emitted, GUC names used, savepoint convention) changes
 * in a non-additive way. See
 * https://github.com/pgrls/pgrls/blob/main/docs/pgrls-test-protocol.md
 * for the contract itself.
 */
export const PROTOCOL_VERSION = 1 as const;
