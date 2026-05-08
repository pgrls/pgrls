/**
 * pgrls-test — Code-first RLS testing for Postgres.
 *
 * TypeScript port of `pgrls.testing` (Python). Implements the
 * cross-language Layer 1 protocol documented at
 * `docs/pgrls-test-protocol.md` in the source repo.
 *
 * Subsequent commits add `PgrlsTestClient` and assertions; this
 * module re-exports the public surface as it grows.
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

/**
 * The version of the cross-language Layer 1 contract this
 * client implements. Bumped only when the wire-level sequence
 * (SQL emitted, GUC names used, savepoint convention) changes
 * in a non-additive way. See `docs/pgrls-test-protocol.md` for
 * the contract itself.
 */
export const PROTOCOL_VERSION = 1 as const;
