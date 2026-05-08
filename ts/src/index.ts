/**
 * pgrls-test — Code-first RLS testing for Postgres.
 *
 * TypeScript port of `pgrls.testing` (Python). Implements the
 * cross-language Layer 1 protocol documented at
 * `docs/pgrls-test-protocol.md` in the source repo.
 *
 * Subsequent commits add `PgrlsTestClient`, drivers, and
 * assertions; this module re-exports them as they're added.
 */

export {
  PgrlsTestAssertionError,
  PgrlsTestConfigError,
  PgrlsTestError,
} from './errors.js';

export { quoteIdent, quoteQualified, RESERVED_KEYWORDS } from './idents.js';

/**
 * The version of the cross-language Layer 1 contract this
 * client implements. Bumped only when the wire-level sequence
 * (SQL emitted, GUC names used, savepoint convention) changes
 * in a non-additive way. See `docs/pgrls-test-protocol.md` for
 * the contract itself.
 */
export const PROTOCOL_VERSION = 1 as const;
