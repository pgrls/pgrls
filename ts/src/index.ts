/**
 * pgrls-test — Code-first RLS testing for Postgres.
 *
 * TypeScript port of `pgrls.testing` (Python). Implements the
 * cross-language Layer 1 protocol documented at
 * `docs/pgrls-test-protocol.md` in the source repo.
 *
 * The full public surface (PgrlsTestClient, drivers, assertions,
 * errors) lands in subsequent commits; this module re-exports
 * them as they're added.
 */

/**
 * The version of the cross-language Layer 1 contract this
 * client implements. Bumped only when the wire-level sequence
 * (SQL emitted, GUC names used, savepoint convention) changes
 * in a non-additive way. See `docs/pgrls-test-protocol.md` for
 * the contract itself.
 */
export const PROTOCOL_VERSION = 1 as const;
