/**
 * Savepoint-name generator. Shared between `client.ts` (which
 * uses `pgrls_actor_` for the `asRole` scope) and
 * `assertions.ts` (which uses `pgrls_check_` for the
 * `assertRejected` scope).
 *
 * Centralizing avoids drift between the two random schemes —
 * the next time we want to tweak the suffix length or the
 * random source, there's one place to do it.
 *
 * 4-byte random suffix → 8 hex chars → 4 billion options.
 * Collisions in the same transaction are astronomically
 * unlikely.
 *
 * Mirrors Python's `secrets.token_hex(4)` call sites.
 */

/**
 * Build a savepoint name with the given prefix and a 4-byte
 * cryptographically-random hex suffix.
 *
 * Uses `globalThis.crypto.getRandomValues` (WHATWG standard;
 * available in Node ≥18, so well within our `engines.node`
 * floor). Reaching via globalThis avoids needing a
 * `node:crypto` import or an ambient `crypto` global decl.
 */
export function newSavepointName(prefix: string): string {
  const bytes = new Uint8Array(4);
  globalThis.crypto.getRandomValues(bytes);
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
  return `${prefix}_${hex}`;
}
