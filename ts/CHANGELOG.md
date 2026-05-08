# Changelog

All notable changes to `pgrls-test` (the TypeScript port of `pgrls.testing`).

The format follows [Keep a Changelog](https://keepachangelog.com/) and the
package adheres to [Semantic Versioning](https://semver.org/). Protocol
versioning is independent — `PROTOCOL_VERSION` (currently `1`) only bumps
on wire-level breaking changes shared with the Python client.

## [0.6.0] - 2026-05-08

Initial public release. TypeScript port of the Python `pgrls.testing` package.
Implements the cross-language Layer 1 protocol at `PROTOCOL_VERSION = 1`.

### Added

- **`PgrlsTestClient`** — wraps a driver; provides `transaction`, `exec`,
  `fetchAll`, `asRole`, `seed`, and the five RLS assertion helpers.
- **Two driver adapters** — `pgDriver(pg.Client)` and
  `postgresJsDriver(postgres.Sql)`. Both `pg` and `postgres` are optional
  peer dependencies; users install only the driver they actually use.
- **Error hierarchy** — `PgrlsTestError` (base), `PgrlsTestAssertionError`,
  `PgrlsTestConfigError`. Mirrors the Python client.
- **Identifier quoting** — `quoteIdent`, `quoteQualified`, `RESERVED_KEYWORDS`
  byte-for-byte equivalent to Python's `pgrls.fixers._idents`. The 78-keyword
  reserved set is pinned identically across languages.
- **Cross-language conformance suite** — same 18 tests run against both `pg`
  and `postgres.js` adapters. Pins all four Layer 1 conformance criteria
  from `docs/pgrls-test-protocol.md`.
- **126 unit + integration tests** total. ESM-only build with full TypeScript
  types.

### Notable design

- **Single npm package, no monorepo.** Surface stays small enough that one
  package is right.
- **ESM-only.** Vitest is ESM-native; modern Node (≥20 LTS) is ESM-first.
  CJS-only stacks can wait for a 0.6.x dual-publish if demand materializes.
- **`pgrls-test` (unscoped)**, not `@pgrls/testing`. One fewer character to
  type, no scope to pre-register. Renames stay cheap.
- **Callback-shaped `transaction` and `asRole`.** Mirrors the Python
  contextmanager API; cleaner exception flow than `await using` +
  `Symbol.asyncDispose`.
- **No first-class test-framework plugin.** Recipes only. A vitest /
  jest / node:test plugin is a v0.7.0 add if user feedback demands it.

### See also

- Design doc: [`docs/v0.6.0-typescript-port-design.md`](https://github.com/pgrls/pgrls/blob/main/docs/v0.6.0-typescript-port-design.md)
- Layer 1 protocol: [`docs/pgrls-test-protocol.md`](https://github.com/pgrls/pgrls/blob/main/docs/pgrls-test-protocol.md)
