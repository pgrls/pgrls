# Changelog

All notable changes to `pgrls-test` (the TypeScript port of `pgrls.testing`).

The format follows [Keep a Changelog](https://keepachangelog.com/) and the
package adheres to [Semantic Versioning](https://semver.org/). Protocol
versioning is independent — `PROTOCOL_VERSION` (currently `1`) only bumps
on wire-level breaking changes shared with the Python client.

## [0.6.2] - 2026-05-13

TS polish bundle. No protocol changes; `PROTOCOL_VERSION` stays at `1`.

### Fixed

- **postgres.js adapter now pins one pool connection internally.**
  `postgres.js` is a pool by default (10 connections), and
  `PgrlsTestClient.transaction()` issues `BEGIN` / queries /
  `ROLLBACK` as separate driver calls. Without pinning, each
  call could land on a different pool connection — transaction
  state (`SET LOCAL`, the implicit `BEGIN`) wouldn't persist,
  and `ROLLBACK` would undo nothing. The adapter now lazily
  calls `sql.reserve()` on the first `query()` and uses the
  reserved connection for every subsequent call. Users no
  longer need the `{ max: 1 }` workaround the README previously
  recommended. The conformance suite drops that workaround
  too; seven new unit tests cover the reserve / reuse /
  release / re-acquire lifecycle.

### Added

- **`PgrlsTestClient.close()` and optional `Driver.close()`.**
  `client.close()` forwards to `driver.close?.()` and releases
  driver-pinned resources. The `postgres.js` adapter uses it
  to release the reserved pool connection back to the pool;
  the `pg` adapter is a no-op (the caller owns the `Client`).
  Idempotent. Recommended in `try/finally` after the test
  body — without it, the postgres.js reservation leaks until
  `sql.end()` is called.

- **Drizzle ORM recipe** in `README.md`. Covers both
  `drizzle-orm/node-postgres` (use `pool.connect()` to get a
  dedicated `pg.Client` for the test) and
  `drizzle-orm/postgres-js` (share the `sql` pool; the
  adapter's connection pinning handles isolation). The
  Drizzle `db` object and the `pgrls-test` client stay
  independent — Drizzle owns the ORM surface, `pgrls-test`
  owns the raw-SQL test transaction.

- **JSR publish** (`jsr.json` + workflow job). `pgrls-test`
  is now published to both [npm](https://www.npmjs.com/package/pgrls-test)
  (as `pgrls-test`) and [JSR](https://jsr.io/@pgrls/test) (as
  `@pgrls/test`). The JSR publish uses GitHub OIDC for
  provenance — no long-lived secret needed. Both publishes
  gate on the same `ts-v*` git tag so the two registries
  track the same version.

## [0.6.1] - 2026-05-12

Post-release review pass. Bug fix + polish; no protocol changes.

### Fixed

- **`assertSilentlyDropped` now rejects UPDATE/DELETE without
  RETURNING.** The Python helper catches `psycopg.
  ProgrammingError` from `cur.fetchall()` when there's no
  result set, so a typo like `assertSilentlyDropped('UPDATE
  t SET x = 1')` (forgot to add `RETURNING id`) raises a
  clear `PgrlsTestError`. Both `pg` and `postgres.js`
  synthesize an empty rows array instead, so v0.6.0's TS
  port couldn't distinguish "RETURNING returned 0 rows"
  from "no RETURNING at all" — the helper would silently
  pass whenever RLS happened to filter every row, defeating
  the test's purpose. v0.6.1 adds a SQL-keyword pre-check
  (`/\bRETURNING\b/i`) that fires the same `PgrlsTestError`
  Python raises, restoring byte-for-byte parity. Four new
  unit tests cover UPDATE/DELETE without RETURNING,
  case-insensitive matching, and word-boundary handling
  (`returning_col` is rejected; `returning` keyword is
  accepted). The regex is documented as deliberately not
  parsing SQL: false positives like RETURNING inside a
  string literal aren't the helper's responsibility.

- **`fetchAll<TRow>` generic constraint relaxed.** v0.6.0
  declared `fetchAll<TRow extends Record<string, unknown> = …>`,
  which under TS structural typing rejects `interface` row
  declarations (`interface Invoice { id: number; … }`) because
  interfaces lack implicit index signatures — only `type`
  aliases get them. Most users declare row shapes as
  `interface`, so the constraint produced a confusing
  compile error on the dominant idiom. v0.6.1 drops the
  `extends` constraint; the default type is still
  `Record<string, unknown>` and the cast was unchecked anyway
  (mirrors Python's untyped `dict` return from `fetchall`).

- **`AsRoleOptions.claims` docstring corrected.** Was
  "`undefined` is treated as `null` by JS convention" — true
  at runtime but misleading under
  `exactOptionalPropertyTypes: true` (which this package's
  `tsconfig` enables), which rejects `claims: undefined` at
  compile time. Docstring now says "omit the key or pass
  `null`" and the corresponding test was renamed from "treats
  undefined claims like null" to "treats absent claims key
  like null" to match what's actually reachable.

### Internal

- Extracted shared `newSavepointName(prefix)` helper to
  `src/_savepoint.ts`. Was duplicated between `client.ts`
  (`pgrls_actor_` prefix) and `assertions.ts`
  (`pgrls_check_` prefix).
- Extracted shared `makeRecordingDriver` / `captureResponse`
  / `selectRows` test helpers to `test/_recording-driver.ts`.
  Was duplicated between `client.test.ts` and
  `assertions.test.ts`.
- Tightened `QueryResult.command` from `string` to the
  known-verb union widened with `(string & {})`, giving
  editor autocomplete for verbs we care about while
  remaining assignable from any string.
- Added two new conformance tests covering `asRole` claim-
  restore cases 2 (outer had no claims, inner set claims)
  and 4 (outer had claims, inner didn't set claims).
  Previous v0.6.0 conformance only covered case 1; cases
  2-4 were unit-test-only.

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
