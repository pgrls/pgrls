# pgrls-test

> 🚧 **v0.6.0-dev** — TypeScript port of `pgrls.testing`. The
> full public surface (`PgrlsTestClient`, drivers, assertions,
> errors) lands in incremental PRs over the v0.6.0 milestone.
> This file's recipe section will fill in as those PRs land.

Code-first RLS testing for Postgres, in TypeScript. Implements
the cross-language Layer 1 contract documented at
[`docs/pgrls-test-protocol.md`](https://github.com/pgrls/pgrls/blob/main/docs/pgrls-test-protocol.md)
in the source repo. Companion to the Python `pgrls.testing`
package — same protocol, byte-for-byte equivalent wire
behaviour, idiomatic JS/TS surface.

## Status

| Component | Status |
|---|---|
| Scaffold (build, lint, test, types) | ✅ landed |
| `PROTOCOL_VERSION` export | ✅ landed |
| `errors.ts` (PgrlsTestError + subclasses) | 🔜 next |
| `idents.ts` (quote_ident port) | 🔜 next |
| `drivers/` (Driver interface, pg adapter, postgres.js adapter) | 🔜 |
| `client.ts` (PgrlsTestClient, transaction, asRole) | 🔜 |
| `assertions.ts` (5 RLS-specific assertions) | 🔜 |
| Cross-lang conformance suite | 🔜 |
| Released to npm as `pgrls-test@0.6.0` | 🔜 |

## Development

Once the `ts/` directory has installable dependencies:

```sh
cd ts
npm install   # or pnpm install
npm test      # vitest
npm run typecheck
npm run lint
npm run build
```

## License

MIT. See [LICENSE](https://github.com/pgrls/pgrls/blob/main/LICENSE) in the repo root.
