// Package pgrlstest is the Go port of the pgrls test client.
//
// It implements the cross-language Layer 1 protocol shared with the
// Python (`pgrls.testing.PgrlsTestClient`) and TypeScript
// (`pgrls-test`) clients. All three port test fixtures interop —
// the same RLS-protected schema and the same per-test wire
// sequence (savepoint-bracketed `SET LOCAL ROLE` + `set_config`
// for the JWT claims, rollback to savepoint on scenario exit).
//
// **Status: step 4 of 7 (v0.7.3 — Client API).**
// v0.7.0 shipped the scaffold + ProtocolVersion + error types;
// v0.7.1 added the Driver and Closer interfaces alongside the
// QueryResult struct; v0.7.2 added the pgx and lib/pq driver
// adapters (each with a single-conn + pool-backed constructor);
// v0.7.3 adds the Client API (`Client.Transaction`, `Client.AsRole`,
// `Client.Exec`, `Client.FetchAll`, `Client.Seed`, `Client.Close`)
// alongside `QuoteIdent` / `QuoteQualified` (identifier quoting
// with reserved-keyword handling) and `NewSavepointName`
// (crypto/rand-backed savepoint suffix generator). Subsequent
// steps add the assertion helpers (v0.7.4), the conformance
// suite (v0.7.5), and CI hardening + release plumbing (v0.7.6).
// See CHANGELOG.md for the per-step plan.
package pgrlstest

// ProtocolVersion is the wire-protocol version this client
// implements. Pinned to a single integer (currently 1) so that
// cross-language tests can assert version equality at startup —
// a future bump of the wire shape (savepoint naming convention,
// claims-encoding rules, etc.) will bump this constant, and
// downstream tests gating on a specific version will fail loudly
// rather than silently misbehave against a mismatched server-
// side convention.
//
// Cross-language guarantee: the Python and TypeScript clients
// both export the same integer under the same name
// (`PROTOCOL_VERSION` in Python and TS; `ProtocolVersion` in
// Go to follow Go's PascalCase exported-name convention). All
// three are kept in lockstep via the spec at
// `docs/pgrls-test-protocol.md` and the cross-language
// conformance fixtures in `tests/protocol/` (Python) +
// `ts/test/conformance/` (TS) + `go/pgrlstest/conformance_test.go`
// (Go — added in step 6).
const ProtocolVersion = 1
