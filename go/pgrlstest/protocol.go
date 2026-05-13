// Package pgrlstest is the Go port of the pgrls test client.
//
// It implements the cross-language Layer 1 protocol shared with the
// Python (`pgrls.testing.PgrlsTestClient`) and TypeScript
// (`pgrls-test`) clients. All three port test fixtures interop —
// the same RLS-protected schema and the same per-test wire
// sequence (savepoint-bracketed `SET LOCAL ROLE` + `set_config`
// for the JWT claims, rollback to savepoint on scenario exit).
//
// **Status: scaffold (v0.7.0 step 1 of N).** Subsequent steps
// add the Driver interface, the pgx adapter, the assertion
// helpers, the conformance suite, and CI integration. See
// CHANGELOG.md for the per-step plan.
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
