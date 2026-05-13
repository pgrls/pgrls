package pgrlstest

import "testing"

// Pin the protocol version. The cross-language contract demands
// that all three clients (Python, TS, Go) export the same
// integer. A future bump must hit this constant intentionally —
// the test ensures a typo doesn't silently shift the contract.
//
// When the protocol version bumps:
//  1. Update the value here, in Python's
//     `src/pgrls/testing/__init__.py` (PROTOCOL_VERSION), and in
//     TS's `ts/src/index.ts` (PROTOCOL_VERSION).
//  2. Update `docs/pgrls-test-protocol.md` to describe the wire
//     change.
//  3. Update the cross-language conformance fixtures.
//  4. Bump each port's package version (Python minor, TS minor,
//     Go minor — independent SemVer per-port; the protocol
//     version is its own thing).
func TestProtocolVersion(t *testing.T) {
	if ProtocolVersion != 1 {
		t.Errorf("ProtocolVersion = %d, want 1 (Layer 1 wire protocol)", ProtocolVersion)
	}
}
