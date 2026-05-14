package pgrlstest

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// NewSavepointName builds a savepoint name with the given prefix
// and a 4-byte cryptographically-random hex suffix (8 hex chars,
// ~4B options). Collisions inside a single transaction are
// astronomically unlikely.
//
// Used by `Client.AsRole` (prefix `pgrls_actor`) and by the
// assertion helpers (prefix `pgrls_check`, added in v0.7.4).
// Centralizing here avoids drift between the two random schemes —
// the next time we want to tweak suffix length or the random
// source, there's one place to do it.
//
// Cross-language guarantee: same 4-byte / 8-hex-char output shape
// as the TypeScript `newSavepointName` and the Python
// `secrets.token_hex(4)` call sites. Returns an error if the
// system entropy source is unavailable — same defensive posture
// as Python's `secrets` (which raises) and the TS port (which
// throws); callers MUST propagate the failure rather than
// silently fall back to a weak source.
func NewSavepointName(prefix string) (string, error) {
	var bytes [4]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		// crypto/rand.Read on Linux/macOS reads from
		// /dev/urandom (or getrandom); failure here means
		// catastrophic OS state. Wrap so the call site sees a
		// pgrls-test error rather than a bare crypto/rand
		// error.
		return "", &Error{
			Msg:   "NewSavepointName: failed to read crypto/rand for savepoint suffix",
			Cause: err,
		}
	}
	return fmt.Sprintf("%s_%s", prefix, hex.EncodeToString(bytes[:])), nil
}
