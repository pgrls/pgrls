package pgrlstest

import (
	"regexp"
	"strings"
	"testing"
)

func TestNewSavepointName_FormatAndPrefix(t *testing.T) {
	// Pin the wire shape: `<prefix>_<8 hex chars>`. This is the
	// cross-language invariant — Python's `secrets.token_hex(4)`
	// and TypeScript's `Array.from(...).padStart(2,'0').join('')`
	// both produce 8 hex chars; Go's `hex.EncodeToString(4 bytes)`
	// must too.
	name, err := NewSavepointName("pgrls_actor")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(name, "pgrls_actor_") {
		t.Errorf("name %q does not have prefix pgrls_actor_", name)
	}
	suffix := strings.TrimPrefix(name, "pgrls_actor_")
	matched, err := regexp.MatchString(`^[0-9a-f]{8}$`, suffix)
	if err != nil {
		t.Fatalf("regex error: %v", err)
	}
	if !matched {
		t.Errorf("suffix %q is not 8 lowercase hex chars", suffix)
	}
}

func TestNewSavepointName_HighEntropy(t *testing.T) {
	// Generating a few hundred names should produce a few
	// hundred distinct values — crypto/rand has effectively no
	// observable bias at this scale. A failure here means
	// either the entropy source is broken or NewSavepointName
	// is reusing state.
	seen := make(map[string]struct{}, 256)
	for i := 0; i < 256; i++ {
		name, err := NewSavepointName("pgrls_test")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, dup := seen[name]; dup {
			t.Errorf("duplicate savepoint name within 256 calls: %q", name)
		}
		seen[name] = struct{}{}
	}
}

func TestNewSavepointName_DifferentPrefixes(t *testing.T) {
	// The same generator backs both the AsRole scope
	// (`pgrls_actor`) and the AssertRejected scope
	// (`pgrls_check`, added in v0.7.4). Pin that the prefix is
	// passed through verbatim.
	cases := []string{"pgrls_actor", "pgrls_check", "anything"}
	for _, prefix := range cases {
		t.Run(prefix, func(t *testing.T) {
			name, err := NewSavepointName(prefix)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !strings.HasPrefix(name, prefix+"_") {
				t.Errorf("name %q does not have prefix %q_", name, prefix)
			}
		})
	}
}
