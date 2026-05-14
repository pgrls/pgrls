package pgrlstest

import (
	"errors"
	"strings"
	"testing"
)

func TestReservedKeywords_Has78Entries(t *testing.T) {
	// Cross-language invariant: the reserved-keyword set must be
	// byte-equivalent in Python, TypeScript, and Go. Adding or
	// removing an entry is a wire behavior change — bump all
	// three and update the conformance fixtures. Pin the count
	// so accidental edits to this file get caught.
	if got := len(ReservedKeywords); got != 78 {
		t.Errorf("ReservedKeywords has %d entries, want 78", got)
	}
}

func TestReservedKeywords_ContainsKnownEntries(t *testing.T) {
	// Spot-check a handful of representative keywords. The full
	// 78-entry set is structurally pinned by the count test;
	// these assert that the well-known tokens are actually
	// present (e.g. a future refactor that drops alphabet halves
	// would fail this even with the right count).
	for _, kw := range []string{
		"select", "from", "where", "table", "user",
		"current_user", "session_user", "current_role",
	} {
		if _, ok := ReservedKeywords[kw]; !ok {
			t.Errorf("ReservedKeywords missing %q", kw)
		}
	}
}

func TestQuoteIdent_PlainName(t *testing.T) {
	cases := []string{
		"tenant_id",
		"a",
		"a1",
		"_underscored",
		"snake_case_name",
	}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := QuoteIdent(name)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != name {
				t.Errorf("QuoteIdent(%q) = %q, want %q (no quoting)", name, got, name)
			}
		})
	}
}

func TestQuoteIdent_ReservedKeywordQuoted(t *testing.T) {
	cases := map[string]string{
		"select": `"select"`,
		"SELECT": `"SELECT"`, // case-insensitive match → still quoted
		"Order":  `"Order"`,
		"user":   `"user"`,
	}
	for input, want := range cases {
		t.Run(input, func(t *testing.T) {
			got, err := QuoteIdent(input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != want {
				t.Errorf("QuoteIdent(%q) = %q, want %q", input, got, want)
			}
		})
	}
}

func TestQuoteIdent_NonPlainQuoted(t *testing.T) {
	cases := map[string]string{
		"MixedCase":  `"MixedCase"`,
		"with space": `"with space"`,
		"with-dash":  `"with-dash"`,
		"1leading":   `"1leading"`,
		"weird.name": `"weird.name"`,
		"weïrd":      `"weïrd"`,
	}
	for input, want := range cases {
		t.Run(input, func(t *testing.T) {
			got, err := QuoteIdent(input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != want {
				t.Errorf("QuoteIdent(%q) = %q, want %q", input, got, want)
			}
		})
	}
}

func TestQuoteIdent_DoublesEmbeddedQuotes(t *testing.T) {
	// Postgres's standard escape rule for double-quoted
	// identifiers: literal `"` is encoded as `""`.
	got, err := QuoteIdent(`he"llo`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != `"he""llo"` {
		t.Errorf("QuoteIdent(`he\"llo`) = %q, want `\"he\"\"llo\"`", got)
	}
}

func TestQuoteIdent_EmptyIsError(t *testing.T) {
	_, err := QuoteIdent("")
	if err == nil {
		t.Fatal("expected error for empty identifier")
	}
	// Must surface as a pgrlstest API error so callers can
	// `errors.Is(err, ErrAPIError)` to distinguish from driver
	// failures.
	if !errors.Is(err, ErrAPIError) {
		t.Errorf("error %v does not match ErrAPIError sentinel", err)
	}
}

func TestQuoteIdent_ControlCharsRejected(t *testing.T) {
	cases := []string{
		"with\x00null",
		"tab\there",
		"newline\nhere",
		"del\x7fhere",
	}
	for _, input := range cases {
		t.Run(input, func(t *testing.T) {
			_, err := QuoteIdent(input)
			if err == nil {
				t.Fatalf("expected error for %q", input)
			}
			if !errors.Is(err, ErrAPIError) {
				t.Errorf("error %v does not match ErrAPIError sentinel", err)
			}
			if !strings.Contains(err.Error(), "control character") {
				t.Errorf("error %q does not mention control character", err.Error())
			}
		})
	}
}

func TestQuoteQualified_BothComponents(t *testing.T) {
	cases := []struct {
		schema, name, want string
	}{
		{"app", "invoices", "app.invoices"},
		{"app", "user", `app."user"`}, // name is reserved
		{"order", "x", `"order".x`},   // schema is reserved
		{"MixedCase", "y", `"MixedCase".y`},
	}
	for _, c := range cases {
		t.Run(c.schema+"."+c.name, func(t *testing.T) {
			got, err := QuoteQualified(c.schema, c.name)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != c.want {
				t.Errorf("QuoteQualified(%q, %q) = %q, want %q", c.schema, c.name, got, c.want)
			}
		})
	}
}

func TestQuoteQualified_PropagatesErrors(t *testing.T) {
	// Invalid schema bubbles up.
	if _, err := QuoteQualified("", "x"); err == nil {
		t.Error("expected error for empty schema")
	}
	// Invalid name bubbles up.
	if _, err := QuoteQualified("app", ""); err == nil {
		t.Error("expected error for empty name")
	}
	// Control-char in either bubbles up.
	if _, err := QuoteQualified("app\x00", "x"); err == nil {
		t.Error("expected error for control char in schema")
	}
	if _, err := QuoteQualified("app", "x\x00"); err == nil {
		t.Error("expected error for control char in name")
	}
}
