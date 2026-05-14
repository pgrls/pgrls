package pgrlstest

import (
	"fmt"
	"regexp"
	"strings"
)

// ReservedKeywords is the Postgres 16 fully-reserved-keywords set
// (appendix C, "reserved" column). Identifiers matching any of
// these (case-insensitive) MUST be double-quoted in emitted SQL,
// or the server will mis-parse `SET LOCAL ROLE select` etc. as
// a SELECT statement.
//
// Cross-language guarantee: 78 entries, byte-equivalent to the
// Python `_RESERVED_KEYWORDS` and the TypeScript
// `RESERVED_KEYWORDS`. Adding or removing one is a wire
// behavior change — bump all three in lockstep and update the
// conformance fixtures.
//
// Stored as a `map[string]struct{}` for O(1) lookup; the
// zero-byte value type keeps memory overhead minimal.
var ReservedKeywords = map[string]struct{}{
	"all":               {},
	"analyse":           {},
	"analyze":           {},
	"and":               {},
	"any":               {},
	"array":             {},
	"as":                {},
	"asc":               {},
	"asymmetric":        {},
	"both":              {},
	"case":              {},
	"cast":              {},
	"check":             {},
	"collate":           {},
	"column":            {},
	"constraint":        {},
	"create":            {},
	"current_catalog":   {},
	"current_date":      {},
	"current_role":      {},
	"current_time":      {},
	"current_timestamp": {},
	"current_user":      {},
	"default":           {},
	"deferrable":        {},
	"desc":              {},
	"distinct":          {},
	"do":                {},
	"else":              {},
	"end":               {},
	"except":            {},
	"false":             {},
	"fetch":             {},
	"for":               {},
	"foreign":           {},
	"from":              {},
	"grant":             {},
	"group":             {},
	"having":            {},
	"in":                {},
	"initially":         {},
	"intersect":         {},
	"into":              {},
	"lateral":           {},
	"leading":           {},
	"limit":             {},
	"localtime":         {},
	"localtimestamp":    {},
	"not":               {},
	"null":              {},
	"offset":            {},
	"on":                {},
	"only":              {},
	"or":                {},
	"order":             {},
	"placing":           {},
	"primary":           {},
	"references":        {},
	"returning":         {},
	"select":            {},
	"session_user":      {},
	"some":              {},
	"symmetric":         {},
	"system_user":       {},
	"table":             {},
	"then":              {},
	"to":                {},
	"trailing":          {},
	"true":              {},
	"union":             {},
	"unique":            {},
	"user":              {},
	"using":             {},
	"variadic":          {},
	"when":              {},
	"where":             {},
	"window":            {},
	"with":              {},
}

// plainIdentRe matches identifiers that need no quoting: lower-
// case ASCII letters / underscores for the first char, plus
// digits for subsequent. Same regex Postgres's lexer uses for
// "downcased plain identifier" — anything outside this AND not
// matching a reserved keyword can flow into emitted SQL raw.
var plainIdentRe = regexp.MustCompile(`^[a-z_][a-z0-9_]*$`)

// controlCharsRe catches C0 control chars (\x00..\x1f) and DEL
// (\x7f). Postgres rejects these at CREATE time, but a hand-
// passed identifier (e.g. user-typed in `client.AsRole("evil\x00",
// …)`) could carry them; fail fast here rather than emitting
// SQL that parses confusingly on the server. Same defense the
// TS port carries.
var controlCharsRe = regexp.MustCompile("[\x00-\x1f\x7f]")

// QuoteIdent quotes `name` with double quotes if Postgres syntax
// requires it. Returns the bare name otherwise.
//
// Doubled quotes inside the name are escaped (`he"llo` →
// `"he""llo"`), matching Postgres's standard escaping rule.
//
// Rejects null bytes, control characters, and DEL explicitly via
// a returned error — fail loudly rather than silently emit
// `"a\x00b"` and get a confusing parse error from the server.
//
// Cross-language guarantee: identical output to Python's
// `pgrls.fixers._idents.quote_ident` and TypeScript's
// `quoteIdent`. Used by `Client.AsRole` (for `SET LOCAL ROLE
// <quoted>`) and `Client.Seed` (for `INSERT INTO <quoted>`).
func QuoteIdent(name string) (string, error) {
	if name == "" {
		return "", &Error{Msg: "QuoteIdent: identifier is empty"}
	}
	if controlCharsRe.MatchString(name) {
		return "", &Error{
			Msg: fmt.Sprintf(
				"QuoteIdent: identifier contains a control character; refusing to emit: %q",
				name,
			),
		}
	}
	// Reserved-keyword check is case-insensitive: `SELECT`,
	// `Select`, `select` all map to the same token in Postgres's
	// parser, so any case folding into the reserved set must be
	// quoted.
	lower := strings.ToLower(name)
	if _, isReserved := ReservedKeywords[lower]; isReserved {
		return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`, nil
	}
	if plainIdentRe.MatchString(name) {
		return name, nil
	}
	return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`, nil
}

// QuoteQualified quotes a `schema.name` pair, each component
// independently. Used by `Client.Seed` to handle schema-qualified
// table names like `app.invoices`; without this, an unquoted
// `order.user` (both reserved) would parse-fail on the server.
func QuoteQualified(schema, name string) (string, error) {
	qs, err := QuoteIdent(schema)
	if err != nil {
		return "", err
	}
	qn, err := QuoteIdent(name)
	if err != nil {
		return "", err
	}
	return qs + "." + qn, nil
}
