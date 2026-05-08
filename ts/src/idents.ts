/**
 * Identifier quoting helpers for SQL emitted by pgrls-test.
 *
 * `pg_class.relname`, `pg_policy.polname`, and `pg_namespace.nspname`
 * all return raw, unquoted identifiers. When pgrls-test emits
 * `SET LOCAL ROLE <role>` or `INSERT INTO schema.name (...)`, a name
 * containing special characters or matching a reserved keyword needs
 * Postgres-style double-quoting (`"weird name"`, `"order"`). Plain
 * `snake_case` non-keywords don't.
 *
 * We DO consult Postgres's reserved-keyword list — `RESERVED_KEYWORDS`
 * below — so a role named `"order"` or a table named `"select"` gets
 * quoted automatically. A test that calls
 * `client.asRole('order', {}, async () => …)` shouldn't fail with a
 * confusing parse error from the server.
 *
 * Beyond keywords: identifiers outside `[a-z_][a-z0-9_]*` (mixed
 * case, embedded spaces/dots/punctuation, non-ASCII letters, leading
 * digit) also get quoted. C0 control characters and DEL are rejected
 * outright — Postgres rejects them at CREATE time, but a hand-passed
 * role name or table identifier could carry them; failing fast here
 * beats producing SQL that parses confusingly on the server.
 *
 * Direct port of `src/pgrls/fixers/_idents.py`. The reserved-keyword
 * set, the C0+DEL rejection, the doubled-quote escaping, and the
 * "plain identifier" regex are all byte-for-byte equivalent.
 */

const PLAIN_IDENT_RE = /^[a-z_][a-z0-9_]*$/;

/**
 * C0 controls (`\x00..\x1f`) and DEL (`\x7f`). Catching the whole
 * range so the defense is uniform — a future reader doesn't see a
 * null-byte-only test and assume tab is fine.
 */
// eslint-disable-next-line no-control-regex
const CONTROL_CHARS_RE = /[\x00-\x1f\x7f]/;

/**
 * Postgres 16 fully-reserved keywords (appendix C, "reserved" column).
 * Type-context-only reserved words (e.g. `bigint`, `numeric`) are NOT
 * here — those parse as identifiers in non-type position. Keep
 * alphabetized; new keywords are extremely rare.
 *
 * Mirrors `_RESERVED_KEYWORDS` in `src/pgrls/fixers/_idents.py`. If
 * Postgres adds a fully-reserved keyword in a future major, both
 * lists must update together — the cross-language conformance suite
 * pins identical behaviour.
 */
export const RESERVED_KEYWORDS: ReadonlySet<string> = new Set([
  'all',
  'analyse',
  'analyze',
  'and',
  'any',
  'array',
  'as',
  'asc',
  'asymmetric',
  'both',
  'case',
  'cast',
  'check',
  'collate',
  'column',
  'constraint',
  'create',
  'current_catalog',
  'current_date',
  'current_role',
  'current_time',
  'current_timestamp',
  'current_user',
  'default',
  'deferrable',
  'desc',
  'distinct',
  'do',
  'else',
  'end',
  'except',
  'false',
  'fetch',
  'for',
  'foreign',
  'from',
  'grant',
  'group',
  'having',
  'in',
  'initially',
  'intersect',
  'into',
  'lateral',
  'leading',
  'limit',
  'localtime',
  'localtimestamp',
  'not',
  'null',
  'offset',
  'on',
  'only',
  'or',
  'order',
  'placing',
  'primary',
  'references',
  'returning',
  'select',
  'session_user',
  'some',
  'symmetric',
  'system_user',
  'table',
  'then',
  'to',
  'trailing',
  'true',
  'union',
  'unique',
  'user',
  'using',
  'variadic',
  'when',
  'where',
  'window',
  'with',
]);

/**
 * Quote `name` with double quotes if Postgres syntax requires it.
 *
 * Doubled quotes inside the name are escaped (`he"llo` →
 * `"he""llo"`), matching Postgres's standard escaping rule.
 *
 * Rejects null bytes, control characters, and DEL explicitly.
 * Postgres rejects them at CREATE time so they can't reach this
 * helper from real introspection, but a hand-passed identifier
 * could; failing fast here is clearer than emitting `"a\x00b"` and
 * getting a confusing parse error from the server.
 *
 * @throws {Error} If `name` is empty or contains a control character.
 */
export function quoteIdent(name: string): string {
  if (!name) {
    throw new Error('identifier is empty');
  }
  if (CONTROL_CHARS_RE.test(name)) {
    throw new Error(
      `identifier contains a control character; refusing to emit: ${JSON.stringify(name)}`,
    );
  }
  // Reserved-keyword check is case-insensitive: `SELECT`/`Select`/
  // `select` all map to the same token in Postgres's parser, so
  // any case folding into the reserved set must be quoted.
  if (RESERVED_KEYWORDS.has(name.toLowerCase())) {
    return '"' + name.replace(/"/g, '""') + '"';
  }
  if (PLAIN_IDENT_RE.test(name)) {
    return name;
  }
  return '"' + name.replace(/"/g, '""') + '"';
}

/**
 * Quote a `schema.name` pair, each component independently.
 */
export function quoteQualified(schema: string, name: string): string {
  return `${quoteIdent(schema)}.${quoteIdent(name)}`;
}
