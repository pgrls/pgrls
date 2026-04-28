"""Identifier quoting helpers for fixer-emitted SQL.

`pg_class.relname`, `pg_policy.polname`, and `pg_namespace.nspname`
all return raw, unquoted identifiers. When pgrls's fixers emit
`ALTER TABLE schema.name` etc., a name containing special characters
or matching a reserved keyword needs Postgres-style double-quoting
(`"weird name"`, `"order"`). Plain `snake_case` non-keywords don't.

We DO consult Postgres's reserved-keyword list — `_RESERVED_KEYWORDS`
below — so a table named `"select"` or a policy named `"order"` gets
quoted automatically. A user copy-pasting `pgrls fix` output into
psql shouldn't have to fix syntax errors that stem from the linter
emitting `ALTER TABLE public.select FORCE ROW LEVEL SECURITY;` (which
the server rejects). The set is the "fully reserved" subset from
Postgres 16's appendix C — words that can never appear unquoted as
column/table names. Type-context-only reserved keywords (e.g.
`bigint`, `numeric`) are NOT included; those are valid as identifier
names per Postgres parser.

Beyond keywords: identifiers outside `[a-z_][a-z0-9_]*` (mixed case,
embedded spaces/dots/punctuation, non-ASCII letters, leading digit)
also get quoted. C0 control characters and DEL are rejected outright
— Postgres rejects them at CREATE time, but a snapshot or hand-built
`Schema` could carry them; failing fast here beats producing SQL
that parses confusingly on the server.
"""
from __future__ import annotations

import re

_PLAIN_IDENT_RE = re.compile(r"^[a-z_][a-z0-9_]*$")

# C0 controls (\x00..\x1f) and DEL (\x7f). Round 14 rejected null
# byte, LF, and CR; tab and the rest of the C0 range pose the same
# embedding-in-quoted-SQL hazard. Catch the whole range so the
# defense is uniform and a future reader doesn't read the
# null-only test and assume tab is fine.
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")

# Postgres 16 fully-reserved keywords (appendix C, "reserved" column).
# Type-context-only reserved (e.g. `bigint`, `numeric`) are NOT here
# — those parse as identifiers in non-type position. Keep this list
# alphabetized; new keywords are extremely rare (Postgres holds the
# vocabulary stable across decades).
_RESERVED_KEYWORDS: frozenset[str] = frozenset({
    "all", "analyse", "analyze", "and", "any", "array", "as", "asc",
    "asymmetric", "both", "case", "cast", "check", "collate", "column",
    "constraint", "create", "current_catalog", "current_date",
    "current_role", "current_time", "current_timestamp", "current_user",
    "default", "deferrable", "desc", "distinct", "do", "else", "end",
    "except", "false", "fetch", "for", "foreign", "from", "grant",
    "group", "having", "in", "initially", "intersect", "into",
    "lateral", "leading", "limit", "localtime", "localtimestamp",
    "not", "null", "offset", "on", "only", "or", "order", "placing",
    "primary", "references", "returning", "select", "session_user",
    "some", "symmetric", "system_user", "table", "then", "to",
    "trailing", "true", "union", "unique", "user", "using", "variadic",
    "when", "where", "window", "with",
})


def quote_ident(name: str) -> str:
    """Quote `name` with double quotes if Postgres syntax requires it.

    Doubled quotes inside the name are escaped (`he"llo` →
    `"he""llo"`), matching Postgres's standard escaping rule.

    Rejects null bytes, control characters, and DEL explicitly.
    Postgres rejects them at CREATE time so they can't reach this
    helper from real introspection, but a snapshot or hand-built
    `Schema` could; failing fast here is clearer than emitting
    `"a\\x00b"` and getting a confusing parse error from the server.
    """
    if not name:
        raise ValueError("identifier is empty")
    if _CONTROL_CHARS_RE.search(name):
        raise ValueError(
            f"identifier contains a control character; "
            f"refusing to emit: {name!r}"
        )
    # Reserved-keyword check is case-insensitive: `SELECT`/`Select`/
    # `select` all map to the same token in Postgres's parser, so
    # any case folding into the reserved set must be quoted.
    if name.lower() in _RESERVED_KEYWORDS:
        return '"' + name.replace('"', '""') + '"'
    if _PLAIN_IDENT_RE.match(name):
        return name
    return '"' + name.replace('"', '""') + '"'


def quote_qualified(schema: str, name: str) -> str:
    """Quote a `schema.name` pair, each component independently."""
    return f"{quote_ident(schema)}.{quote_ident(name)}"
