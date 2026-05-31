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
from typing import Any

from pglast.stream import RawStream

_PLAIN_IDENT_RE = re.compile(r"^[a-z_][a-z0-9_]*$")

# C0 controls (\x00..\x1f) and DEL (\x7f). An earlier change
# rejected null byte, LF, and CR; tab and the rest of the C0 range
# pose the same embedding-in-quoted-SQL hazard. Catch the whole
# range so the defense is uniform and a future reader doesn't read
# the null-only test and assume tab is fine.
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


def alter_policy(
    table: Any,
    policy_name: str,
    *,
    using_ast: Any | None = None,
    with_check_ast: Any | None = None,
) -> str:
    """Assemble an `ALTER POLICY` statement with optional clauses.

    Single source of truth for the shape the PERF001 / SEC006 /
    SEC011 / SEC019 / SEC020 fixers all emit:

        ALTER POLICY <name> ON <schema>.<table>
            [USING (<using_ast>)]
            [WITH CHECK (<with_check_ast>)];

    `USING` precedes `WITH CHECK`; each clause is 4-space indented
    and only rendered when its AST is provided. Each clause AST is
    round-tripped through `pglast.stream.RawStream` so pglast's
    escaping is applied consistently regardless of where the SQL
    originated. The identifier and qualified-name quoting is the
    same `quote_ident` / `quote_qualified` this module owns.

    At least one clause is expected; with neither, the result is a
    bare `ALTER POLICY … ON …;` (no fixer emits that — they all
    only call this after establishing a clause changed).
    """
    clauses: list[str] = []
    if using_ast is not None:
        clauses.append(f"    USING ({RawStream()(using_ast)})")
    if with_check_ast is not None:
        clauses.append(f"    WITH CHECK ({RawStream()(with_check_ast)})")
    return (
        f"ALTER POLICY {quote_ident(policy_name)} "
        f"ON {quote_qualified(table.schema, table.name)}\n"
        + "\n".join(clauses)
        + ";"
    )


def enable_rls_sql(qname: str) -> str:
    """`ALTER TABLE <qname> ENABLE ROW LEVEL SECURITY;` (SEC001 shape).

    `qname` is already a quoted qualified name (`quote_qualified`).
    Shared verbatim by the SEC001 fixer and `pgrls generate`.
    """
    return f"ALTER TABLE {qname} ENABLE ROW LEVEL SECURITY;"


def force_rls_sql(qname: str) -> str:
    """`ALTER TABLE <qname> FORCE ROW LEVEL SECURITY;` (SEC002 shape).

    `qname` is already a quoted qualified name (`quote_qualified`).
    Shared verbatim by the SEC002 fixer and `pgrls generate`.
    """
    return f"ALTER TABLE {qname} FORCE ROW LEVEL SECURITY;"


def create_index_sql(qname: str, column: str) -> str:
    """`CREATE INDEX ON <qname> (<column>);` (PERF003 shape).

    `qname` is already a quoted qualified name; `column` is a raw
    identifier and is quoted here via `quote_ident`. The index name
    is left to Postgres (no explicit name), matching PERF003's
    recommended remediation. Shared verbatim by the PERF003 fixer
    and `pgrls generate`.
    """
    return f"CREATE INDEX ON {qname} ({quote_ident(column)});"
