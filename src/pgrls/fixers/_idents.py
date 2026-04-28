"""Identifier quoting helpers for fixer-emitted SQL.

`pg_class.relname`, `pg_policy.polname`, and `pg_namespace.nspname`
all return raw, unquoted identifiers. When pgrls's fixers emit
`ALTER TABLE schema.name` etc., a name containing special characters
or matching a reserved keyword needs Postgres-style double-quoting
(`"weird name"`, `"order"`). Plain `snake_case` doesn't.

We do NOT consult Postgres's reserved-keyword list — the common
case of `snake_case` identifiers is keyword-free, and the over-
quoting cost (always producing `"public"."users"`) is uglier in
the dominant case. Borderline names (mixed case, embedded spaces,
leading digit, anything outside `[a-z_][a-z0-9_]*`) get quoted;
others are emitted bare. Users with reserved-word table names will
need to quote in their own code anyway.
"""
from __future__ import annotations

import re

_PLAIN_IDENT_RE = re.compile(r"^[a-z_][a-z0-9_]*$")


def quote_ident(name: str) -> str:
    """Quote `name` with double quotes if Postgres syntax requires it.

    Doubled quotes inside the name are escaped (`he"llo` →
    `"he""llo"`), matching Postgres's standard escaping rule.

    Rejects null bytes and embedded newlines/carriage returns
    explicitly. Postgres rejects them at CREATE time so they
    can't reach this helper from real introspection, but a
    snapshot or hand-built `Schema` could; failing fast here is
    clearer than emitting `"a\\x00b"` and getting a confusing
    parse error from the server.
    """
    if "\x00" in name or "\n" in name or "\r" in name:
        raise ValueError(
            f"identifier contains a null byte or newline; "
            f"refusing to emit: {name!r}"
        )
    if _PLAIN_IDENT_RE.match(name):
        return name
    return '"' + name.replace('"', '""') + '"'


def quote_qualified(schema: str, name: str) -> str:
    """Quote a `schema.name` pair, each component independently."""
    return f"{quote_ident(schema)}.{quote_ident(name)}"
