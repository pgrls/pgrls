"""Identifier quoting helpers for fixer-emitted SQL.

`pg_class.relname`, `pg_policy.polname`, and `pg_namespace.nspname`
all return raw, unquoted identifiers. When pgrls's fixers emit
`ALTER TABLE schema.name` etc., a name containing special characters
or matching a reserved keyword needs Postgres-style double-quoting
(`"weird name"`, `"order"`). Plain `snake_case` non-keywords don't.

A name is emitted BARE only when it is a valid unquoted Postgres
`ColId` — the grammar position every identifier pgrls emits sits in
(policy / table / schema / column / role names). Rather than hand-
maintain a keyword list (which silently rots: the *fully*-reserved
subset is not enough — `type_func_name`-reserved words like `join`,
`left`, `is`, `natural` are equally invalid as a bare `ColId` yet are
not "fully reserved"), `_is_safe_bare_ident` PROBE-PARSES the name in
a `ColId` position via pglast. Coverage therefore tracks the installed
parser's grammar exactly — reserved AND type_func_name keywords, case
folding, and punctuation all decided by one check — so a policy named
`join` or column named `left` (captured verbatim from clean live
introspection) is quoted instead of emitting `ALTER POLICY join …`,
which the server rejects.

The structural regex `[a-z_][a-z0-9_]*` is kept as a fast pre-filter:
anything outside it (mixed case, embedded spaces/dots/punctuation,
non-ASCII letters, leading digit) is quoted without a probe. Only a NUL
byte is rejected outright — it is the one character Postgres forbids in
an identifier even when double-quoted (it terminates the C string).
Tab / newline / CR and the rest of the C0 range are legal double-quoted
identifier characters, so they are quoted (not rejected): rejecting the
whole range over-rejected legitimately-named objects (a quoted
`"a<TAB>b"` table is valid Postgres) and aborted the whole fix run.
"""
from __future__ import annotations

import hashlib
import re
from functools import lru_cache
from typing import Any

import pglast
from pglast.ast import ColumnDef
from pglast.stream import RawStream

_PLAIN_IDENT_RE = re.compile(r"^[a-z_][a-z0-9_]*$")

# NUL (\x00) is the ONLY character Postgres forbids in an identifier —
# it terminates the underlying C string, so even a double-quoted
# `"a<NUL>b"` is an "unterminated quoted identifier" error. Every other
# byte, including tab / newline / CR and the rest of the C0 range, is a
# legal identifier character when double-quoted (`CREATE TABLE "a<TAB>b"`
# parses), and live introspection returns such names raw. Double-quoting
# (with the `"` -> `""` escape below) neutralizes them safely — there is
# no embedding-breakout hazard, since only an unescaped `"` could close
# the quotes. So reject ONLY NUL and quote the rest; rejecting the whole
# C0 range over-rejected legitimately-named objects and aborted the
# entire fix / Schema.to_sql() run on one of them.
_NUL_RE = re.compile(r"\x00")


@lru_cache(maxsize=4096)
def _is_safe_bare_ident(name: str) -> bool:
    """True iff `name` is valid UNQUOTED as a Postgres ``ColId``.

    ``ColId`` is the grammar nonterminal for policy / table / schema /
    column / role names — every position pgrls emits an identifier in.
    A word is a valid bare ``ColId`` iff it is neither a fully-reserved
    nor a ``type_func_name``-reserved keyword (the latter — `join`,
    `left`, `is`, `natural`, … — is the category a fully-reserved list
    misses). We decide by probe-parsing rather than enumerating
    keywords, so the answer always matches the installed pglast's
    grammar and never drifts.

    The probe puts `name` in a column-definition position
    (``CREATE TABLE __probe (<name> integer)``) and requires it to come
    back as exactly one ``ColumnDef`` whose ``colname`` equals `name`
    verbatim — so a case-folded spelling (``MyCol`` → ``mycol``) or a
    name that smuggled extra tokens is rejected and quoted. The
    structural regex gate first rejects anything non-lowercase-ASCII,
    so the probe only runs for plain-looking candidates and `colname`
    equality is then exact. Cached: identifiers repeat heavily across a
    snapshot's tables/columns.
    """
    if not _PLAIN_IDENT_RE.match(name):
        return False
    try:
        stmts = pglast.parse_sql(
            f"CREATE TABLE __pgrls_ident_probe ({name} integer)"
        )
    except Exception:
        return False
    if len(stmts) != 1:
        return False
    elts = stmts[0].stmt.tableElts
    if not elts or len(elts) != 1:
        return False
    first = elts[0]
    return isinstance(first, ColumnDef) and first.colname == name


def quote_ident(name: str) -> str:
    """Quote `name` with double quotes if Postgres syntax requires it.

    Doubled quotes inside the name are escaped (`he"llo` →
    `"he""llo"`), matching Postgres's standard escaping rule.

    Rejects only a NUL byte — the sole character Postgres forbids in an
    identifier (it can't appear even double-quoted). Every other byte,
    including tab / newline / CR, is a legal double-quoted identifier
    character that Postgres accepts and that live introspection can
    return raw, so it is quoted, not rejected. (An earlier version
    rejected the whole C0 range + DEL, which over-rejected legitimately-
    named objects and aborted the entire fix / Schema.to_sql() run.)

    Bare-vs-quoted is decided by `_is_safe_bare_ident` (a pglast
    `ColId` probe), so reserved AND type_func_name keywords (`select`,
    `join`, `left`, `is`, …) are all quoted.
    """
    if not name:
        raise ValueError("identifier is empty")
    if _NUL_RE.search(name):
        raise ValueError(
            f"identifier contains a NUL byte (forbidden by Postgres); "
            f"refusing to emit: {name!r}"
        )
    if _is_safe_bare_ident(name):
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
    """`CREATE INDEX IF NOT EXISTS <name> ON <qname> (<column>);`.

    `qname` is already a quoted qualified name; `column` is a raw
    identifier and is quoted here via `quote_ident`. Shared verbatim by
    the PERF003 fixer and `pgrls generate`.

    The index is given a DETERMINISTIC name plus `IF NOT EXISTS` (the
    same scheme PERF004's fixer uses) so an emitted `pgrls fix --output`
    / `pgrls generate --output` migration is safely re-runnable.
    Postgres does NOT treat a repeated *unnamed* `CREATE INDEX` as a
    no-op — it auto-names and builds a redundant duplicate — so leaving
    the name to Postgres made committed migrations non-idempotent. The
    name hashes the (qualified table, column) so it is stable across
    runs and collision-resistant.
    """
    index_name = "pgrls_idx_" + hashlib.sha1(
        f"{qname}.{column}".encode()
    ).hexdigest()[:16]
    return (
        f"CREATE INDEX IF NOT EXISTS {index_name} "
        f"ON {qname} ({quote_ident(column)});"
    )
