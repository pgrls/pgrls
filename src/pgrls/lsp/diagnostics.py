"""The protocol-free core of the pgrls Language Server.

`diagnose(text)` turns a `.sql` buffer into a list of LSP `Diagnostic`s. It is
a pure function — no `pygls`, no server, no I/O — so it is unit-testable
without an LSP client.

It reuses the exact offline path `pgrls lint --sql-file` runs:

1. `schema_from_sql(text)` builds a `Schema` from the buffer's DDL. A buffer
   that doesn't parse (a normal state mid-keystroke) yields **no** diagnostics
   rather than an error — the editor must not flash a crash while you type.
2. Every rule that is *analyzable offline* runs (`all_rules()` minus the
   `inert_rule_ids("sql")` catalog-only set), so the diagnostics are a subset
   of what `pgrls lint --sql-file` would report — never a finding the CLI
   wouldn't make. A rule that raises on partial mid-edit input is skipped, not
   propagated.
3. Each finding's logical location (`schema.table[.policy]`) is mapped back to
   a **precise source range** by walking the parsed statements' `stmt_location`
   / `stmt_len` spans — the offline buffer *is* source text, so the range that
   the `github` formatter can't produce against a live database is available
   here (issue #227, addressing the `AGENTS.md` note).
"""
from __future__ import annotations

import bisect

import pglast
from lsprotocol import types as lsp

from pgrls.rules import all_rules
from pgrls.schema_sources import (
    SchemaSourceError,
    _relation_key,
    inert_rule_ids,
    schema_from_sql,
)
from pgrls.violations import Violation

_SOURCE = "pgrls"
_RULES_DOC = "https://github.com/pgrls/pgrls/blob/main/docs/RULES.md#rule-"

_SEVERITY: dict[str, lsp.DiagnosticSeverity] = {
    "error": lsp.DiagnosticSeverity.Error,
    "warning": lsp.DiagnosticSeverity.Warning,
    "info": lsp.DiagnosticSeverity.Information,
}

# A finding whose object has no `CREATE …` statement in the buffer (e.g. a
# migration that only `ALTER`s a table defined elsewhere) has no span to
# underline — anchor it at the document start rather than dropping it.
_ZERO_RANGE = lsp.Range(
    start=lsp.Position(line=0, character=0),
    end=lsp.Position(line=0, character=0),
)


def diagnose(text: str) -> list[lsp.Diagnostic]:
    """LSP diagnostics for a `.sql` buffer (empty if it doesn't parse)."""
    try:
        schema = schema_from_sql(text)
    except SchemaSourceError:
        # Unparseable mid-edit buffer: publish nothing, don't surface an error.
        return []

    inert = inert_rule_ids("sql")
    violations: list[Violation] = []
    for rule in all_rules():
        if rule.id in inert:
            # Catalog-only rule — cannot be analyzed from a SQL buffer; the CLI
            # skips it offline too, so skip it here to keep parity.
            continue
        try:
            violations.extend(rule.check(schema, {}))
        except Exception:
            # A rule that trips over partial mid-edit DDL must not take down the
            # whole diagnostics pass (or the editor session).
            continue

    spans = _object_spans(text)
    index = _LineIndex(text)
    out: list[lsp.Diagnostic] = []
    for v in violations:
        span = spans.get(v.location) if v.location else None
        rng = (
            lsp.Range(
                start=index.position(span[0]),
                end=index.position(span[1]),
            )
            if span is not None
            else _ZERO_RANGE
        )
        out.append(
            lsp.Diagnostic(
                range=rng,
                message=v.message,
                severity=_SEVERITY.get(v.severity, lsp.DiagnosticSeverity.Error),
                source=_SOURCE,
                code=v.rule_id,
                code_description=lsp.CodeDescription(
                    href=f"{_RULES_DOC}{v.rule_id.lower()}"
                ),
            )
        )
    return out


def _object_spans(text: str) -> dict[str, tuple[int, int]]:
    """Map each defined object (`schema.table[.policy]`) to its buffer span.

    Keys are formatted exactly as `Violation.location` is (`Table.qualified_name`
    and `f"{table}.{policy}"`), so a finding looks its range up directly. First
    occurrence wins, so a `CREATE` keeps its span even if a later `ALTER`
    references the same object.
    """
    try:
        statements = pglast.parse_sql(text)
    except pglast.parser.ParseError:
        return {}

    default_schema = "public"
    spans: dict[str, tuple[int, int]] = {}
    length = len(text)
    for raw in statements:
        stmt = raw.stmt
        # pglast's `stmt_location` for a non-first statement points at the
        # whitespace/newline after the preceding `;` — advance past it so the
        # range underlines the statement, not the gap before it.
        start = raw.stmt_location or 0
        while start < length and text[start] in " \t\r\n":
            start += 1
        end = (raw.stmt_location or 0) + (raw.stmt_len or 0)
        if end < start:
            end = start

        kind = type(stmt).__name__
        key: str | None = None
        if kind == "CreateStmt":
            rk = _relation_key(stmt.relation, default_schema)
            if rk is not None:
                key = f"{rk[0]}.{rk[1]}"
        elif kind == "CreatePolicyStmt":
            rk = _relation_key(stmt.table, default_schema)
            pname = getattr(stmt, "policy_name", None)
            if rk is not None and pname:
                key = f"{rk[0]}.{rk[1]}.{pname}"
        elif kind == "AlterTableStmt":
            # Fallback for a table defined only by ALTER in this buffer (a
            # migration file). setdefault below lets a CREATE win if present.
            rk = _relation_key(stmt.relation, default_schema)
            if rk is not None:
                key = f"{rk[0]}.{rk[1]}"

        if key is not None:
            spans.setdefault(key, (start, end))
    return spans


class _LineIndex:
    """Char-offset → LSP `Position` (0-indexed line, UTF-16 character)."""

    def __init__(self, text: str) -> None:
        self._text = text
        self._line_starts = [0]
        for i, ch in enumerate(text):
            if ch == "\n":
                self._line_starts.append(i + 1)

    def position(self, offset: int) -> lsp.Position:
        offset = max(0, min(offset, len(self._text)))
        line = bisect.bisect_right(self._line_starts, offset) - 1
        line_start = self._line_starts[line]
        # LSP counts `character` in UTF-16 code units, not Unicode code points,
        # so a non-ASCII prefix (an emoji in a comment) offsets correctly.
        prefix = self._text[line_start:offset]
        character = len(prefix.encode("utf-16-le")) // 2
        return lsp.Position(line=line, character=character)


# Re-exported for the server module / tests.
__all__ = ["diagnose"]
