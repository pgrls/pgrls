"""The protocol-free core of the pgrls Language Server.

`diagnose(text, config=...)` turns a `.sql` buffer into a list of LSP
`Diagnostic`s. It is a pure function — no `pygls`, no server, no I/O — so it is
unit-testable without an LSP client.

It reuses the exact offline path `pgrls lint --sql-file` runs:

1. `schema_from_sql(text)` builds a `Schema` from the buffer's DDL. A buffer
   that doesn't parse (a normal state mid-keystroke) yields **no** diagnostics
   rather than an error — the editor must not flash a crash while you type.
2. The project's `pgrls.toml` (`config`) is honored the same way the CLI honors
   it: disabled rules don't run, per-rule `allowlist`s apply, `extra_rules`
   load, and `severity_overrides` remap the diagnostic level. So the
   diagnostics are a subset of what `pgrls lint --sql-file` would report **with
   the same config** — never a finding the CLI wouldn't make. Catalog-only rules
   (the `inert_rule_ids("sql")` set — BYPASSRLS roles, triggers, …) can't be
   analyzed from a buffer and are skipped, exactly as the CLI skips them offline.
   A rule that raises on partial mid-edit input is skipped, not propagated.
3. Each finding's logical location (`schema.table[.policy]`) is mapped back to a
   **precise source range** by walking the parsed statements' `stmt_location` /
   `stmt_len` spans — the offline buffer *is* source text, so the range the
   `github` formatter can't produce against a live database is available here
   (issue #227).
"""
from __future__ import annotations

import bisect

import pglast
from lsprotocol import types as lsp

from pgrls.config import Config
from pgrls.rules import (
    Rule,
    RuleRegistry,
    all_rules,
    default_registry,
    load_extra_rules,
)
from pgrls.schema_sources import (
    SchemaSourceError,
    _relation_key,
    inert_rule_ids,
    schema_from_sql,
)
from pgrls.violations import Severity, Violation

_SOURCE = "pgrls"
_RULES_DOC = "https://github.com/pgrls/pgrls/blob/main/docs/RULES.md#rule-"

_SEVERITY: dict[str, lsp.DiagnosticSeverity] = {
    "error": lsp.DiagnosticSeverity.Error,
    "warning": lsp.DiagnosticSeverity.Warning,
    "info": lsp.DiagnosticSeverity.Information,
}

# A finding whose object has no `CREATE …` / `ALTER …` statement in the buffer
# (e.g. a rule keyed on a schema-wide object) has no span to underline — anchor
# it at the document start rather than dropping it.
_ZERO_RANGE = lsp.Range(
    start=lsp.Position(line=0, character=0),
    end=lsp.Position(line=0, character=0),
)


def diagnose(text: str, *, config: Config | None = None) -> list[lsp.Diagnostic]:
    """LSP diagnostics for a `.sql` buffer (empty if it doesn't parse).

    `config` is the resolved `pgrls.toml` for the project; when omitted, an
    unconfigured default is used (every rule at its default severity, no
    allowlists) — the shape a plain `pgrls lint --sql-file` produces.
    """
    try:
        schema = schema_from_sql(text)
    except SchemaSourceError:
        # Unparseable mid-edit buffer: publish nothing, don't surface an error.
        return []

    if config is None:
        config = Config()

    inert = inert_rule_ids("sql")
    overrides = config.severity_overrides
    violations: list[Violation] = []
    for rule in _rules_for(config):
        if rule.id in inert:
            # Catalog-only rule — cannot be analyzed from a SQL buffer; the CLI
            # skips it offline too, so skip it here to keep parity.
            continue
        try:
            violations.extend(
                rule.check(schema, config.rule_options.get(rule.id, {}))
            )
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
        severity: Severity = overrides.get(v.rule_id, v.severity)
        out.append(
            lsp.Diagnostic(
                range=rng,
                message=v.message,
                severity=_SEVERITY.get(severity, lsp.DiagnosticSeverity.Error),
                source=_SOURCE,
                code=v.rule_id,
                code_description=lsp.CodeDescription(
                    href=f"{_RULES_DOC}{v.rule_id.lower()}"
                ),
            )
        )
    return out


def _rules_for(config: Config) -> list[Rule]:
    """The rule set to run, honoring `config.disable` / `config.extra_rules`.

    Mirrors `cli._run_rules`'s registry build. A malformed / colliding extra
    rule can't be surfaced as a hard error in an editor, so the bad module is
    skipped and linting proceeds with the built-ins.
    """
    if config.extra_rules:
        registry = RuleRegistry()
        for r in all_rules():
            registry.register(r)
        for r in load_extra_rules(config.extra_rules):
            try:
                registry.register(r)
            except ValueError:
                continue
    else:
        registry = default_registry()
    return list(registry.enabled(disabled_ids=config.disable))


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
        loc = raw.stmt_location or 0
        # pglast's `stmt_location` points at the whitespace / comment before the
        # statement — advance past leading blanks AND SQL comments so the range
        # underlines the statement, not a license header or the gap after the
        # previous `;`.
        start = _skip_leading_noise(text, loc, length)
        # pglast reports `stmt_len == 0` for a statement with no trailing `;`
        # (the last statement of a file, and every statement mid-keystroke) —
        # the sentinel for "extends to end of input". Take end-of-buffer there
        # instead of collapsing the range to a zero-width point.
        raw_len = raw.stmt_len or 0
        end = (loc + raw_len) if raw_len else length
        while end > start and text[end - 1] in " \t\r\n":
            end -= 1
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


def _skip_leading_noise(text: str, i: int, length: int) -> int:
    """Advance `i` past leading whitespace and SQL comments (`--`, `/* */`)."""
    while i < length:
        if text[i] in " \t\r\n":
            i += 1
        elif text.startswith("--", i):
            nl = text.find("\n", i)
            i = length if nl == -1 else nl + 1
        elif text.startswith("/*", i):
            close = text.find("*/", i + 2)
            i = length if close == -1 else close + 2
        else:
            break
    return i


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


__all__ = ["diagnose"]
