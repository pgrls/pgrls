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
from dataclasses import replace

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
from pgrls.violations import Violation

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
            found = rule.check(schema, config.rule_options.get(rule.id, {}))
        except Exception:
            # A rule that trips over partial mid-edit DDL must not take down the
            # whole diagnostics pass (or the editor session).
            continue
        # Apply the per-rule severity override exactly as `cli._run_rules` does:
        # keyed on the *running* rule's id, before the level is mapped. Keeping
        # the keying identical (rather than on each violation's `rule_id`) is
        # what makes the diagnostics a faithful subset of `pgrls lint
        # --sql-file` — a custom rule may emit a violation under a foreign id.
        override = overrides.get(rule.id)
        if override is not None:
            found = [replace(v, severity=override) for v in found]
        violations.extend(found)

    spans = _object_spans(text)
    index = _LineIndex(text)
    out: list[lsp.Diagnostic] = []
    for v in violations:
        span = spans.resolve(v.location) if v.location else None
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


class _Spans:
    """Buffer spans of a document's defined objects, grouped by the kind of
    `Violation.location` that resolves to them.

    A `location` is a flat dotted string, so a policy name and a granted column
    name of the same table would otherwise collide on one dict key. Grouping by
    kind keeps them apart and lets `resolve` pick the right statement.
    """

    def __init__(self) -> None:
        self.table: dict[str, tuple[int, int]] = {}
        self.policy: dict[str, tuple[int, int]] = {}
        self.column: dict[str, tuple[int, int]] = {}

    def resolve(self, location: str) -> tuple[int, int] | None:
        """Best source span for a finding's `location` (None if the object is
        not defined in this buffer).

        A 2-part `schema.table` matches a table span. A 3-part `schema.table.X`
        is ambiguous — `X` may be a policy or a granted column — so a
        column-grant span is tried first (a SEC045 column finding must not
        underline a policy that merely shares the column's name), then a policy
        span, then the owning table's `CREATE` as a fallback so a finding never
        silently collapses to the document start while its table sits right
        there in the buffer.
        """
        if location in self.table:
            return self.table[location]
        if location in self.column:
            return self.column[location]
        if location in self.policy:
            return self.policy[location]
        head = location.rpartition(".")[0]
        return self.table.get(head) if head else None


def _object_spans(text: str) -> _Spans:
    """Map each defined object to its buffer span, grouped by object kind.

    Table spans are keyed `schema.table` (`Table.qualified_name`), policy spans
    `schema.table.policy`, and column-grant spans `schema.table.column` — the
    three shapes a `Violation.location` takes. First occurrence of a key wins,
    so a `CREATE` keeps its span even if a later `ALTER` references the object.
    """
    spans = _Spans()
    try:
        statements = pglast.parse_sql(text)
    except pglast.parser.ParseError:
        return spans

    default_schema = "public"
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
        span = (start, end)

        kind = type(stmt).__name__
        if kind in ("CreateStmt", "AlterTableStmt"):
            # AlterTableStmt covers a table defined only by ALTER in this buffer
            # (a migration file); `setdefault` lets a CREATE win if present too.
            rk = _relation_key(stmt.relation, default_schema)
            if rk is not None:
                spans.table.setdefault(f"{rk[0]}.{rk[1]}", span)
        elif kind == "CreatePolicyStmt":
            rk = _relation_key(stmt.table, default_schema)
            pname = getattr(stmt, "policy_name", None)
            if rk is not None and pname:
                spans.policy.setdefault(f"{rk[0]}.{rk[1]}.{pname}", span)
        elif kind == "GrantStmt" and stmt.is_grant:
            # A column-level GRANT (`GRANT SELECT (col) ON t TO role`) is the
            # precise site SEC045 flags — register each granted column so the
            # finding underlines the GRANT itself, not the whole table or a
            # policy that merely shares the column's name. REVOKEs
            # (`is_grant` false) never create a grant a rule fires on.
            columns = {
                col.sval
                for priv in (stmt.privileges or ())
                for col in (priv.cols or ())
                if col.sval
            }
            for obj in stmt.objects or ():
                if type(obj).__name__ != "RangeVar":
                    continue
                rk = _relation_key(obj, default_schema)
                if rk is None:
                    continue
                for column in columns:
                    spans.column.setdefault(f"{rk[0]}.{rk[1]}.{column}", span)

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
