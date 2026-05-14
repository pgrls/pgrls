"""Text, JSON, and SARIF formatters for pgrls.diff Changes.

The text format is for humans — wording and layout are not stable
across releases. CI consumers should use --format json or --format sarif.

JSON / SARIF output reuses the canonical `Violation` shape produced
by `pgrls lint`, so a CI consumer that parses lint output handles
diff output without code changes. `rule_id` values use the `DIFF_*`
prefix (e.g. `DIFF_USING_TIGHTENED`) — disjoint from lint's
`SEC###` / `PERF###` / `HYG###` namespace, so an aggregator merging
both feeds has no rule_id collisions by construction.
"""
from __future__ import annotations

from collections import Counter
from typing import get_args

from pgrls.diff.differ import Change, ChangeKind, Classification
from pgrls.formatters import format_violations
from pgrls.formatters._common import (
    EMPTY_OR_ZERO_WIDTH_SENTINEL,
    safe_location,
)
from pgrls.formatters.sarif import format_sarif
from pgrls.violations import Severity, Violation

# ---------------------------------------------------------------------------
# Marker sets
# ---------------------------------------------------------------------------

_ADD_KINDS: frozenset[ChangeKind] = frozenset(
    {
        ChangeKind.TABLE_ADDED_WITH_RLS,
        ChangeKind.TABLE_ADDED_WITHOUT_RLS,
        ChangeKind.POLICY_ADDED_RESTRICTIVE,
        ChangeKind.POLICY_ADDED_PERMISSIVE,
        ChangeKind.GRANT_ADDED,
        ChangeKind.GRANT_PUBLIC_NO_RLS,
    }
)

_DROP_KINDS: frozenset[ChangeKind] = frozenset(
    {
        ChangeKind.TABLE_DROPPED,
        ChangeKind.POLICY_DROPPED_RESTRICTIVE,
        ChangeKind.POLICY_DROPPED_PERMISSIVE,
        ChangeKind.COLUMN_DROPPED_REFERENCED,
        ChangeKind.GRANT_REVOKED,
    }
)

_MOD_KINDS: frozenset[ChangeKind] = frozenset(
    {
        ChangeKind.USING_TIGHTENED,
        ChangeKind.USING_LOOSENED,
        ChangeKind.USING_REQUIRES_REVIEW,
        ChangeKind.WITH_CHECK_TIGHTENED,
        ChangeKind.WITH_CHECK_LOOSENED,
        ChangeKind.WITH_CHECK_REQUIRES_REVIEW,
        ChangeKind.PERMISSIVE_FLAG_TIGHTENED,
        ChangeKind.PERMISSIVE_FLAG_LOOSENED,
        ChangeKind.COMMAND_BROADENED,
        ChangeKind.COMMAND_NARROWED,
        ChangeKind.ROLES_WIDENED,
        ChangeKind.ROLES_NARROWED,
        ChangeKind.ROLES_DISJOINT_REPLACED,
        # POLICY_RENAMED is reserved in the ChangeKind enum but no
        # detection rule through v0.5.10 emits it — rename detection
        # remains unimplemented (see `_diff_policies` docstring).
        # Classify as a modification anyway so a future detection
        # rule (or programmatic Change construction in tests) doesn't
        # crash the formatter with "unknown ChangeKind".
        ChangeKind.POLICY_RENAMED,
    }
)

_STATE_KINDS: frozenset[ChangeKind] = frozenset(
    {
        ChangeKind.RLS_FLIPPED,
        ChangeKind.FORCE_RLS_FLIPPED,
    }
)

# Predicate kinds that produce a before/after SQL block.
_PREDICATE_KINDS: frozenset[ChangeKind] = frozenset(
    {
        ChangeKind.USING_TIGHTENED,
        ChangeKind.USING_LOOSENED,
        ChangeKind.USING_REQUIRES_REVIEW,
        ChangeKind.WITH_CHECK_TIGHTENED,
        ChangeKind.WITH_CHECK_LOOSENED,
        ChangeKind.WITH_CHECK_REQUIRES_REVIEW,
    }
)

# ---------------------------------------------------------------------------
# Per-kind summary line (short, human-readable)
# ---------------------------------------------------------------------------

_SUMMARY_BY_KIND: dict[ChangeKind, str] = {
    # Table presence
    ChangeKind.TABLE_ADDED_WITH_RLS: "table added (RLS enabled)",
    ChangeKind.TABLE_ADDED_WITHOUT_RLS: "table added (no RLS)",
    ChangeKind.TABLE_DROPPED: "table dropped",
    # RLS state
    ChangeKind.RLS_FLIPPED: "RLS state changed",
    ChangeKind.FORCE_RLS_FLIPPED: "FORCE RLS state changed",
    # Policy add / drop
    ChangeKind.POLICY_ADDED_RESTRICTIVE: "policy added (RESTRICTIVE)",
    ChangeKind.POLICY_ADDED_PERMISSIVE: "policy added (PERMISSIVE)",
    ChangeKind.POLICY_DROPPED_RESTRICTIVE: "policy dropped (RESTRICTIVE)",
    ChangeKind.POLICY_DROPPED_PERMISSIVE: "policy dropped (PERMISSIVE)",
    # Policy shape
    ChangeKind.PERMISSIVE_FLAG_TIGHTENED: "policy flag changed: PERMISSIVE → RESTRICTIVE",
    ChangeKind.PERMISSIVE_FLAG_LOOSENED: "policy flag changed: RESTRICTIVE → PERMISSIVE",
    ChangeKind.COMMAND_BROADENED: "policy command broadened",
    ChangeKind.COMMAND_NARROWED: "policy command narrowed",
    ChangeKind.ROLES_WIDENED: "policy roles widened",
    ChangeKind.ROLES_NARROWED: "policy roles narrowed",
    ChangeKind.ROLES_DISJOINT_REPLACED: "policy roles replaced",
    ChangeKind.POLICY_RENAMED: "policy renamed",
    # Predicates
    ChangeKind.USING_TIGHTENED: "USING predicate tightened",
    ChangeKind.USING_LOOSENED: "USING predicate loosened",
    ChangeKind.USING_REQUIRES_REVIEW: "USING predicate changed",
    ChangeKind.WITH_CHECK_TIGHTENED: "WITH CHECK predicate tightened",
    ChangeKind.WITH_CHECK_LOOSENED: "WITH CHECK predicate loosened",
    ChangeKind.WITH_CHECK_REQUIRES_REVIEW: "WITH CHECK predicate changed",
    # Columns
    ChangeKind.COLUMN_DROPPED_REFERENCED: "column dropped (still referenced)",
    # Grants
    ChangeKind.GRANT_REVOKED: "grant revoked",
    ChangeKind.GRANT_ADDED: "grant added",
    ChangeKind.GRANT_PUBLIC_NO_RLS: "PUBLIC grant on table with no RLS",
}

# ---------------------------------------------------------------------------
# Summary line bucket ordering
# ---------------------------------------------------------------------------

# Canonical order for the trailing summary: dangerous → requires-review →
# breaking → safe. The classification field uses underscores internally;
# the user-facing label for requires_review uses a hyphen.
_BUCKET_ORDER: list[str] = ["dangerous", "requires_review", "breaking", "safe"]
_BUCKET_LABEL: dict[str, str] = {
    "dangerous": "dangerous",
    "requires_review": "requires-review",
    "breaking": "breaking",
    "safe": "safe",
}

# Import-time exhaustiveness check — every Classification literal value
# must appear as a key in _BUCKET_LABEL AND in _BUCKET_ORDER. Mirrors the
# `_CLASSIFICATION_TO_SEVERITY` exhaustiveness guard further down. A 5th
# Classification ever added would silently drop from the trailing summary
# without this check.
_classification_values: frozenset[str] = frozenset(get_args(Classification))
_missing_labels = _classification_values - set(_BUCKET_LABEL)
_missing_order = _classification_values - set(_BUCKET_ORDER)
if _missing_labels or _missing_order:
    raise RuntimeError(  # pragma: no cover — import-time invariant
        "pgrls.diff.formatters bucket tables must cover every "
        f"Classification value. Missing from _BUCKET_LABEL: "
        f"{sorted(_missing_labels)}; missing from _BUCKET_ORDER: "
        f"{sorted(_missing_order)}."
    )
del _classification_values, _missing_labels, _missing_order


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _marker(kind: ChangeKind) -> str:
    if kind in _ADD_KINDS:
        return "+"
    if kind in _DROP_KINDS:
        return "-"
    if kind in _MOD_KINDS:
        return "~"
    if kind in _STATE_KINDS:
        return "!"
    raise ValueError(f"unknown ChangeKind: {kind}")


# Import-time completeness check — every ChangeKind value must land in
# exactly one marker set. A new enum member added in a later task that
# someone forgets to wire here would otherwise blow up at runtime
# (in the middle of a `pgrls diff` call) with `unknown ChangeKind`.
# Prefer to fail the import so the test suite catches it first.
_all_marker_kinds: frozenset[ChangeKind] = (
    _ADD_KINDS | _DROP_KINDS | _MOD_KINDS | _STATE_KINDS
)
_missing_kinds = set(ChangeKind) - _all_marker_kinds
if _missing_kinds:
    raise RuntimeError(
        "pgrls.diff.formatters is missing marker classification for "
        f"ChangeKind member(s): {sorted(k.name for k in _missing_kinds)}. "
        "Add to one of _ADD_KINDS / _DROP_KINDS / _MOD_KINDS / _STATE_KINDS."
    )
del _missing_kinds, _all_marker_kinds


def _render_stanza(change: Change) -> list[str]:
    """Return lines (no trailing newline) for one Change stanza."""
    marker = _marker(change.kind)
    lines: list[str] = []

    # Header line: marker + location. `safe_location` keeps the
    # line single — operator-supplied identifiers (introspected
    # from `pg_catalog`) can legally contain `\n` / `\r` / `\t` /
    # zero-width chars inside a quoted Postgres identifier, and
    # without escaping those split the stanza header into multiple
    # lines that a `^- (\S+)$` CI grep can't distinguish from a
    # legitimate second stanza. Mirrors the `pgrls lint --format
    # text` hardening from v0.5.10. Zero-width-only locations
    # collapse to "" after sanitization; surface the
    # `(empty-or-zero-width)` sentinel instead of a bare marker
    # so the reader sees that there WAS something there. An
    # all-empty `change.location` (in practice never produced by
    # the differ, but defensively handled) gets the same
    # treatment.
    #
    # The `before_sql` / `after_sql` predicate blocks below are
    # NOT sanitized — those are operator-supplied SQL text and
    # multi-line clauses (e.g. `USING (\n  tenant_id = ...\n)`)
    # are legitimate diff output.
    raw_loc = change.location
    if not raw_loc:
        loc = EMPTY_OR_ZERO_WIDTH_SENTINEL
    else:
        cleaned = safe_location(raw_loc)
        loc = cleaned if cleaned else EMPTY_OR_ZERO_WIDTH_SENTINEL
    lines.append(f"{marker} {loc}")

    # Summary line (2-space indent)
    summary = _SUMMARY_BY_KIND.get(change.kind, "change")
    lines.append(f"  {summary}")

    # Predicate block (only for USING_* / WITH_CHECK_* kinds)
    if change.kind in _PREDICATE_KINDS:
        before = change.before_sql if change.before_sql is not None else "(no clause)"
        after = change.after_sql if change.after_sql is not None else "(no clause)"
        lines.append(f"- {before}")
        lines.append(f"+ {after}")

    # Classification line (2-space indent, uppercase tag)
    tag = change.classification.upper()
    lines.append(f"  [{tag}] {change.message}")

    return lines


def _trailing_summary(changes: list[Change]) -> str:
    if not changes:
        return "pgrls diff: no changes."

    n = len(changes)
    counts: Counter[str] = Counter(c.classification for c in changes)

    parts: list[str] = []
    for bucket in _BUCKET_ORDER:
        count = counts.get(bucket, 0)
        if count:
            label = _BUCKET_LABEL[bucket]
            parts.append(f"{count} {label}")

    breakdown = ", ".join(parts)
    # Singular/plural agreement on the count noun. The classification
    # buckets stay bare-noun ("1 dangerous") regardless because the
    # classification IS the noun there.
    noun = "change" if n == 1 else "changes"
    return f"pgrls diff: {n} {noun} — {breakdown}."


# ---------------------------------------------------------------------------
# Public function
# ---------------------------------------------------------------------------


def format_diff_text(changes: list[Change]) -> str:
    """Render a list of Changes in git-diff style for human consumption."""
    if not changes:
        return "pgrls diff: no changes."

    stanzas: list[list[str]] = [_render_stanza(c) for c in changes]

    # Join stanzas with a single blank line between them
    body_lines: list[str] = []
    for i, stanza_lines in enumerate(stanzas):
        if i > 0:
            body_lines.append("")  # blank separator
        body_lines.extend(stanza_lines)

    # Append trailing summary (no blank line before it — it follows immediately)
    body_lines.append(_trailing_summary(changes))

    return "\n".join(body_lines)


# ---------------------------------------------------------------------------
# Change → Violation projection (JSON / SARIF formatters)
# ---------------------------------------------------------------------------

_CLASSIFICATION_TO_SEVERITY: dict[Classification, Severity] = {
    "safe": "info",
    "breaking": "warning",
    "requires_review": "warning",
    "dangerous": "error",
}

# Import-time exhaustiveness check — every Classification Literal value must
# appear in _CLASSIFICATION_TO_SEVERITY. Mirrors the _all_marker_kinds check
# above for ChangeKind, surfacing gaps at import time rather than at runtime.
_all_classifications = set(get_args(Classification))
_missing_classifications = _all_classifications - set(_CLASSIFICATION_TO_SEVERITY)
if _missing_classifications:
    raise RuntimeError(
        "pgrls.diff.formatters is missing severity mapping for "
        f"Classification value(s): {sorted(_missing_classifications)}. "
        "Add to _CLASSIFICATION_TO_SEVERITY."
    )
del _missing_classifications, _all_classifications


# Acronym tokens that must keep all-caps capitalization in the
# humanized `title` field. `str.title()` would otherwise crush
# them: "RLS_FLIPPED" → "Rls Flipped", "GRANT_PUBLIC_NO_RLS" →
# "Grant Public No Rls". Each entry is the UPPERCASE form that
# both appears in ChangeKind names AND should appear in titles.
# Add new acronyms here as they enter the enum — keep this
# allowlist tight, NOT forward-looking. A speculative entry like
# "OR" or "AND" would incorrectly preserve a future kind that
# happens to use those tokens (e.g. `BROADENED_OR_NARROWED`).
_TITLE_ACRONYMS: frozenset[str] = frozenset({"RLS"})


def _humanize_kind_name(kind_name: str) -> str:
    """Render `USING_TIGHTENED` → `Using Tightened`, `RLS_FLIPPED` → `RLS Flipped`.

    `str.title()` lowercases past the first character of each
    whitespace-delimited token, which crushes acronyms. Iterate
    word-by-word and preserve any token in `_TITLE_ACRONYMS`
    in its uppercase form; otherwise apply title-case to the
    individual word.
    """
    return " ".join(
        word if word in _TITLE_ACRONYMS else word.title()
        for word in kind_name.split("_")
    )


def _change_to_violation(c: Change) -> Violation:
    """Project a Change into a Violation for the existing JSON/SARIF formatters."""
    return Violation(
        rule_id=c.kind.value,
        severity=_CLASSIFICATION_TO_SEVERITY[c.classification],
        title=_humanize_kind_name(c.kind.name),
        message=c.message,
        location=c.location,
    )


def format_diff_json(changes: list[Change]) -> str:
    """Render a list of Changes as the canonical JSON violations document."""
    violations = [_change_to_violation(c) for c in changes]
    return format_violations(violations, format="json")


def format_diff_sarif(changes: list[Change]) -> str:
    """Render a list of Changes as a SARIF v2.1.0 JSON document."""
    violations = [_change_to_violation(c) for c in changes]
    return format_sarif(violations)


# Public constant for the CLI: the user-facing values for the
# `pgrls diff --format` option. Mirrors `pgrls.formatters.
# SUPPORTED_FORMATS` (the lint command's source of truth) and is
# kept here so a future format addition (e.g. markdown) only
# requires editing this module — the CLI consumes the constant.
DIFF_SUPPORTED_FORMATS: tuple[str, ...] = ("text", "json", "sarif")
