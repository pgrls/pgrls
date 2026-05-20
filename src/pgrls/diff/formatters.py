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
# Rationale text — `pgrls diff --explain`
# ---------------------------------------------------------------------------

# Keyed by `(ChangeKind, Classification)` rather than just `ChangeKind`
# because RLS_FLIPPED and FORCE_RLS_FLIPPED reuse one kind for both
# directions (on→off and off→on) but emit different classifications.
# A future direction-dependent kind doesn't need special-casing —
# add the new `(kind, classification)` entry and the import-time
# exhaustiveness check below confirms coverage.
#
# Rationales answer the "why does this Change carry this
# classification" question one layer deeper than the per-Change
# `message` field (which describes *what* changed). One paragraph
# each — long enough to be useful in a CI log without burying the
# diff payload.
_RATIONALE_BY_KIND_AND_CLASSIFICATION: dict[
    tuple[ChangeKind, Classification], str
] = {
    # ---------- Table presence ----------
    (ChangeKind.TABLE_ADDED_WITH_RLS, "safe"): (
        "New table ships with RLS enabled. With no policies yet, "
        "Postgres denies non-owner reads and writes by default, so "
        "the table is closed by construction until a policy is added."
    ),
    (ChangeKind.TABLE_ADDED_WITHOUT_RLS, "dangerous"): (
        "New table has no RLS. Every role with table privileges can "
        "see every row — no tenant isolation, no default-deny shape. "
        "Add `ALTER TABLE ... ENABLE ROW LEVEL SECURITY` and at least "
        "one policy before granting access."
    ),
    (ChangeKind.TABLE_DROPPED, "breaking"): (
        "Table dropped. Reads and writes that referenced it will fail "
        "until callers are updated. Classified BREAKING (access "
        "narrows to nothing) rather than DANGEROUS (which is reserved "
        "for changes that widen access)."
    ),
    # ---------- RLS state ----------
    (ChangeKind.RLS_FLIPPED, "safe"): (
        "RLS was enabled on a table that previously had it off. "
        "Existing policies (if any) now apply; with no policies, "
        "Postgres denies non-owner access by default."
    ),
    (ChangeKind.RLS_FLIPPED, "dangerous"): (
        "RLS was disabled on a table that previously had it on. "
        "Every policy on the table stops applying — every row becomes "
        "reachable to any role with table privileges. This is the "
        "single most dangerous diff signal pgrls reports."
    ),
    (ChangeKind.FORCE_RLS_FLIPPED, "safe"): (
        "FORCE ROW LEVEL SECURITY was newly enabled. Policies now "
        "apply to the table owner too, closing the bypass that "
        "default RLS leaves open for the owning role."
    ),
    (ChangeKind.FORCE_RLS_FLIPPED, "dangerous"): (
        "FORCE ROW LEVEL SECURITY was disabled. The table owner now "
        "bypasses every policy, regaining full-table access — exactly "
        "the owner-bypass that default RLS leaves open and FORCE RLS "
        "exists to close."
    ),
    # ---------- Policy add / drop ----------
    (ChangeKind.POLICY_ADDED_RESTRICTIVE, "safe"): (
        "A RESTRICTIVE policy was added. Restrictive policies "
        "AND-combine into the access predicate — adding one can only "
        "narrow access, never widen it."
    ),
    (ChangeKind.POLICY_ADDED_PERMISSIVE, "dangerous"): (
        "A PERMISSIVE policy was added. Permissive policies "
        "OR-combine into the access predicate — adding one widens "
        "access by including its rows in the visible set. Review "
        "whether the new disjunct is the intended access shape."
    ),
    (ChangeKind.POLICY_DROPPED_RESTRICTIVE, "dangerous"): (
        "A RESTRICTIVE policy was dropped. Restrictive policies "
        "AND-combine — removing one removes a tightening conjunct, "
        "so rows it previously blocked are now reachable through "
        "the remaining policies."
    ),
    (ChangeKind.POLICY_DROPPED_PERMISSIVE, "breaking"): (
        "A PERMISSIVE policy was dropped. Permissive policies "
        "OR-combine — removing one removes a disjunct, so rows it "
        "previously made visible may no longer be. Classified "
        "BREAKING (access narrows, callers may see empty result "
        "sets) rather than DANGEROUS."
    ),
    # ---------- Policy shape ----------
    (ChangeKind.PERMISSIVE_FLAG_TIGHTENED, "safe"): (
        "Policy switched from PERMISSIVE to RESTRICTIVE. Its "
        "predicate now AND-combines with the other policies instead "
        "of OR-combining — the access set can only shrink."
    ),
    (ChangeKind.PERMISSIVE_FLAG_LOOSENED, "dangerous"): (
        "Policy switched from RESTRICTIVE to PERMISSIVE. Its "
        "predicate now OR-combines with the other policies instead "
        "of AND-combining — the access set can only grow."
    ),
    (ChangeKind.COMMAND_BROADENED, "dangerous"): (
        "Policy command was broadened (narrow command → ALL). The "
        "policy now authorizes additional verbs against the table; "
        "operations that previously fell back to default-deny are "
        "now gated only by this policy's predicate."
    ),
    (ChangeKind.COMMAND_NARROWED, "breaking"): (
        "Policy command was narrowed (ALL → narrow, or one narrow "
        "command swapped for another). Operations previously "
        "authorized by this policy now fall back to default-deny — "
        "callers performing the dropped verbs against this table "
        "will start failing."
    ),
    (ChangeKind.ROLES_WIDENED, "dangerous"): (
        "Policy applies to a wider role set than before. Principals "
        "that did not match the policy's role list previously now "
        "do, gaining access through its predicate."
    ),
    (ChangeKind.ROLES_NARROWED, "safe"): (
        "Policy applies to a narrower role set than before. Some "
        "principals lose access through this policy; the new role "
        "set is a strict subset of the old."
    ),
    (ChangeKind.ROLES_DISJOINT_REPLACED, "requires_review"): (
        "Policy role set was replaced with a disjoint set — old "
        "principals lost access, new ones gained it. Whether the "
        "swap matches intent depends on the migration; pgrls cannot "
        "decide automatically."
    ),
    # POLICY_RENAMED is reserved in ChangeKind but no detection rule
    # through v0.5.42 emits it (a rename surfaces as drop+add). The
    # entry is here for forward compatibility — a future emitter
    # picking this kind doesn't crash --explain.
    (ChangeKind.POLICY_RENAMED, "requires_review"): (
        "Policy was renamed. Through v0.5.42 the differ never emits "
        "this kind (a rename surfaces as a drop + add with their "
        "independent classifications); the entry exists for forward "
        "compatibility when rename detection ships."
    ),
    # ---------- Predicate changes ----------
    (ChangeKind.USING_TIGHTENED, "safe"): (
        "USING predicate added a conjunct (AND-tighten) or dropped "
        "a disjunct (OR-tighten-drop). Fewer rows pass — the head "
        "is strictly more restrictive than the base."
    ),
    (ChangeKind.USING_LOOSENED, "dangerous"): (
        "USING predicate added a disjunct (OR-loosen) or dropped a "
        "conjunct (AND-loosen-drop). More rows pass — the head is "
        "strictly less restrictive than the base."
    ),
    (ChangeKind.USING_REQUIRES_REVIEW, "requires_review"): (
        "USING predicate changed in a shape that is not a simple "
        "AND/OR shift. pgrls cannot mechanically prove whether the "
        "new predicate is more or less permissive than the old. "
        "Install `pgrls[diff-z3]` for SAT-assisted classification, "
        "or review manually."
    ),
    (ChangeKind.WITH_CHECK_TIGHTENED, "safe"): (
        "WITH CHECK predicate added a conjunct or dropped a "
        "disjunct. Fewer writes pass — the head's write validation "
        "is strictly tighter than the base's."
    ),
    (ChangeKind.WITH_CHECK_LOOSENED, "dangerous"): (
        "WITH CHECK predicate added a disjunct or dropped a "
        "conjunct. More writes pass — the head accepts writes the "
        "base would have rejected."
    ),
    (ChangeKind.WITH_CHECK_REQUIRES_REVIEW, "requires_review"): (
        "WITH CHECK predicate changed in a shape that is not a "
        "simple AND/OR shift. Install `pgrls[diff-z3]` for "
        "SAT-assisted classification, or review manually."
    ),
    # ---------- Columns ----------
    (ChangeKind.COLUMN_DROPPED_REFERENCED, "requires_review"): (
        "A column was dropped while still referenced by at least "
        "one policy's USING or WITH CHECK predicate. The policy is "
        "now invalid; review whether to rewrite the policy or "
        "re-add the column."
    ),
    # ---------- Grants ----------
    (ChangeKind.GRANT_REVOKED, "safe"): (
        "A privilege was revoked from a role. The role can no "
        "longer perform the corresponding operation through that "
        "grant."
    ),
    (ChangeKind.GRANT_ADDED, "requires_review"): (
        "A privilege was granted to a role. Verify the role is "
        "supposed to have this access — pgrls cannot tell intent "
        "from shape, so every grant addition is REQUIRES_REVIEW "
        "by default."
    ),
    (ChangeKind.GRANT_PUBLIC_NO_RLS, "dangerous"): (
        "A privilege was granted to PUBLIC on a table with no RLS. "
        "Every authenticated role can now perform the operation, "
        "with no per-row scoping — the canonical accidental-"
        "exposure shape pgrls diff watches for."
    ),
}

# Import-time exhaustiveness check — every ChangeKind that the
# differ emits MUST have at least one `(kind, classification)`
# entry in the rationale table. The differ doesn't currently
# expose its emission set as data, so the canonical list below is
# the contract. A new ChangeKind added without a rationale would
# silently degrade `pgrls diff --explain` to "no rationale shown"
# for that kind — fail at import instead.
_EXPECTED_RATIONALE_KEYS: frozenset[tuple[ChangeKind, Classification]] = (
    frozenset(
        {
            (ChangeKind.TABLE_ADDED_WITH_RLS, "safe"),
            (ChangeKind.TABLE_ADDED_WITHOUT_RLS, "dangerous"),
            (ChangeKind.TABLE_DROPPED, "breaking"),
            (ChangeKind.RLS_FLIPPED, "safe"),
            (ChangeKind.RLS_FLIPPED, "dangerous"),
            (ChangeKind.FORCE_RLS_FLIPPED, "safe"),
            (ChangeKind.FORCE_RLS_FLIPPED, "dangerous"),
            (ChangeKind.POLICY_ADDED_RESTRICTIVE, "safe"),
            (ChangeKind.POLICY_ADDED_PERMISSIVE, "dangerous"),
            (ChangeKind.POLICY_DROPPED_RESTRICTIVE, "dangerous"),
            (ChangeKind.POLICY_DROPPED_PERMISSIVE, "breaking"),
            (ChangeKind.PERMISSIVE_FLAG_TIGHTENED, "safe"),
            (ChangeKind.PERMISSIVE_FLAG_LOOSENED, "dangerous"),
            (ChangeKind.COMMAND_BROADENED, "dangerous"),
            (ChangeKind.COMMAND_NARROWED, "breaking"),
            (ChangeKind.ROLES_WIDENED, "dangerous"),
            (ChangeKind.ROLES_NARROWED, "safe"),
            (ChangeKind.ROLES_DISJOINT_REPLACED, "requires_review"),
            (ChangeKind.POLICY_RENAMED, "requires_review"),
            (ChangeKind.USING_TIGHTENED, "safe"),
            (ChangeKind.USING_LOOSENED, "dangerous"),
            (ChangeKind.USING_REQUIRES_REVIEW, "requires_review"),
            (ChangeKind.WITH_CHECK_TIGHTENED, "safe"),
            (ChangeKind.WITH_CHECK_LOOSENED, "dangerous"),
            (ChangeKind.WITH_CHECK_REQUIRES_REVIEW, "requires_review"),
            (ChangeKind.COLUMN_DROPPED_REFERENCED, "requires_review"),
            (ChangeKind.GRANT_REVOKED, "safe"),
            (ChangeKind.GRANT_ADDED, "requires_review"),
            (ChangeKind.GRANT_PUBLIC_NO_RLS, "dangerous"),
        }
    )
)

_missing_rationale = _EXPECTED_RATIONALE_KEYS - set(
    _RATIONALE_BY_KIND_AND_CLASSIFICATION
)
_unexpected_rationale = set(_RATIONALE_BY_KIND_AND_CLASSIFICATION) - _EXPECTED_RATIONALE_KEYS
if _missing_rationale or _unexpected_rationale:
    raise RuntimeError(  # pragma: no cover — import-time invariant
        "pgrls.diff.formatters._RATIONALE_BY_KIND_AND_CLASSIFICATION "
        "drifted from _EXPECTED_RATIONALE_KEYS. Missing: "
        f"{sorted(repr(p) for p in _missing_rationale)}; Unexpected: "
        f"{sorted(repr(p) for p in _unexpected_rationale)}."
    )
del _missing_rationale, _unexpected_rationale

# Verify every ChangeKind that the differ can emit has at least one
# rationale entry (one entry suffices — covers the kinds that emit
# a single classification; the flip kinds emit two and have both).
_kinds_with_rationale = {k for k, _ in _RATIONALE_BY_KIND_AND_CLASSIFICATION}
_kinds_without_rationale = set(ChangeKind) - _kinds_with_rationale
if _kinds_without_rationale:
    raise RuntimeError(  # pragma: no cover — import-time invariant
        "pgrls.diff.formatters is missing rationale entries for "
        f"ChangeKind member(s): "
        f"{sorted(k.name for k in _kinds_without_rationale)}. "
        "Add a (kind, classification) entry to "
        "_RATIONALE_BY_KIND_AND_CLASSIFICATION."
    )
del _kinds_with_rationale, _kinds_without_rationale


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


def _render_stanza(change: Change, *, explain: bool = False) -> list[str]:
    """Return lines (no trailing newline) for one Change stanza.

    When ``explain=True``, append a `  -> <rationale>` line below
    the classification line, explaining why this kind carries the
    classification it does. A `(kind, classification)` pair with no
    rationale entry degrades silently (no suffix) — same approach
    `pgrls lint --explain` takes when a rule's docstring is absent.
    """
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

    # Optional rationale line — `pgrls diff --explain`. Indented to
    # match the classification line and prefixed with `-> ` so the
    # rationale is visually distinct from the classification message
    # while staying in the same stanza block.
    if explain:
        rationale = _RATIONALE_BY_KIND_AND_CLASSIFICATION.get(
            (change.kind, change.classification)
        )
        if rationale:
            lines.append(f"  -> {rationale}")

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


def format_diff_text(changes: list[Change], *, explain: bool = False) -> str:
    """Render a list of Changes in git-diff style for human consumption.

    When ``explain=True``, each stanza grows a `  -> <rationale>`
    line below the classification line explaining the reason
    behind the classification — `pgrls diff --explain`'s text-only
    mode. JSON / SARIF output ignore the flag (rationale lives in
    the per-Change classification tag those formats already carry).
    """
    if not changes:
        return "pgrls diff: no changes."

    stanzas: list[list[str]] = [
        _render_stanza(c, explain=explain) for c in changes
    ]

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
