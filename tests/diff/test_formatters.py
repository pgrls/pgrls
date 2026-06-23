"""Tests for pgrls.diff.formatters (text + JSON + SARIF)."""
from __future__ import annotations

import pytest

from pgrls.diff.differ import Change, ChangeKind
from pgrls.diff.formatters import (
    EMPTY_OR_ZERO_WIDTH_SENTINEL,
    _EXPECTED_RATIONALE_KEYS,
    _RATIONALE_BY_KIND_AND_CLASSIFICATION,
    _trailing_summary,
    format_diff_text,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _change(
    kind: ChangeKind,
    classification: str,
    location: str = "public.t",
    message: str = "Test message.",
    before_sql: str | None = None,
    after_sql: str | None = None,
) -> Change:
    return Change(
        kind=kind,
        classification=classification,  # type: ignore[arg-type]
        location=location,
        message=message,
        before_sql=before_sql,
        after_sql=after_sql,
    )


# ---------------------------------------------------------------------------
# 1. Empty changes
# ---------------------------------------------------------------------------

def test_empty_changes_renders_no_changes_summary():
    result = format_diff_text([])
    assert result == "pgrls diff: no changes."


def test_trailing_summary_handles_empty_change_list_directly():
    # `format_diff_text` short-circuits empty input before the summary,
    # but `_trailing_summary` is a standalone helper that must produce
    # the same "no changes" line when handed an empty list — pins the
    # helper's empty-input branch independent of its public caller.
    assert _trailing_summary([]) == "pgrls diff: no changes."


def test_stanza_with_empty_location_renders_sentinel():
    # A Change whose `location` is the empty string (defensively
    # handled — the differ doesn't emit one today) must not produce a
    # bare `- ` header. The renderer substitutes the
    # `(empty-or-zero-width)` sentinel so the reader sees that there
    # WAS a location slot, kept on a single line for CI greps.
    change = _change(
        ChangeKind.TABLE_DROPPED,
        "breaking",
        location="",
        message="Table dropped.",
    )
    header = format_diff_text([change]).split("\n")[0]
    assert header == f"- {EMPTY_OR_ZERO_WIDTH_SENTINEL}"


# ---------------------------------------------------------------------------
# 2. Marker +
# ---------------------------------------------------------------------------

def test_single_table_added_renders_plus_marker():
    change = _change(
        ChangeKind.TABLE_ADDED_WITH_RLS,
        "safe",
        location="public.orders",
        message="Table public.orders added with RLS enabled.",
    )
    result = format_diff_text([change])
    lines = result.split("\n")
    # Header line: + {location}
    assert lines[0] == "+ public.orders"


# ---------------------------------------------------------------------------
# 3. Marker -
# ---------------------------------------------------------------------------

def test_single_table_dropped_renders_minus_marker():
    change = _change(
        ChangeKind.TABLE_DROPPED,
        "breaking",
        location="public.orders",
        message="Table public.orders dropped.",
    )
    result = format_diff_text([change])
    lines = result.split("\n")
    assert lines[0] == "- public.orders"


# ---------------------------------------------------------------------------
# 4. Predicate block (USING change with both sides present)
# ---------------------------------------------------------------------------

def test_using_change_renders_predicate_block():
    change = _change(
        ChangeKind.USING_LOOSENED,
        "dangerous",
        location="public.invoices.tenant_isolation",
        message="Policy public.invoices.tenant_isolation USING predicate loosened.",
        before_sql="tenant_id = current_setting('app.tenant')::uuid",
        after_sql="tenant_id = current_setting('app.tenant')::uuid OR tenant_id = '00000000'",
    )
    result = format_diff_text([change])
    lines = result.split("\n")
    assert any(
        line == "- tenant_id = current_setting('app.tenant')::uuid"
        for line in lines
    )
    assert any(
        line == "+ tenant_id = current_setting('app.tenant')::uuid OR tenant_id = '00000000'"
        for line in lines
    )


# ---------------------------------------------------------------------------
# 5. before_sql is None → "- (no clause)"
# ---------------------------------------------------------------------------

def test_using_added_renders_no_clause_marker():
    change = _change(
        ChangeKind.USING_TIGHTENED,
        "safe",
        location="public.t.pol",
        message="Policy public.t.pol USING predicate tightened.",
        before_sql=None,
        after_sql="tenant_id = current_user::uuid",
    )
    result = format_diff_text([change])
    lines = result.split("\n")
    assert "- (no clause)" in lines


# ---------------------------------------------------------------------------
# 6. after_sql is None → "+ (no clause)"
# ---------------------------------------------------------------------------

def test_using_removed_renders_no_clause_marker():
    change = _change(
        ChangeKind.USING_TIGHTENED,
        "safe",
        location="public.t.pol",
        message="Policy public.t.pol USING predicate tightened.",
        before_sql="tenant_id = current_user::uuid",
        after_sql=None,
    )
    result = format_diff_text([change])
    lines = result.split("\n")
    assert "+ (no clause)" in lines


# ---------------------------------------------------------------------------
# 7. Marker !
# ---------------------------------------------------------------------------

def test_rls_flipped_renders_bang_marker():
    change = _change(
        ChangeKind.RLS_FLIPPED,
        "dangerous",
        location="public.t",
        message="Table public.t RLS disabled.",
    )
    result = format_diff_text([change])
    lines = result.split("\n")
    assert lines[0] == "! public.t"


# ---------------------------------------------------------------------------
# 8. Classification tag is uppercase
# ---------------------------------------------------------------------------

def test_classification_line_uppercase_label():
    change = _change(
        ChangeKind.USING_LOOSENED,
        "dangerous",
        location="public.t.pol",
        message="Policy public.t.pol USING predicate loosened.",
        before_sql="a = 1",
        after_sql="a = 1 OR a = 2",
    )
    result = format_diff_text([change])
    lines = result.split("\n")
    # There should be a line starting with "  [DANGEROUS]"
    classification_lines = [ln for ln in lines if ln.startswith("  [")]
    assert len(classification_lines) >= 1
    assert any("[DANGEROUS]" in ln for ln in classification_lines)
    assert not any("[dangerous]" in ln for ln in classification_lines)


# ---------------------------------------------------------------------------
# 9. Summary line omits zero-count buckets
# ---------------------------------------------------------------------------

def test_summary_line_omits_zero_buckets():
    changes = [
        _change(ChangeKind.TABLE_ADDED_WITHOUT_RLS, "dangerous", location="public.a"),
        _change(ChangeKind.GRANT_PUBLIC_NO_RLS, "dangerous", location="public.b.PUBLIC"),
    ]
    result = format_diff_text(changes)
    # Should be: "pgrls diff: 2 changes — 2 dangerous."
    # Must NOT contain "requires-review", "breaking", or "safe"
    last_line = result.split("\n")[-1]
    assert last_line == "pgrls diff: 2 changes — 2 dangerous."
    assert "requires-review" not in last_line
    assert "breaking" not in last_line
    assert "safe" not in last_line


# ---------------------------------------------------------------------------
# 10. Summary line renders all four buckets in correct order
# ---------------------------------------------------------------------------

def test_summary_line_renders_all_four_buckets():
    changes = [
        _change(ChangeKind.TABLE_ADDED_WITHOUT_RLS, "dangerous", location="public.a"),
        _change(ChangeKind.GRANT_ADDED, "requires_review", location="public.b.role"),
        _change(ChangeKind.TABLE_DROPPED, "breaking", location="public.c"),
        _change(ChangeKind.TABLE_ADDED_WITH_RLS, "safe", location="public.d"),
        _change(ChangeKind.GRANT_REVOKED, "safe", location="public.e.role"),
    ]
    result = format_diff_text(changes)
    last_line = result.split("\n")[-1]
    # Order: dangerous → requires-review → breaking → safe
    assert "5 changes" in last_line
    assert "1 dangerous" in last_line
    assert "1 requires-review" in last_line
    assert "1 breaking" in last_line
    assert "2 safe" in last_line
    # Verify order by checking index positions
    idx_dangerous = last_line.index("dangerous")
    idx_requires_review = last_line.index("requires-review")
    idx_breaking = last_line.index("breaking")
    idx_safe = last_line.index("safe")
    assert idx_dangerous < idx_requires_review < idx_breaking < idx_safe


# ---------------------------------------------------------------------------
# 11. Summary line uses hyphenated "requires-review" not underscore
# ---------------------------------------------------------------------------

def test_summary_line_uses_singular_for_one_change():
    # Pin the singular/plural agreement on the count noun. With one
    # change, the line says "1 change", not "1 changes". The
    # classification breakdown stays bare-noun ("1 dangerous")
    # because the classification IS the noun there.
    changes = [
        _change(ChangeKind.TABLE_ADDED_WITH_RLS, "safe", location="public.a")
    ]
    last_line = format_diff_text(changes).split("\n")[-1]
    assert last_line == "pgrls diff: 1 change — 1 safe."


def test_summary_line_uses_hyphen_for_requires_review():
    changes = [
        _change(ChangeKind.GRANT_ADDED, "requires_review", location="public.t.role"),
    ]
    result = format_diff_text(changes)
    last_line = result.split("\n")[-1]
    assert "requires-review" in last_line
    assert "requires_review" not in last_line


# ---------------------------------------------------------------------------
# 12. Blank line between stanzas, no trailing blank before summary
# ---------------------------------------------------------------------------

def test_blank_line_between_stanzas():
    changes = [
        _change(ChangeKind.TABLE_ADDED_WITH_RLS, "safe", location="public.a"),
        _change(ChangeKind.TABLE_ADDED_WITH_RLS, "safe", location="public.b"),
    ]
    result = format_diff_text(changes)
    lines = result.split("\n")

    # Find blank lines (empty strings).
    blank_indices = [i for i, ln in enumerate(lines) if ln == ""]

    # Exactly one blank line — between the two stanzas.
    assert len(blank_indices) == 1

    # No blank line at the very start — first line is a stanza header.
    assert lines[0] != ""

    # The summary line is last, never blank.
    assert lines[-1].startswith("pgrls diff:")

    # No blank line directly before the summary either.
    assert lines[-2] != ""


def test_using_loosened_renders_tilde_marker():
    # Dedicated test for the `~` modification marker on the header
    # line. test_using_change_renders_predicate_block exercises a `~`
    # kind but pins the predicate-block body lines, not the marker
    # itself. This test pins the header line shape so any future
    # refactor that drops `~` from _MOD_KINDS surfaces here.
    changes = [
        _change(
            ChangeKind.USING_LOOSENED,
            "dangerous",
            location="public.t.policy",
            message="USING loosened.",
            before_sql="a = 1",
            after_sql="a = 1 OR b = 2",
        )
    ]
    result = format_diff_text(changes)
    lines = result.split("\n")
    assert lines[0] == "~ public.t.policy"


# ---------------------------------------------------------------------------
# 13. --explain — per-stanza rationale line
# ---------------------------------------------------------------------------


def test_explain_false_does_not_emit_rationale_line():
    # Default behavior: no `-> ` line, output identical to a
    # caller who never set the flag at all.
    changes = [
        _change(
            ChangeKind.TABLE_DROPPED,
            "breaking",
            location="public.dropped",
            message="Table public.dropped removed.",
        )
    ]
    without = format_diff_text(changes)
    explicit_false = format_diff_text(changes, explain=False)
    assert without == explicit_false
    assert "-> " not in without


def test_explain_true_appends_rationale_for_table_dropped():
    changes = [
        _change(
            ChangeKind.TABLE_DROPPED,
            "breaking",
            location="public.dropped",
            message="Table public.dropped removed.",
        )
    ]
    result = format_diff_text(changes, explain=True)
    # The rationale line lives below the classification line,
    # indented to match it, prefixed with `-> `.
    lines = result.split("\n")
    classification_idx = next(
        i for i, ln in enumerate(lines) if ln.startswith("  [BREAKING]")
    )
    rationale_line = lines[classification_idx + 1]
    assert rationale_line.startswith("  -> ")
    assert "BREAKING" in rationale_line
    assert "narrows" in rationale_line.lower()


def test_explain_true_picks_correct_text_for_rls_flipped_directions():
    # RLS_FLIPPED uses one ChangeKind but two classifications (safe
    # for off→on, dangerous for on→off). The rationale must read
    # differently per direction — this pins the (kind, classification)
    # keying.
    on_to_off = [
        _change(
            ChangeKind.RLS_FLIPPED,
            "dangerous",
            location="public.t",
            message="Table public.t RLS disabled.",
        )
    ]
    off_to_on = [
        _change(
            ChangeKind.RLS_FLIPPED,
            "safe",
            location="public.t",
            message="Table public.t RLS enabled.",
        )
    ]

    dangerous_out = format_diff_text(on_to_off, explain=True)
    safe_out = format_diff_text(off_to_on, explain=True)

    # The "single most dangerous diff signal" framing lives ONLY in
    # the on→off rationale; the off→on rationale uses different
    # wording. Verifies the table is keyed by (kind, classification),
    # not just kind.
    assert "most dangerous diff signal" in dangerous_out
    assert "most dangerous diff signal" not in safe_out
    assert "denies non-owner access" in safe_out
    assert "denies non-owner access" not in dangerous_out


def test_explain_true_on_predicate_change_appends_after_predicate_block():
    # USING/WITH CHECK kinds have a before/after SQL block between
    # the summary and classification lines. The rationale must
    # still appear immediately below the classification line —
    # NOT inside the predicate block.
    changes = [
        _change(
            ChangeKind.USING_LOOSENED,
            "dangerous",
            location="public.t.p",
            message="USING loosened.",
            before_sql="a = 1",
            after_sql="a = 1 OR b = 2",
        )
    ]
    result = format_diff_text(changes, explain=True)
    lines = result.split("\n")
    # Expected sequence:
    #   ~ public.t.p
    #     USING predicate loosened
    #   - a = 1
    #   + a = 1 OR b = 2
    #     [DANGEROUS] USING loosened.
    #     -> ...
    assert any(ln.startswith("  -> ") for ln in lines)
    classification_idx = next(
        i for i, ln in enumerate(lines) if ln.startswith("  [DANGEROUS]")
    )
    assert lines[classification_idx + 1].startswith("  -> ")
    # Before/after SQL block stays above the classification line —
    # not below the rationale.
    assert any(ln.startswith("- a = 1") for ln in lines)
    assert any(ln.startswith("+ a = 1 OR b = 2") for ln in lines)


def test_explain_emits_one_rationale_line_per_change():
    # Multiple stanzas → one rationale line each, attached to the
    # correct classification line.
    changes = [
        _change(
            ChangeKind.TABLE_ADDED_WITH_RLS,
            "safe",
            location="public.a",
            message="Added with RLS.",
        ),
        _change(
            ChangeKind.TABLE_ADDED_WITHOUT_RLS,
            "dangerous",
            location="public.b",
            message="Added without RLS.",
        ),
    ]
    result = format_diff_text(changes, explain=True)
    rationale_lines = [
        ln for ln in result.split("\n") if ln.startswith("  -> ")
    ]
    assert len(rationale_lines) == 2
    # First stanza → safe rationale; second → dangerous.
    assert "closed by construction" in rationale_lines[0]
    assert "default-deny" in rationale_lines[1]


def test_explain_does_not_change_summary_line():
    # The trailing `pgrls diff: N changes — ...` line lives below
    # all stanzas and must be unaffected by --explain.
    changes = [
        _change(
            ChangeKind.GRANT_REVOKED,
            "safe",
            location="public.t",
            message="Grant revoked.",
        )
    ]
    summary_without = format_diff_text(changes).split("\n")[-1]
    summary_with = format_diff_text(changes, explain=True).split("\n")[-1]
    assert summary_without == summary_with


def test_explain_empty_changes_returns_no_changes_string():
    # The empty path bypasses the stanza loop entirely; --explain
    # has nothing to attach to. Output must match the un-explained
    # empty form.
    assert (
        format_diff_text([], explain=True)
        == format_diff_text([])
        == "pgrls diff: no changes."
    )


def test_explain_unknown_kind_classification_pair_degrades_silently():
    # The rationale table covers every (kind, classification) the
    # differ emits today (pinned by an import-time check). A
    # hypothetical NEW combination — e.g. someone constructs a
    # Change programmatically with TABLE_DROPPED + "safe" — has no
    # rationale entry and must silently degrade rather than crash.
    # Mirrors `pgrls lint --explain` for rules without a docstring.
    changes = [
        _change(
            ChangeKind.TABLE_DROPPED,
            "safe",  # not a real differ emission for this kind
            location="public.t",
            message="Synthetic.",
        )
    ]
    result = format_diff_text(changes, explain=True)
    # No `-> ` line for this stanza; rest of the rendering intact.
    assert "-> " not in result
    assert "  [SAFE] Synthetic." in result


def test_explain_rationale_table_covers_every_kind_classification_pair():
    # Test-side mirror of the import-time exhaustiveness check —
    # makes the failure mode visible to reviewers rather than only
    # to the import system. Also covers the case where a new
    # ChangeKind ships without a rationale entry (would crash at
    # import, so the test itself catches the regression).
    from pgrls.diff.formatters import (
        _EXPECTED_RATIONALE_KEYS,
        _RATIONALE_BY_KIND_AND_CLASSIFICATION,
    )

    assert set(_RATIONALE_BY_KIND_AND_CLASSIFICATION) == _EXPECTED_RATIONALE_KEYS

    # Each rationale is non-empty and ends with a period — the
    # paragraph reads as a complete sentence.
    for key, text in _RATIONALE_BY_KIND_AND_CLASSIFICATION.items():
        assert text, f"Empty rationale for {key!r}"
        assert text.rstrip().endswith("."), (
            f"Rationale for {key!r} doesn't end with a period: "
            f"{text!r}"
        )


def test_every_change_kind_has_marker_classification():
    # Exhaustive contract: every ChangeKind value lands in one of
    # _ADD_KINDS / _DROP_KINDS / _MOD_KINDS / _STATE_KINDS, so the
    # formatter never raises "unknown ChangeKind" at runtime. This
    # mirrors the import-time check in formatters.py — duplicating
    # it as a test makes the failure mode visible to reviewers
    # rather than only to the import system.
    from pgrls.diff.formatters import (
        _ADD_KINDS,
        _DROP_KINDS,
        _MOD_KINDS,
        _STATE_KINDS,
    )

    all_kinds = set(ChangeKind)
    classified = _ADD_KINDS | _DROP_KINDS | _MOD_KINDS | _STATE_KINDS
    missing = all_kinds - classified
    assert missing == set(), (
        "ChangeKind member(s) not classified by the formatter: "
        f"{sorted(k.name for k in missing)}"
    )

    # Each kind belongs to exactly one set (no overlap that would
    # make _marker's order-dependent if-cascade ambiguous).
    for kind in all_kinds:
        memberships = sum(
            1
            for s in (_ADD_KINDS, _DROP_KINDS, _MOD_KINDS, _STATE_KINDS)
            if kind in s
        )
        assert memberships == 1, (
            f"ChangeKind.{kind.name} appears in {memberships} marker "
            "sets; should appear in exactly one."
        )


def test_policy_renamed_renders_tilde_marker():
    # POLICY_RENAMED is in the ChangeKind enum but no v0.2 detection
    # rule emits it (rename detection deferred to v0.3). The formatter
    # still has to handle it without crashing — this test pins the
    # contract by constructing a Change directly.
    changes = [
        _change(
            ChangeKind.POLICY_RENAMED,
            "safe",
            location="public.t.new_name",
            message="Policy renamed from old_name to new_name.",
        )
    ]
    result = format_diff_text(changes)
    lines = result.split("\n")
    assert lines[0] == "~ public.t.new_name"
    assert "policy renamed" in lines[1]
    assert lines[2].startswith("  [SAFE]")


# ---------------------------------------------------------------------------
# JSON formatter (format_diff_json)
# ---------------------------------------------------------------------------

import json as _json  # noqa: E402 — stdlib, after project imports
from pgrls.diff.formatters import format_diff_json, format_diff_sarif, _change_to_violation  # noqa: E402


def test_format_diff_json_returns_valid_json():
    changes = [
        _change(ChangeKind.USING_TIGHTENED, "safe", location="public.t.pol",
                message="USING tightened.")
    ]
    result = format_diff_json(changes)
    # Must parse without raising
    parsed = _json.loads(result)
    assert isinstance(parsed, dict)


def test_format_diff_json_rule_id_matches_change_kind_value():
    changes = [
        _change(ChangeKind.USING_TIGHTENED, "safe", location="public.t.pol",
                message="USING tightened.")
    ]
    parsed = _json.loads(format_diff_json(changes))
    first = parsed["violations"][0]
    assert first["rule_id"] == "DIFF_USING_TIGHTENED"


def test_format_diff_json_severity_mapping_exhaustive():
    # One Change per classification → verify each maps to the right severity.
    changes = [
        _change(ChangeKind.TABLE_ADDED_WITH_RLS, "safe", location="public.a",
                message="safe msg."),
        _change(ChangeKind.TABLE_DROPPED, "breaking", location="public.b",
                message="breaking msg."),
        _change(ChangeKind.GRANT_ADDED, "requires_review", location="public.c.r",
                message="requires_review msg."),
        _change(ChangeKind.USING_LOOSENED, "dangerous", location="public.d.pol",
                message="dangerous msg.", before_sql="a=1", after_sql="a=2"),
    ]
    parsed = _json.loads(format_diff_json(changes))
    violations = parsed["violations"]
    # Build {location: severity} map for easy lookup
    by_loc = {v["location"]: v["severity"] for v in violations}
    assert by_loc["public.a"] == "info"
    assert by_loc["public.b"] == "warning"
    assert by_loc["public.c.r"] == "warning"
    assert by_loc["public.d.pol"] == "error"


def test_format_diff_json_carries_raw_classification():
    # R12 #8: breaking and requires_review both project to
    # `severity: warning`, so the JSON must also carry the raw 4-way
    # `classification` key — otherwise a CI consumer can't split "block
    # on breaking" from "warn on requires_review" from the JSON alone.
    changes = [
        _change(ChangeKind.TABLE_DROPPED, "breaking", location="public.b",
                message="breaking msg."),
        _change(ChangeKind.GRANT_ADDED, "requires_review", location="public.c.r",
                message="requires_review msg."),
    ]
    parsed = _json.loads(format_diff_json(changes))
    by_loc = {v["location"]: v for v in parsed["violations"]}
    assert by_loc["public.b"]["severity"] == "warning"
    assert by_loc["public.b"]["classification"] == "breaking"
    assert by_loc["public.c.r"]["severity"] == "warning"
    assert by_loc["public.c.r"]["classification"] == "requires_review"


def test_format_diff_sarif_carries_raw_classification():
    # Same on the SARIF side — via the standard result.properties bag.
    changes = [
        _change(ChangeKind.TABLE_DROPPED, "breaking", location="public.b",
                message="breaking msg."),
    ]
    parsed = _json.loads(format_diff_sarif(changes))
    result = parsed["runs"][0]["results"][0]
    assert result["properties"]["classification"] == "breaking"


def test_lint_violation_json_omits_classification_key():
    # Additive: a plain lint Violation (no classification) must keep the
    # historical shape — the key appears only on diff output.
    from pgrls.formatters import format_violations
    from pgrls.violations import Violation

    v = Violation(
        rule_id="SEC001", severity="error", title="t",
        message="m", location="public.t",
    )
    parsed = _json.loads(format_violations([v], format="json"))
    assert "classification" not in parsed["violations"][0]


def test_format_diff_json_empty_changes_produces_valid_empty_object():
    result = format_diff_json([])
    parsed = _json.loads(result)
    assert parsed["violations"] == []
    assert "summary" in parsed
    assert parsed["summary"]["total"] == 0


def test_format_diff_json_is_byte_stable():
    changes = [
        _change(ChangeKind.USING_TIGHTENED, "safe", location="public.t.pol",
                message="USING tightened."),
        _change(ChangeKind.TABLE_DROPPED, "breaking", location="public.t",
                message="Table dropped."),
    ]
    result1 = format_diff_json(changes)
    result2 = format_diff_json(changes)
    assert result1 == result2


# ---------------------------------------------------------------------------
# SARIF formatter (format_diff_sarif)
# ---------------------------------------------------------------------------


def test_format_diff_sarif_returns_valid_json():
    changes = [
        _change(ChangeKind.USING_TIGHTENED, "safe", location="public.t.pol",
                message="USING tightened.")
    ]
    result = format_diff_sarif(changes)
    parsed = _json.loads(result)
    # Top-level SARIF shape
    assert "$schema" in parsed
    assert parsed["version"] == "2.1.0"
    assert "runs" in parsed


def test_format_diff_sarif_empty_run_is_valid():
    result = format_diff_sarif([])
    parsed = _json.loads(result)
    assert "runs" in parsed
    assert len(parsed["runs"]) == 1
    assert parsed["runs"][0]["results"] == []


def test_format_diff_sarif_rule_id_matches_change_kind_value():
    changes = [
        _change(ChangeKind.USING_TIGHTENED, "safe", location="public.t.pol",
                message="USING tightened.")
    ]
    parsed = _json.loads(format_diff_sarif(changes))
    first_result = parsed["runs"][0]["results"][0]
    assert first_result["ruleId"] == "DIFF_USING_TIGHTENED"


# ---------------------------------------------------------------------------
# _change_to_violation projection helper
# ---------------------------------------------------------------------------


def test_change_to_violation_title_humanizes_kind_name():
    change = _change(ChangeKind.USING_TIGHTENED, "safe", location="public.t.pol",
                     message="USING tightened.")
    v = _change_to_violation(change)
    assert v.title == "Using Tightened"


@pytest.mark.parametrize(
    "kind, expected_title",
    [
        # Single concept, two words.
        (ChangeKind.USING_TIGHTENED, "Using Tightened"),
        # Four-word kind to cover deeper humanization.
        (ChangeKind.WITH_CHECK_REQUIRES_REVIEW, "With Check Requires Review"),
        # Acronym-bearing kinds: v0.2.1 added a tight allowlist
        # (`_TITLE_ACRONYMS = frozenset({"RLS"})`) so the RLS
        # token survives humanization in its uppercase form
        # rather than being crushed by str.title() to `Rls`.
        (ChangeKind.GRANT_PUBLIC_NO_RLS, "Grant Public No RLS"),
        (ChangeKind.RLS_FLIPPED, "RLS Flipped"),
        (ChangeKind.FORCE_RLS_FLIPPED, "Force RLS Flipped"),
        # Single-component shape from the policy-shape family.
        (ChangeKind.PERMISSIVE_FLAG_TIGHTENED, "Permissive Flag Tightened"),
    ],
)
def test_change_to_violation_title_humanization_table(
    kind: ChangeKind, expected_title: str
) -> None:
    change = _change(kind, "safe", location="public.t", message="m")
    assert _change_to_violation(change).title == expected_title


def test_change_to_violation_passes_through_location_and_message():
    # Pin the full projection so a future refactor that, e.g.,
    # normalizes locations through a helper surfaces here. The
    # title-humanization tests above only assert v.title.
    change = _change(
        ChangeKind.USING_LOOSENED,
        "dangerous",
        location="public.invoices.tenant_isolation",
        message=(
            "Policy public.invoices.tenant_isolation USING predicate "
            "loosened (disjunct added) — broader row set."
        ),
    )
    v = _change_to_violation(change)
    assert v.location == change.location
    assert v.message == change.message
    assert v.rule_id == "DIFF_USING_LOOSENED"
    assert v.severity == "error"


# ---------------------------------------------------------------------------
# Hostile-input hardening (operator-controlled identifiers)
# ---------------------------------------------------------------------------


def test_text_location_with_newline_renders_single_line() -> None:
    # `Change.location` is built from `pg_catalog` introspection
    # of identifiers, which can legally contain `\n` inside a
    # quoted Postgres identifier (`"weird\nname"`). Without
    # `safe_location` escaping, the diff stanza header splits into
    # two lines that a `^- (\S+)$` CI grep can't distinguish from
    # a legitimate second stanza. Mirrors the v0.5.10 lint-text
    # hardening.
    change = _change(
        kind=ChangeKind.TABLE_DROPPED,
        classification="breaking",
        location="public.evil\nINJECTED",
        message="m",
    )
    result = format_diff_text([change])
    # Locate the stanza header. It must be exactly one line.
    header_lines = [ln for ln in result.splitlines() if ln.startswith("- ")]
    assert len(header_lines) == 1
    # The escape representation is visible in the cell.
    assert "evil\\nINJECTED" in header_lines[0]
    # No bare newline leaked.
    assert "evil\nINJECTED" not in result


def test_text_location_with_carriage_return_escaped() -> None:
    change = _change(
        kind=ChangeKind.POLICY_ADDED_PERMISSIVE,
        classification="dangerous",
        location="public.a\rhidden",
        message="m",
    )
    result = format_diff_text([change])
    assert "\\r" in result
    # The raw CR is gone.
    assert "\rhidden" not in result


def test_text_location_with_tab_escaped() -> None:
    change = _change(
        kind=ChangeKind.RLS_FLIPPED,
        classification="requires_review",
        location="public.a\tcol",
        message="m",
    )
    result = format_diff_text([change])
    # RLS_FLIPPED → `!` marker. Header line carries the escape,
    # not a raw tab.
    header_lines = [ln for ln in result.splitlines() if ln.startswith("! ")]
    assert len(header_lines) == 1
    assert "public.a\\tcol" in header_lines[0]
    assert "\t" not in header_lines[0]


def test_text_location_zero_width_only_uses_sentinel() -> None:
    # A location composed entirely of zero-width formatting chars
    # (e.g. ZWSP + ZWNJ) collapses to "" after `safe_location`
    # drops them. Surface the `(empty-or-zero-width)` sentinel
    # instead of leaving the marker line with a bare trailing
    # space — operators reading the diff need to know there WAS
    # something there.
    change = _change(
        kind=ChangeKind.TABLE_DROPPED,
        classification="breaking",
        location="\u200b\u200c",
        message="m",
    )
    result = format_diff_text([change])
    assert "(empty-or-zero-width)" in result
    # And the zero-width chars are gone.
    assert "\u200b" not in result
    assert "\u200c" not in result


def test_text_location_well_formed_passes_through_unchanged() -> None:
    # Fast-path regression: a well-formed location renders
    # byte-identical to pre-hardening output (no perf hit on
    # the common case).
    change = _change(
        kind=ChangeKind.TABLE_DROPPED,
        classification="breaking",
        location="public.invoices",
        message="m",
    )
    result = format_diff_text([change])
    assert "- public.invoices" in result
    # No escape chars introduced.
    header = [ln for ln in result.splitlines() if ln.startswith("- ")][0]
    assert "\\" not in header


# ---------------------------------------------------------------------------
# Markdown formatter (v0.6.18)
# ---------------------------------------------------------------------------


from pgrls.diff.formatters import format_diff_markdown  # noqa: E402


def test_markdown_empty_changes_renders_no_changes_line() -> None:
    # Empty input matches the text formatter's clean output verbatim
    # so a one-liner CI script that greps for the string works
    # against either format. Trailing newline is the conventional
    # final-character contract every renderer here honours.
    result = format_diff_markdown([])
    assert result == "pgrls diff: no changes.\n"


def test_markdown_emits_h2_header_and_table_skeleton() -> None:
    [c] = [_change(ChangeKind.TABLE_DROPPED, "breaking", message="dropped")]
    result = format_diff_markdown([c])
    assert result.startswith("## pgrls diff\n")
    assert "| Classification | Kind | Object | Summary |" in result
    assert "|---|---|---|---|" in result


def test_markdown_each_classification_renders_distinct_emoji() -> None:
    # All four classifications must be visually distinguishable.
    # The lint markdown uses only 3 emoji (one per severity); diff
    # markdown uses 4 (one per classification) because the
    # classification distinction is the whole point of diff output.
    changes = [
        _change(ChangeKind.TABLE_ADDED_WITH_RLS, "safe", location="public.a"),
        _change(ChangeKind.USING_REQUIRES_REVIEW, "requires_review", location="public.b"),
        _change(ChangeKind.POLICY_DROPPED_PERMISSIVE, "breaking", location="public.c"),
        _change(ChangeKind.GRANT_PUBLIC_NO_RLS, "dangerous", location="public.d"),
    ]
    result = format_diff_markdown(changes)
    # Each classification's row carries its dedicated emoji prefix.
    assert "✅ SAFE" in result
    assert "⚠️ REQUIRES REVIEW" in result
    assert "🚦 BREAKING" in result
    assert "❌ DANGEROUS" in result


def test_markdown_kind_name_is_humanized() -> None:
    # ChangeKind enum members are SCREAMING_SNAKE; the rendered Kind
    # column is title-cased with whitespace separators. The acronym
    # exception RLS stays uppercase (`Rls Flipped` would crush it
    # to "Rls"; we want "RLS Flipped").
    changes = [
        _change(ChangeKind.USING_TIGHTENED, "safe"),
        _change(ChangeKind.RLS_FLIPPED, "breaking"),
    ]
    result = format_diff_markdown(changes)
    assert "| Using Tightened |" in result
    assert "| RLS Flipped |" in result


def test_markdown_object_cell_uses_gfm_inline_code() -> None:
    # Object identifiers go through `gfm_inline_code` so backticks
    # in the identifier don't close the code span prematurely.
    result = format_diff_markdown([
        _change(ChangeKind.TABLE_DROPPED, "breaking",
                location="weird`name"),
    ])
    # Wrapper must be longer than the inner backtick run; space
    # padding lets the content start/end with a backtick.
    assert "`` weird`name ``" in result


def test_markdown_object_cell_handles_none_location() -> None:
    result = format_diff_markdown([
        _change(ChangeKind.TABLE_DROPPED, "breaking", location=""),
    ])
    # Empty location falls back to the shared sentinel (same
    # wording the text/markdown lint formatters use).
    assert f"`{EMPTY_OR_ZERO_WIDTH_SENTINEL}`" in result


def test_markdown_object_cell_handles_pipe_in_location() -> None:
    # `|` would terminate the GFM table cell; escape to `\|`.
    result = format_diff_markdown([
        _change(ChangeKind.TABLE_DROPPED, "breaking",
                location="public.weird|name"),
    ])
    # Inside an inline-code span pipes still need escaping for the
    # GFM table parser (it scans for unescaped `|` before parsing
    # inline content).
    assert r"`public.weird\|name`" in result


def test_markdown_summary_cell_escapes_pipe() -> None:
    result = format_diff_markdown([
        _change(ChangeKind.USING_TIGHTENED, "safe",
                message="A | B in message"),
    ])
    assert r"A \| B in message" in result


def test_markdown_summary_cell_collapses_newlines_to_br() -> None:
    # Multi-line diff messages exist (the differ produces them for
    # some kinds). Without escaping, `\n` ends the row early in GFM.
    result = format_diff_markdown([
        _change(ChangeKind.USING_TIGHTENED, "safe",
                message="line one\nline two"),
    ])
    assert "line one<br>line two" in result


def test_markdown_trailing_summary_matches_text_phrasing() -> None:
    # The summary wording mirrors `_trailing_summary`'s line for
    # `pgrls diff --format text` so a CI script that greps both
    # formats sees identical breakdown text. The markdown variant
    # wraps it in `**…**` for emphasis but the inner text matches.
    changes = [
        _change(ChangeKind.TABLE_ADDED_WITH_RLS, "safe", location="a"),
        _change(ChangeKind.TABLE_DROPPED, "breaking", location="b"),
        _change(ChangeKind.GRANT_PUBLIC_NO_RLS, "dangerous", location="c"),
    ]
    result = format_diff_markdown(changes)
    # 3 changes; the breakdown follows _BUCKET_ORDER:
    # dangerous, requires_review, breaking, safe — only non-zero.
    assert "3 changes — 1 dangerous, 1 breaking, 1 safe." in result
    # Wrapped in bold inside markdown.
    assert "**Summary:** 3 changes" in result


def test_markdown_trailing_summary_singular_when_one_change() -> None:
    [c] = [_change(ChangeKind.TABLE_DROPPED, "breaking")]
    result = format_diff_markdown([c])
    # Singular noun agreement matches the text formatter.
    assert "1 change — 1 breaking." in result
    assert "1 changes" not in result


def test_markdown_dispatch_registered_for_cli() -> None:
    # `pgrls diff --format markdown` must reach the new renderer.
    # Pins the wiring without spinning up a live database (the CLI
    # would otherwise need a connection to introspect snapshots).
    from pgrls.diff.formatters import DIFF_SUPPORTED_FORMATS
    assert "markdown" in DIFF_SUPPORTED_FORMATS


# ---------------------------------------------------------------------------
# HTML formatter (v0.6.19)
# ---------------------------------------------------------------------------


from datetime import datetime, timezone, timedelta  # noqa: E402

from pgrls.diff.formatters import format_diff_html  # noqa: E402


_FIXED_GEN = datetime(2026, 5, 27, 16, 0, 0, tzinfo=timezone.utc)


def test_html_empty_changes_renders_no_changes_banner() -> None:
    out = format_diff_html([], generated_at=_FIXED_GEN)
    # Standalone HTML5 document with no external assets.
    assert out.startswith("<!DOCTYPE html>")
    assert "<html lang=\"en\">" in out
    assert "<title>pgrls diff</title>" in out
    assert "<style>" in out
    assert "<link" not in out
    assert "<script" not in out
    # Empty case shows a green "No changes" banner.
    assert "No changes in this diff" in out
    assert "net-good" in out


def test_html_carries_iso_utc_timestamp() -> None:
    out = format_diff_html([], generated_at=_FIXED_GEN)
    assert "2026-05-27T16:00:00Z" in out


def test_html_accepts_injected_generated_at() -> None:
    fixed = datetime(2026, 1, 15, 10, 30, 45, tzinfo=timezone.utc)
    out = format_diff_html([], generated_at=fixed)
    assert "2026-01-15T10:30:45Z" in out


def test_html_rejects_naive_generated_at() -> None:
    # Mirrors report and history HTML — naive datetimes silently
    # become wrong-by-host-timezone audit timestamps. Refuse at
    # the boundary.
    with pytest.raises(ValueError, match="timezone-aware"):
        format_diff_html([], generated_at=datetime(2026, 1, 15, 10, 30))


def test_html_normalizes_non_utc_generated_at_to_utc() -> None:
    cet = timezone(timedelta(hours=1))
    out = format_diff_html(
        [], generated_at=datetime(2026, 1, 15, 11, 30, 45, tzinfo=cet)
    )
    assert "2026-01-15T10:30:45Z" in out  # CET 11:30 → UTC 10:30


def test_html_carries_row_per_change_with_classification_color() -> None:
    changes = [
        _change(ChangeKind.TABLE_ADDED_WITH_RLS, "safe", location="public.a", message="added"),
        _change(ChangeKind.USING_REQUIRES_REVIEW, "requires_review", location="public.b", message="review"),
        _change(ChangeKind.POLICY_DROPPED_PERMISSIVE, "breaking", location="public.c", message="dropped"),
        _change(ChangeKind.GRANT_PUBLIC_NO_RLS, "dangerous", location="public.d", message="grant"),
    ]
    out = format_diff_html(changes, generated_at=_FIXED_GEN)
    # Each row's `<tr class="row-{cls}">` lets downstream CSS
    # target individual classifications.
    assert 'class="row-safe"' in out
    assert 'class="row-requires_review"' in out
    assert 'class="row-breaking"' in out
    assert 'class="row-dangerous"' in out
    # Each row also carries the classification pill chip.
    assert 'class="pill class-safe">✅ SAFE' in out
    assert 'class="pill class-requires_review">⚠️ REQUIRES REVIEW' in out
    assert 'class="pill class-breaking">🚦 BREAKING' in out
    assert 'class="pill class-dangerous">❌ DANGEROUS' in out


def test_html_summary_band_shows_per_classification_chips() -> None:
    changes = [
        _change(ChangeKind.TABLE_ADDED_WITH_RLS, "safe", location="a"),
        _change(ChangeKind.TABLE_DROPPED, "breaking", location="b"),
        _change(ChangeKind.TABLE_DROPPED, "breaking", location="c"),
    ]
    out = format_diff_html(changes, generated_at=_FIXED_GEN)
    # 1 safe + 2 breaking, both chips appear with their counts.
    assert "<strong>1</strong>&nbsp;safe" in out
    assert "<strong>2</strong>&nbsp;breaking" in out
    # No "0 dangerous" noise.
    assert "&nbsp;dangerous" not in out
    assert "&nbsp;requires review" not in out


def test_html_escapes_special_chars_in_location() -> None:
    # Postgres quoted identifiers permit `<`, `>`, `&`, `"`. Without
    # escaping, those would break the page (or worse — inject markup
    # if the HTML is opened from an email attachment).
    [c] = [_change(ChangeKind.TABLE_DROPPED, "breaking",
                   location='weird<name>&"', message="dropped")]
    out = format_diff_html([c], generated_at=_FIXED_GEN)
    assert "weird&lt;name&gt;&amp;&quot;" in out
    # The literal `<name>` must not appear as a tag.
    assert "<name>" not in out


def test_html_escapes_special_chars_in_message() -> None:
    # A future ChangeKind could route SQL into Change.message
    # (today every message is plain English from `_SUMMARY_BY_KIND`,
    # but defence-in-depth here). Operator-supplied SQL like
    # `<script>` inside a quoted predicate fragment must not inject.
    [c] = [_change(ChangeKind.TABLE_DROPPED, "breaking", location="x",
                   message="<script>alert('xss')</script>")]
    out = format_diff_html([c], generated_at=_FIXED_GEN)
    assert "&lt;script&gt;" in out
    assert "<script>" not in out


def test_html_collapses_message_newlines_to_br() -> None:
    [c] = [_change(ChangeKind.USING_TIGHTENED, "safe", location="x",
                   message="line one\nline two")]
    out = format_diff_html([c], generated_at=_FIXED_GEN)
    assert "line one<br>line two" in out


def test_html_is_registered_format() -> None:
    from pgrls.diff.formatters import DIFF_SUPPORTED_FORMATS
    assert "html" in DIFF_SUPPORTED_FORMATS


def test_html_renders_predicate_block_for_using_kinds() -> None:
    # The text formatter shows the before/after SQL for USING_* /
    # WITH_CHECK_* changes (the most useful detail for a reviewer
    # asking "is this migration safe?"). HTML mirrors that as a
    # styled <pre> block beneath the message. Without it, an
    # offline reviewer reading the archive sees "USING tightened"
    # but not what it tightened to.
    [c] = [_change(
        ChangeKind.USING_TIGHTENED, "safe",
        location="public.docs.tenant_scope",
        message="USING tightened",
        before_sql="(true)",
        after_sql='(tenant_id = current_setting("app.t", true))',
    )]
    out = format_diff_html([c], generated_at=_FIXED_GEN)
    assert "tenant_id = current_setting" in out
    assert "pred-plus" in out
    assert "pred-minus" in out
    # No-clause-on-one-side renders the sentinel.
    [c2] = [_change(
        ChangeKind.WITH_CHECK_REQUIRES_REVIEW, "requires_review",
        location="public.t.p",
        message="WITH CHECK changed",
        before_sql=None,
        after_sql="(owner_id = auth.uid())",
    )]
    out2 = format_diff_html([c2], generated_at=_FIXED_GEN)
    assert "(no clause)" in out2
    assert "owner_id = auth.uid()" in out2


def test_html_predicate_block_escapes_sql() -> None:
    # before_sql / after_sql is operator-supplied SQL — must be
    # html.escape-d so SQL operators (`<`, `>`) don't break the
    # layout or inject markup.
    [c] = [_change(
        ChangeKind.USING_TIGHTENED, "safe", location="x",
        message="m",
        before_sql='(a < 5 AND b > 10)',
        after_sql='(a <= 5 AND b >= 10)',
    )]
    out = format_diff_html([c], generated_at=_FIXED_GEN)
    assert "a &lt; 5" in out
    assert "b &gt;= 10" in out
    # Literal `<` / `>` (other than legitimate HTML tags) must not
    # appear in the predicate block.
    pred_start = out.index("pre class=\"predicate\"")
    pred_end = out.index("</pre>", pred_start)
    pred_block = out[pred_start:pred_end]
    # Strip the legitimate <span> open/close tags so we only check
    # the inner text content.
    inner = pred_block.replace("<span", "").replace("</span>", "").replace(
        'class="pred-minus">', "").replace('class="pred-plus">', "")
    assert "<" not in inner.replace("&lt;", "")


# ---------------------------------------------------------------------------
# POLICY_RENAMED rationale exhaustiveness
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "classification", ["safe", "requires_review", "dangerous"]
)
def test_policy_renamed_has_rationale_for_every_emitted_class(classification: str) -> None:
    key = (ChangeKind.POLICY_RENAMED, classification)
    assert key in _EXPECTED_RATIONALE_KEYS
    assert key in _RATIONALE_BY_KIND_AND_CLASSIFICATION
    assert _RATIONALE_BY_KIND_AND_CLASSIFICATION[key]  # non-empty text
