"""Tests for pgrls.diff.formatters (text + JSON + SARIF)."""
from __future__ import annotations

import pytest

from pgrls.diff.differ import Change, ChangeKind
from pgrls.diff.formatters import format_diff_text


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
