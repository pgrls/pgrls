"""Use case 69: json summary matches violation body invariant."""
from __future__ import annotations


def test_uc69_json_summary_matches_violation_body_invariant(
    demo_db: str,
    lint_json,
) -> None:
    # `summary.total == len(violations)` and per-severity counts
    # match the actual violation list. This is the invariant CI
    # dashboards rely on. A regression that drifts the summary
    # away from the body fails this loudly.
    parsed = lint_json()
    violations = parsed["violations"]
    summary = parsed["summary"]

    assert summary["total"] == len(violations)
    assert summary["errors"] == sum(
        1 for v in violations if v["severity"] == "error"
    )
    assert summary["warnings"] == sum(
        1 for v in violations if v["severity"] == "warning"
    )
    assert summary["infos"] == sum(
        1 for v in violations if v["severity"] == "info"
    )


