"""Use case 21: PERF001 fires on an unwrapped auth call in WITH CHECK."""
from __future__ import annotations


def test_uc21_perf001_fires_when_auth_only_in_with_check(
    lint_output: str,
) -> None:
    # A bare `auth.uid()` in WITH CHECK is re-evaluated once per written
    # row, so PERF001 must fire on it — exactly like USING. (Verified
    # empirically: a 1000-row INSERT calls it 1000x; the (SELECT …) wrap,
    # once.)
    assert (
        "PERF001  app.audit_inserts.insert_self_only" in lint_output
    )


def test_uc21_perf001_silent_when_with_check_wrapped(
    lint_output: str,
) -> None:
    # The PERMISSIVE policy wraps auth.uid() in both clauses, so the wrap
    # clears the finding on the write side too — PERF001 stays silent.
    assert (
        "PERF001  app.audit_inserts.audit_inserts_authenticated_access"
        not in lint_output
    )
