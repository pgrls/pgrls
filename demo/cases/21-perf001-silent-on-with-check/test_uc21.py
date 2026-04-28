"""Use case 21: PERF001 silent on WITH CHECK — pin USING-only contract."""
from __future__ import annotations


def test_uc21_perf001_silent_when_auth_only_in_with_check(
    lint_output: str,
) -> None:
    # Pins the USING-only contract: `auth.uid()` in WITH CHECK
    # alone must NOT trigger PERF001. A future regression
    # extending the rule to WITH CHECK breaks this test loudly.
    assert (
        "PERF001  app.audit_inserts.insert_self_only" not in lint_output
    )


