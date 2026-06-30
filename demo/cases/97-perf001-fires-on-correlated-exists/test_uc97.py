"""Use case 97: PERF001 fires on an auth call nested in a correlated subquery."""
from __future__ import annotations


def test_uc97_perf001_fires_on_correlated_nested_auth(
    lint_output: str,
) -> None:
    # A bare auth.uid() inside a CORRELATED EXISTS (the subquery
    # references the outer row) re-evaluates once per outer row scanned,
    # so PERF001 must fire — the (SELECT …) wrap collapses it to one
    # InitPlan call, exactly like a top-level call. Verifies the
    # introspection path: the stored policy deparses with the outer
    # reference qualified, which subselect_is_correlated keys on.
    assert (
        "PERF001  app.uc97_documents.uc97_same_folder_read" in lint_output
    )


def test_uc97_perf001_silent_when_correlated_call_wrapped(
    lint_output: str,
) -> None:
    # The companion policy wraps the same auth.uid() in `(SELECT …)`, so
    # PERF001 stays silent on it — the descent into the correlated
    # subselect finds nothing unwrapped to flag.
    assert (
        "PERF001  app.uc97_documents.uc97_owner_all" not in lint_output
    )
