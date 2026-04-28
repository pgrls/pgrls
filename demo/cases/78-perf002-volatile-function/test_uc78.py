"""Use case 78: PERF002 — VOLATILE function in policy."""
from __future__ import annotations


def test_uc78_perf002_fires_on_random_in_using(
    lint_output: str,
) -> None:
    assert (
        "PERF002  app.volatile_predicate.random_sampling\n"
        in lint_output
    )
    # SEC005 also fires (the policy has no own-column ref) — pin
    # both so the cross-fire stays visible.
    assert (
        "SEC005  app.volatile_predicate.random_sampling\n"
        in lint_output
    )
