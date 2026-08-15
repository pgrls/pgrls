"""The CI gate for the `pgrls verify` verdict corpus.

`test_corpus.py` gates which *lint rules* fire. This gates what the **prover
concludes** — the layer where two exploitable false clears reached 0.52.0
unnoticed. A change that flips any adjudicated verdict fails here.
"""
from __future__ import annotations

import pytest

from corpus.verdicts import (
    VERDICT_CASES,
    VerdictResult,
    describe,
    failures,
)


def test_every_verdict_matches(verdict_results: list[VerdictResult]) -> None:
    """Every adjudicated verdict still holds.

    Reported all-at-once rather than failing on the first case, so a change
    that shifts several verdicts shows its full blast radius in one run.
    """
    bad = failures(verdict_results)
    assert not bad, "verdict regressions:\n\n" + "\n\n".join(
        describe(r) for r in bad
    )


def test_corpus_covers_every_mode(verdict_results: list[VerdictResult]) -> None:
    """Each `--mode` the CLI exposes has at least one adjudicated case.

    Guards the gap this corpus was built to close: a mode with no verdict case
    is a mode whose regressions are invisible here, which is exactly the state
    `write` and `anon` were in when their false clears shipped.
    """
    covered = {r.case.mode for r in verdict_results}
    expected = {"anon", "cross-tenant", "write", "escalation", "reachability"}
    assert expected <= covered, f"modes with no verdict case: {expected - covered}"


def test_corpus_pins_both_directions(verdict_results: list[VerdictResult]) -> None:
    """The corpus asserts isolation as well as leaks.

    A corpus of leaks alone would pass for a prover that called everything a
    leak; a corpus of clean schemas alone would pass for one that proved
    everything isolated. Both directions must be represented.
    """
    verdicts = {v for r in verdict_results for _, v in r.case.expect}
    assert "leak" in verdicts, "no case pins a leak"
    assert "isolated" in verdicts, "no case pins isolation"
    assert any(
        not r.case.expect for r in verdict_results
    ), "no case pins the empty (no-finding) result"


@pytest.mark.parametrize("case", VERDICT_CASES, ids=lambda c: c.name)
def test_every_case_is_adjudicated(case: object) -> None:
    """Each case carries a note explaining *why* its verdict is correct.

    The corpus is only worth its weight if the expectations were adjudicated
    against real Postgres behaviour rather than pinned from whatever the
    prover printed that day. An unexplained case cannot be re-checked by the
    next reader, so require the reasoning inline.
    """
    assert case.note.strip(), f"{case.name} has no adjudication note"  # type: ignore[attr-defined]
