"""Regression gate for the adjudicated precision corpus.

Re-runs the corpus measurement (see :mod:`corpus.harness`) and fails if
any case drifts from its label:

* an **undocumented false positive** — a rule fired on a case that lists
  it as neither expected nor a recorded ``known_fp``; or
* a **false negative** — an ``expect``-ed rule that did not fire.

This keeps ``docs/PRECISION.md`` honest: a rule change that introduces a
false positive on a corpus negative (or drops a true positive) breaks CI
here, not silently in a published number.
"""
from __future__ import annotations

from corpus.harness import CaseResult, Summary


def test_no_undocumented_false_positives(corpus_results: list[CaseResult]) -> None:
    offenders = {
        r.case.name: sorted(r.false_positives)
        for r in corpus_results
        if r.false_positives
    }
    assert not offenders, (
        "Undocumented false positives — a rule fired on a case that labels "
        "it neither in `expect` nor `known_fp`. Either the rule regressed "
        f"(fix it) or the label is wrong (adjudicate it): {offenders}"
    )


def test_no_false_negatives(corpus_results: list[CaseResult]) -> None:
    offenders = {
        r.case.name: sorted(r.false_negatives)
        for r in corpus_results
        if r.false_negatives
    }
    assert not offenders, (
        "False negatives — an expected rule did not fire. A detector "
        f"regressed or the case no longer triggers it: {offenders}"
    )


def test_corpus_is_nontrivial(corpus_results: list[CaseResult]) -> None:
    # Guard against an empty/degenerate corpus silently passing the gate.
    assert len(corpus_results) >= 15
    kinds = {r.case.kind for r in corpus_results}
    assert "positive" in kinds and "negative" in kinds


def test_corpus_exercises_real_detection(corpus_summary: Summary) -> None:
    # The precision number is only meaningful if rules actually fire on
    # the positives (true positives) and the negatives stress them.
    assert corpus_summary.tp_total > 0
    assert corpus_summary.n_negative > 0
