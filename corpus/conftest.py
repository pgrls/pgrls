"""Session-scoped corpus measurement for the precision regression gate.

Spins one throwaway Postgres (or honours ``PGRLS_TEST_DATABASE_URL`` /
``DATABASE_URL``), measures every case once, and shares the result across
the test module.
"""
from __future__ import annotations

import pytest

from corpus.harness import CaseResult, Summary, corpus_db, measure, summarize
from corpus.verdicts import VerdictResult, measure_verdicts


@pytest.fixture(scope="session")
def corpus_results() -> list[CaseResult]:
    with corpus_db() as url:
        return measure(url)


@pytest.fixture(scope="session")
def corpus_summary(corpus_results: list[CaseResult]) -> Summary:
    return summarize(corpus_results)


@pytest.fixture(scope="session")
def verdict_results() -> list[VerdictResult]:
    """The `pgrls verify` verdict corpus, measured once per session.

    Takes its own database rather than sharing `corpus_results`': that one
    lints, this one proves, and the verdict cases need roles and SET ROLE
    ownership the lint prelude does not set up.
    """
    with corpus_db() as url:
        return measure_verdicts(url)
