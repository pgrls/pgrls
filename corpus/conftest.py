"""Session-scoped corpus measurement for the precision regression gate.

Spins one throwaway Postgres (or honours ``PGRLS_TEST_DATABASE_URL`` /
``DATABASE_URL``), measures every case once, and shares the result across
the test module.
"""
from __future__ import annotations

import pytest

from corpus.harness import CaseResult, Summary, corpus_db, measure, summarize


@pytest.fixture(scope="session")
def corpus_results() -> list[CaseResult]:
    with corpus_db() as url:
        return measure(url)


@pytest.fixture(scope="session")
def corpus_summary(corpus_results: list[CaseResult]) -> Summary:
    return summarize(corpus_results)
