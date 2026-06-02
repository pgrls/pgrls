"""Use case 89: semantic anonymous-read leak — SEC038."""
from __future__ import annotations


def test_uc89_anonymous_read_semantic_fires_sec038(lint_output: str) -> None:
    # SEC038 (Z3-backed) catches the NOT-wrapped inverted-auth disjunct
    # that SEC004's syntactic matcher misses.
    assert "SEC038  app.anon_reports.anon_reports_leaky_read\n" in lint_output


def test_uc89_sec004_does_not_fire_on_not_wrapped_shape(lint_output: str) -> None:
    # The whole point of the semantic rule: SEC004 stays silent on the
    # NOT-wrapped form, so SEC038 is the only detector that sees it.
    assert "SEC004  app.anon_reports.anon_reports_leaky_read\n" not in lint_output
