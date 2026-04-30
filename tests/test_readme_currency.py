"""Pin user-visible README claims against the codebase.

A prior review caught the README still describing 2-tier exit
codes after the codebase had added a third tier (tool-error),
plus a stale PG version disclaimer. These tests guard against
that class of drift — README is the first contact for any
potential user, so claims that no longer match reality are
credibility issues.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
README = REPO_ROOT / "README.md"


@pytest.fixture(scope="module")
def readme_text() -> str:
    return README.read_text(encoding="utf-8")


def test_readme_documents_all_three_exit_codes(readme_text: str) -> None:
    # Three-tier exit codes: 0 clean, 1 findings, 2 tool errors
    # (config / network / fixer SQL failure). The README must
    # cover all three so CI engineers know they can route alerts
    # differently — that's the entire point of having a third code.
    for marker in ("`0`", "`1`", "`2`"):
        assert marker in readme_text, (
            f"README missing exit-code documentation for {marker}. "
            "The tool-error tier (2) must appear alongside the "
            "existing clean (0) and findings (1) descriptions."
        )


def test_readme_rule_table_lists_every_registered_rule(
    readme_text: str,
) -> None:
    # Mechanical drift catch: when a future rule lands in
    # `default_registry()` and the README's hand-maintained table
    # is forgotten, this test fails immediately. Better than
    # shipping a release whose docs omit the rule.
    from pgrls.rules import all_rules

    registered_ids = {rule.id for rule in all_rules()}
    # Find every `SEC###` / `PERF###` / `HYG###` / `VIEW###` token in
    # the README.
    documented_ids = set(
        re.findall(r"\b((?:SEC|PERF|HYG|VIEW)\d{3})\b", readme_text)
    )
    missing = registered_ids - documented_ids
    assert not missing, (
        f"README does not mention rule(s) {sorted(missing)}; the "
        "rule table at the `## Rules` section needs a row per "
        "registered rule."
    )


def test_readme_pg_floor_matches_ci_matrix(readme_text: str) -> None:
    # The CI matrix in `.github/workflows/test.yml` is the
    # authoritative test of the supported PG version range.
    # README must declare a floor at-or-below the matrix minimum.
    workflow = (REPO_ROOT / ".github/workflows/test.yml").read_text(
        encoding="utf-8"
    )
    matrix_majors = sorted(
        {int(m) for m in re.findall(r'pg:\s*\[([^\]]+)\]', workflow)[0]
            .replace('"', '').replace("'", '').split(",")
            if m.strip().isdigit()},
    )
    matrix_min = matrix_majors[0]
    # README's floor mention: "Postgres 10+" / "Postgres 12+"
    floor_match = re.search(r"Postgres (\d+)\+", readme_text)
    assert floor_match is not None, (
        "README must declare a Postgres floor like 'Postgres 10+'."
    )
    declared_floor = int(floor_match.group(1))
    assert declared_floor <= matrix_min, (
        f"README claims PG{declared_floor}+ but the CI matrix only "
        f"tests PG{matrix_min}+. Either lower the README floor or "
        "extend the matrix."
    )
