"""Pin the implicit constraints `tests/conftest.py:apply_sql` relies on.

The naive `;` split in `apply_sql` is fine "for our test fixtures"
(per the conftest comment) but the constraint — no PL/pgSQL `$$`
bodies, no `;` inside `--` comments — is implicit. As the suite
grows, a developer copy-pasting from the demo (which uses libpq's
multi-statement execute path and is constraint-free) would silently
introduce a fixture that misparses.

This test scans every fixture file and rejects the two shapes the
naive split can't handle, so a future fixture violating the
constraint fails at suite startup with a clear message rather than
at runtime with a confusing syntax error.
"""
from __future__ import annotations

from pathlib import Path

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_fixtures_have_no_pl_pgsql_bodies() -> None:
    # `$$ ... $$` (PL/pgSQL function body, anonymous DO block) embeds
    # `;` inside the body. The naive split in `apply_sql` would carve
    # the body into half-statements and execute fragments individually.
    for fixture in sorted(FIXTURES_DIR.glob("*.sql")):
        text = fixture.read_text(encoding="utf-8")
        assert "$$" not in text, (
            f"{fixture.name}: contains `$$` (PL/pgSQL body). The naive "
            "`;` split in `tests/conftest.py:apply_sql` cannot handle "
            "embedded statements. Either rewrite without the body or "
            "switch the apply path to multi-statement execute."
        )


def test_fixtures_have_no_semicolons_inside_line_comments() -> None:
    # `-- comment with ; in it` would cause the naive split to break
    # the comment in two and try to execute the remainder as SQL.
    for fixture in sorted(FIXTURES_DIR.glob("*.sql")):
        for lineno, line in enumerate(
            fixture.read_text(encoding="utf-8").splitlines(), 1
        ):
            comment_idx = line.find("--")
            if comment_idx >= 0 and ";" in line[comment_idx:]:
                raise AssertionError(
                    f"{fixture.name}:{lineno}: ';' inside '--' comment "
                    f"breaks the naive split in apply_sql. Line: "
                    f"{line.rstrip()!r}"
                )
