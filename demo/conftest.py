"""Shared fixtures and helpers for demo cases.

`pytest demo/` discovers per-case `cases/NN-*/test_uc<NN>.py` files.
This conftest spins up a session-scoped Postgres testcontainer (or
honours `DATABASE_URL` if set), applies `cases/_shared.sql` (auth
schema and stub functions), then walks every `cases/NN-*/setup.sql`
in numeric order and applies it. Result: one DB shared across all
case tests with every fixture visible.

Helpers (`lint`, `lint_json`, `base_config`, `all_rule_ids`,
`pgrls_toml`) are exposed as fixtures rather than module-level
constants so each case file declares precisely what it needs in the
function signature.
"""
from __future__ import annotations

import json as _json
import os
import re
from collections.abc import Callable, Generator
from pathlib import Path

import psycopg
import pytest
from click.testing import CliRunner
from testcontainers.postgres import PostgresContainer

from pgrls.cli import main
from pgrls.rules import all_rules

DEMO_DIR = Path(__file__).parent
CASES_DIR = DEMO_DIR / "cases"
PGRLS_TOML_PATH = DEMO_DIR / "pgrls.toml"

# Derive from the rule registry so a new rule lands without the
# demo's all-rules tuple drifting from the lint test suite's copy
# (tests/test_cli.py does the same).
_ALL_RULE_IDS = tuple(rule.id for rule in all_rules())

# `_SEC012_ALLOWLIST_BLOCK` is the full per-table allowlist that the
# demo's pgrls.toml uses (see the pgrls.toml comment for the
# rationale — these tables predate SEC012 and are kept as-is to
# avoid rewriting every demo case fixture). Embedding the same
# block here keeps `_BASE_CONFIG`-based tests (uc72 etc.) seeing
# the same SEC012-quiet shape; a future demo overhaul that updates
# the fixtures to use proper PERMISSIVE+RESTRICTIVE pairs will
# delete both.
import tomllib  # noqa: E402

_PGRLS_TOML_CONTENT = (DEMO_DIR / "pgrls.toml").read_text(encoding="utf-8")
_PARSED_TOML = tomllib.loads(_PGRLS_TOML_CONTENT)
_SEC012_ALLOWLIST = _PARSED_TOML.get("lint", {}).get(
    "rules", {}
).get("SEC012", {}).get("allowlist", [])
_SEC012_ALLOWLIST_BLOCK = (
    "[lint.rules.SEC012]\n"
    "allowlist = [\n"
    + "".join(f'    "{t}",\n' for t in _SEC012_ALLOWLIST)
    + "]\n"
)

_BASE_CONFIG = (
    '[database]\nschemas = ["app"]\n'
    # PERF003 is disabled for the demo (see pgrls.toml comment) —
    # the rule fires on every RLS-enabled table that lacks a
    # leading-column index, and the 50+ demo fixtures don't carry
    # indexes. Embedding the same disable here keeps
    # `_BASE_CONFIG`-based tests (uc72 etc.) seeing the same
    # ruleset the demo's pgrls.toml runs with.
    '[lint]\ndisable = ["PERF003"]\n'
    '[lint.rules.SEC001]\nallowlist = ["app.countries"]\n'
    # Mirror pgrls.toml's SEC022 allowlist: `app.gen_cols` (uc46)
    # is an intentionally read-only table, so SEC022 is allowlisted
    # there. Embedding it keeps `_BASE_CONFIG`-based tests (uc72)
    # seeing the same rule set as the pgrls.toml-based ones.
    '[lint.rules.SEC022]\nallowlist = ["app.gen_cols"]\n'
    + _SEC012_ALLOWLIST_BLOCK
)


def _apply_all_setup(url: str) -> None:
    # Explicit UTF-8 — on Windows, default `read_text()` uses
    # `locale.getpreferredencoding()` which can be cp1252; a
    # non-ASCII byte in any fixture would blow up here.
    sqls = [(CASES_DIR / "_shared.sql").read_text(encoding="utf-8")]
    case_dirs = sorted(
        d
        for d in CASES_DIR.iterdir()
        if d.is_dir() and re.match(r"^\d", d.name)
    )
    for case_dir in case_dirs:
        case_sql = case_dir / "setup.sql"
        if case_sql.exists():
            sqls.append(case_sql.read_text(encoding="utf-8"))
    full = "\n".join(sqls)
    with psycopg.connect(url, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(full)


@pytest.fixture(scope="session")
def demo_db() -> Generator[str, None, None]:
    existing = os.environ.get("DATABASE_URL")
    if existing:
        _apply_all_setup(existing)
        yield existing
        return
    with PostgresContainer(
        "postgres:16-alpine",
        username="demo",
        password="demo",
        dbname="demo",
    ) as pg:
        url = pg.get_connection_url(driver=None)
        _apply_all_setup(url)
        yield url


@pytest.fixture(scope="session")
def lint_output(demo_db: str) -> str:
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "lint",
            "--database-url", demo_db,
            "--config", str(PGRLS_TOML_PATH),
        ],
        env={"DATABASE_URL": demo_db},
    )
    return result.output


@pytest.fixture(scope="session")
def lint(demo_db: str) -> Callable[..., str]:
    def _run(
        *,
        config: Path | None = None,
        extra_args: tuple[str, ...] = (),
    ) -> str:
        runner = CliRunner()
        args = ["lint", "--database-url", demo_db, *extra_args]
        if config is not None:
            args.extend(["--config", str(config)])
        return runner.invoke(
            main, args, env={"DATABASE_URL": demo_db}
        ).output

    return _run


@pytest.fixture(scope="session")
def lint_json(demo_db: str, lint: Callable[..., str]) -> Callable[..., dict]:
    def _run(
        *,
        config: Path | None = None,
        extra_args: tuple[str, ...] = (),
    ) -> dict:
        text = lint(
            config=config or PGRLS_TOML_PATH,
            extra_args=("--format", "json", *extra_args),
        )
        return _json.loads(text)

    return _run


@pytest.fixture(scope="session")
def base_config() -> str:
    return _BASE_CONFIG


@pytest.fixture(scope="session")
def all_rule_ids() -> tuple[str, ...]:
    return _ALL_RULE_IDS


@pytest.fixture(scope="session")
def pgrls_toml() -> Path:
    return PGRLS_TOML_PATH
