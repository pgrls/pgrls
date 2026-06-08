"""Unit tests for migration-layout detection and ordering (no Docker)."""
from __future__ import annotations

from pathlib import Path

import pytest

from pgrls.migrations_layout import (
    LayoutError,
    detect_layout,
    resolve_plan,
)


def _touch(path: Path, text: str = "-- sql\n") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


# --- detect_layout ---------------------------------------------------------


def test_detect_single_sql_file(tmp_path: Path) -> None:
    f = _touch(tmp_path / "schema.sql")
    assert detect_layout(f) == "sql"


def test_detect_supabase_project_root(tmp_path: Path) -> None:
    _touch(tmp_path / "config.toml", "# supabase\n")
    _touch(tmp_path / "migrations" / "0001_init.sql")
    assert detect_layout(tmp_path) == "supabase"


def test_detect_supabase_migrations_dir(tmp_path: Path) -> None:
    mig = tmp_path / "supabase" / "migrations"
    _touch(mig / "0001_init.sql")
    assert detect_layout(mig) == "supabase"


def test_detect_prisma(tmp_path: Path) -> None:
    _touch(tmp_path / "20240101000000_init" / "migration.sql")
    assert detect_layout(tmp_path) == "prisma"


def test_detect_flyway(tmp_path: Path) -> None:
    _touch(tmp_path / "V1__init.sql")
    _touch(tmp_path / "V2__more.sql")
    assert detect_layout(tmp_path) == "flyway"


def test_detect_sqitch(tmp_path: Path) -> None:
    _touch(tmp_path / "sqitch.plan", "%project=t\nusers 2020 me # x\n")
    _touch(tmp_path / "deploy" / "users.sql")
    assert detect_layout(tmp_path) == "sqitch"


def test_detect_plain_glob(tmp_path: Path) -> None:
    _touch(tmp_path / "001_a.sql")
    _touch(tmp_path / "002_b.sql")
    assert detect_layout(tmp_path) == "glob"


def test_detect_python_migrations_errors(tmp_path: Path) -> None:
    _touch(tmp_path / "versions" / "abc_init.py", "# alembic\n")
    with pytest.raises(LayoutError, match="Alembic/Django"):
        detect_layout(tmp_path)


def test_detect_empty_dir_errors(tmp_path: Path) -> None:
    with pytest.raises(LayoutError, match="no .sql"):
        detect_layout(tmp_path)


# --- resolve_plan ordering -------------------------------------------------


def test_resolve_single_file(tmp_path: Path) -> None:
    f = _touch(tmp_path / "schema.sql")
    plan = resolve_plan(f)
    assert plan.layout == "sql"
    assert plan.files == (f,)


def test_resolve_supabase_lexicographic(tmp_path: Path) -> None:
    mig = tmp_path / "supabase" / "migrations"
    a = _touch(mig / "20240101000000_a.sql")
    b = _touch(mig / "20240202000000_b.sql")
    plan = resolve_plan(mig)
    assert plan.layout == "supabase"
    assert plan.files == (a, b)


def test_resolve_prisma_by_parent(tmp_path: Path) -> None:
    a = _touch(tmp_path / "20240101_a" / "migration.sql")
    b = _touch(tmp_path / "20240202_b" / "migration.sql")
    plan = resolve_plan(tmp_path, layout="prisma")
    assert plan.files == (a, b)


def test_resolve_flyway_numeric_version(tmp_path: Path) -> None:
    v1 = _touch(tmp_path / "V1__a.sql")
    v1_1 = _touch(tmp_path / "V1_1__b.sql")
    v2 = _touch(tmp_path / "V2__c.sql")
    v10 = _touch(tmp_path / "V10__d.sql")
    plan = resolve_plan(tmp_path, layout="flyway")
    # numeric, not lexical: V2 before V10; V1_1 between V1 and V2
    assert plan.files == (v1, v1_1, v2, v10)


def test_resolve_sqitch_plan_order(tmp_path: Path) -> None:
    _touch(
        tmp_path / "sqitch.plan",
        "%syntax-version=1.0.0\n%project=t\n\n"
        "users 2020-01-01T00:00:00Z me <m@x> # add users\n"
        "posts [users] 2020-01-02T00:00:00Z me <m@x> # add posts\n",
    )
    users = _touch(tmp_path / "deploy" / "users.sql")
    posts = _touch(tmp_path / "deploy" / "posts.sql")
    plan = resolve_plan(tmp_path, layout="sqitch")
    assert plan.files == (users, posts)


def test_resolve_glob_custom_pattern(tmp_path: Path) -> None:
    a = _touch(tmp_path / "db" / "001.sql")
    b = _touch(tmp_path / "db" / "002.sql")
    _touch(tmp_path / "ignore.sql")
    plan = resolve_plan(tmp_path, layout="glob", glob_pattern="db/*.sql")
    assert plan.files == (a, b)


def test_resolve_unknown_layout(tmp_path: Path) -> None:
    with pytest.raises(LayoutError, match="unknown layout"):
        resolve_plan(tmp_path, layout="nope")


def test_resolve_missing_path(tmp_path: Path) -> None:
    with pytest.raises(LayoutError, match="does not exist"):
        resolve_plan(tmp_path / "nope")


def test_resolve_glob_no_match(tmp_path: Path) -> None:
    _touch(tmp_path / "a.sql")
    with pytest.raises(LayoutError, match="matched no files"):
        resolve_plan(tmp_path, layout="glob", glob_pattern="*.nope")
