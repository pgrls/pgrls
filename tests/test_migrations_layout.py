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


def test_detect_flyway_with_undo_scripts(tmp_path: Path) -> None:
    _touch(tmp_path / "V1__init.sql")
    _touch(tmp_path / "V2__add.sql")
    _touch(tmp_path / "U1__undo_add.sql")
    # Undo scripts are Flyway-shaped, so the dir still detects as flyway —
    # not glob, which would apply U1 first lexically and DROP-before-create.
    assert detect_layout(tmp_path) == "flyway"


def test_resolve_flyway_excludes_undo(tmp_path: Path) -> None:
    v1 = _touch(tmp_path / "V1__init.sql")
    v2 = _touch(tmp_path / "V2__add.sql")
    _touch(tmp_path / "U1__undo_add.sql")
    plan = resolve_plan(tmp_path, layout="flyway")
    assert plan.files == (v1, v2)  # a forward build never applies U*


def test_resolve_sqitch_rework(tmp_path: Path) -> None:
    _touch(
        tmp_path / "sqitch.plan",
        "%project=t\n\n"
        "users 2020-01-01T00:00:00Z me <m@x> # add\n"
        "@v1.0 2020-01-02T00:00:00Z me <m@x> # release\n"
        "users [users@v1.0] 2020-01-03T00:00:00Z me <m@x> # rework\n",
    )
    snap = _touch(tmp_path / "deploy" / "users@v1.0.sql")
    base = _touch(tmp_path / "deploy" / "users.sql")
    plan = resolve_plan(tmp_path, layout="sqitch")
    # earlier occurrence -> as-of-tag snapshot, later -> current; no double-apply
    assert plan.files == (snap, base)


def test_resolve_glob_absolute_pattern_errors(tmp_path: Path) -> None:
    _touch(tmp_path / "a.sql")
    with pytest.raises(LayoutError, match="invalid --migrations-glob"):
        resolve_plan(tmp_path, layout="glob", glob_pattern="/etc/*.sql")


def test_detect_flyway_with_callback(tmp_path: Path) -> None:
    _touch(tmp_path / "V1__init.sql")
    _touch(tmp_path / "V2__a.sql")
    _touch(tmp_path / "afterMigrate.sql")
    # A callback (or any extra .sql) must not flip the dir to lexical glob.
    assert detect_layout(tmp_path) == "flyway"


def test_resolve_flyway_orders_callbacks_and_versions(tmp_path: Path) -> None:
    before = _touch(tmp_path / "beforeMigrate.sql")
    v1 = _touch(tmp_path / "V1__init.sql")
    v2 = _touch(tmp_path / "V2__a.sql")
    v10 = _touch(tmp_path / "V10__b.sql")
    after = _touch(tmp_path / "afterMigrate.sql")
    plan = resolve_plan(tmp_path, layout="flyway")
    # beforeMigrate, then V numeric (V2 before V10), then afterMigrate last
    assert plan.files == (before, v1, v2, v10, after)


def test_resolve_flyway_seed_file_last(tmp_path: Path) -> None:
    v1 = _touch(tmp_path / "V1__init.sql")
    v2 = _touch(tmp_path / "V2__a.sql")
    seed = _touch(tmp_path / "seed.sql")
    plan = resolve_plan(tmp_path, layout="flyway")
    assert plan.files == (v1, v2, seed)


def test_resolve_auto_glob_promotion(tmp_path: Path) -> None:
    # SQL only in a subdir + a --migrations-glob => auto promotes to glob.
    a = _touch(tmp_path / "db" / "migrate" / "001.sql")
    b = _touch(tmp_path / "db" / "migrate" / "002.sql")
    plan = resolve_plan(tmp_path, layout="auto", glob_pattern="db/migrate/*.sql")
    assert plan.layout == "glob"
    assert plan.files == (a, b)


def test_resolve_glob_skips_directories(tmp_path: Path) -> None:
    a = _touch(tmp_path / "a.sql")
    (tmp_path / "sub.sql").mkdir()  # a directory whose name matches *.sql
    plan = resolve_plan(tmp_path, layout="glob")
    assert plan.files == (a,)
