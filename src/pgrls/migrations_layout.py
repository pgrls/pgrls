"""Detect a project's migration layout and produce an ordered SQL file list.

Pure, dependency-free, and DB-free so it is fully unit-testable without
Docker. ``pgrls lint --migrations <path>`` calls :func:`resolve_plan` to turn
a directory (or a single ``.sql`` file) into the ordered list of SQL files
that :func:`pgrls.ephemeral.build_schema_from_migrations` applies to a
throwaway Postgres.

Detection is best-effort: the supported layouts cover the common
SQL-migration tools, and an explicit ``--migrations-layout`` /
``--migrations-glob`` always overrides it. Frameworks whose migrations are
*code* (Alembic, Django) emit no ``.sql`` to apply, so detection surfaces a
clear, actionable error rather than guessing.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

# Layout identifiers accepted by ``--migrations-layout``. ``auto`` runs
# :func:`detect_layout`; the rest force a specific resolver.
LAYOUTS: tuple[str, ...] = (
    "auto",
    "supabase",
    "prisma",
    "flyway",
    "sqitch",
    "sql",
    "glob",
)

# A Flyway migration file: ``V<version>__desc.sql`` (versioned) or
# ``R__desc.sql`` (repeatable). Version is digits separated by ``.`` or ``_``.
_FLYWAY_VERSIONED = re.compile(r"^V(\d+(?:[._]\d+)*)__.+\.sql$")
_FLYWAY_REPEATABLE = re.compile(r"^R__.+\.sql$")


class LayoutError(Exception):
    """No applicable SQL migrations could be resolved from the given path."""


@dataclass(frozen=True)
class MigrationPlan:
    """An ordered set of SQL files to apply, plus the detected layout."""

    files: tuple[Path, ...]
    layout: str
    root: Path


def _is_flyway_name(name: str) -> bool:
    return bool(_FLYWAY_VERSIONED.match(name) or _FLYWAY_REPEATABLE.match(name))


def _flyway_sort_key(path: Path) -> tuple[int, tuple[int, ...], str]:
    """Order versioned files by numeric version, then repeatable by name."""
    m = _FLYWAY_VERSIONED.match(path.name)
    if m:
        version = tuple(int(part) for part in re.split(r"[._]", m.group(1)))
        return (0, version, path.name)
    return (1, (), path.name)


def detect_layout(path: Path) -> str:
    """Infer the migration layout of ``path`` (a directory or a .sql file).

    Raises :class:`LayoutError` when the directory holds no applicable SQL
    (e.g. Alembic/Django Python migrations), with guidance to export a SQL
    dump or pass ``--migrations-glob``.
    """
    if path.is_file():
        return "sql"
    if not path.is_dir():
        raise LayoutError(f"{path} is not a file or directory.")

    # A Supabase project root (``supabase/`` with config.toml + migrations/),
    # or the ``supabase/migrations`` directory itself.
    if (path / "config.toml").is_file() and (path / "migrations").is_dir():
        return "supabase"
    if path.name == "migrations" and path.parent.name == "supabase":
        return "supabase"

    if (path / "sqitch.plan").is_file():
        return "sqitch"

    # Prisma: ``<migrations>/<timestamp>_name/migration.sql``.
    if any(path.glob("*/migration.sql")):
        return "prisma"

    sql_files = sorted(path.glob("*.sql"))
    if sql_files:
        if all(_is_flyway_name(p.name) for p in sql_files):
            return "flyway"
        return "glob"

    # No .sql anywhere. If it looks like a code-migration tool, say so.
    if any(path.glob("*.py")) or (path / "versions").is_dir():
        raise LayoutError(
            f"{path} appears to contain code (not SQL) migrations "
            "(Alembic/Django). pgrls applies SQL to an ephemeral database; "
            "export a SQL dump first — e.g. `alembic upgrade head --sql "
            "> schema.sql` or `python manage.py sqlmigrate` — and point "
            "--migrations at the resulting .sql file."
        )
    raise LayoutError(
        f"no .sql migrations found under {path}. Pass --migrations-glob "
        "with an explicit pattern, or point --migrations at a schema.sql file."
    )


def _resolve_supabase(path: Path) -> tuple[tuple[Path, ...], Path]:
    root = path / "migrations" if (path / "migrations").is_dir() else path
    # Supabase names migrations ``<YYYYMMDDHHMMSS>_name.sql``; lexicographic
    # order is chronological.
    return tuple(sorted(root.glob("*.sql"))), root


def _resolve_sqitch(path: Path) -> tuple[Path, ...]:
    """Order deploy scripts by the change order in ``sqitch.plan``."""
    plan = (path / "sqitch.plan").read_text(encoding="utf-8")
    deploy = path / "deploy"
    files: list[Path] = []
    for raw in plan.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", "%")):
            continue  # comments and pragmas
        change = line.split()[0]
        if change.startswith("@"):
            continue  # tag line, not a change
        candidate = deploy / f"{change}.sql"
        if candidate.is_file():
            files.append(candidate)
    if not files:
        raise LayoutError(
            f"sqitch.plan in {path} named no deployable changes under "
            f"{deploy}. Pass --migrations-glob instead."
        )
    return tuple(files)


def resolve_plan(
    path: Path, *, layout: str = "auto", glob_pattern: str | None = None
) -> MigrationPlan:
    """Resolve ``path`` to an ordered :class:`MigrationPlan`.

    ``layout`` is one of :data:`LAYOUTS`; ``auto`` infers it. ``glob_pattern``
    is honored only for the ``glob`` layout (e.g. ``db/migrate/*.sql``).
    """
    if layout not in LAYOUTS:
        raise LayoutError(
            f"unknown layout {layout!r}; expected one of {', '.join(LAYOUTS)}."
        )
    if not path.exists():
        raise LayoutError(f"{path} does not exist.")

    if layout == "auto":
        layout = detect_layout(path)

    if layout == "sql":
        if not path.is_file():
            raise LayoutError(f"{path} is not a .sql file.")
        return MigrationPlan(files=(path,), layout="sql", root=path.parent)

    if not path.is_dir():
        raise LayoutError(f"{path} must be a directory for layout {layout!r}.")

    if layout == "supabase":
        files, root = _resolve_supabase(path)
        if not files:
            raise LayoutError(f"no .sql migrations under {root}.")
        return MigrationPlan(files=files, layout="supabase", root=root)

    if layout == "prisma":
        files = tuple(sorted(path.glob("*/migration.sql"), key=lambda p: p.parent.name))
        if not files:
            raise LayoutError(f"no */migration.sql under {path}.")
        return MigrationPlan(files=files, layout="prisma", root=path)

    if layout == "flyway":
        files = tuple(sorted(path.glob("*.sql"), key=_flyway_sort_key))
        if not files:
            raise LayoutError(f"no Flyway .sql files under {path}.")
        return MigrationPlan(files=files, layout="flyway", root=path)

    if layout == "sqitch":
        return MigrationPlan(files=_resolve_sqitch(path), layout="sqitch", root=path)

    # glob
    pattern = glob_pattern or "*.sql"
    files = tuple(sorted(path.glob(pattern)))
    if not files:
        raise LayoutError(
            f"pattern {pattern!r} matched no files under {path}."
        )
    return MigrationPlan(files=files, layout="glob", root=path)
