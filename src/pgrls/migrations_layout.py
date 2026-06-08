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
# Undo migrations (``U<version>__desc.sql``) — excluded from a forward build.
_FLYWAY_UNDO = re.compile(r"^U(\d+(?:[._]\d+)*)__.+\.sql$")
# Once-run callbacks that can define schema; ordered around the versioned set.
_FLYWAY_BEFORE = re.compile(r"^beforeMigrate(?:__.+)?\.sql$")
_FLYWAY_AFTER = re.compile(r"^afterMigrate(?:__.+)?\.sql$")


class LayoutError(Exception):
    """No applicable SQL migrations could be resolved from the given path."""


@dataclass(frozen=True)
class MigrationPlan:
    """An ordered set of SQL files to apply, plus the detected layout."""

    files: tuple[Path, ...]
    layout: str
    root: Path


def _flyway_sort_key(path: Path) -> tuple[int, tuple[int, ...], str]:
    """Forward-build order: beforeMigrate, then versioned (numeric) and
    repeatable, then afterMigrate, then any other .sql last — never lexical
    across versions (so V2 precedes V10)."""
    name = path.name
    if _FLYWAY_BEFORE.match(name):
        return (0, (), name)
    m = _FLYWAY_VERSIONED.match(name)
    if m:
        version = tuple(int(part) for part in re.split(r"[._]", m.group(1)))
        return (1, version, name)
    if _FLYWAY_REPEATABLE.match(name):
        return (2, (), name)
    if _FLYWAY_AFTER.match(name):
        return (3, (), name)
    return (4, (), name)


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
        # Any versioned V* file means Flyway, even alongside callbacks or a
        # seed .sql — otherwise we'd fall to glob and apply V10 before V2.
        if any(_FLYWAY_VERSIONED.match(p.name) for p in sql_files):
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
    """Order deploy scripts by the change order in ``sqitch.plan``.

    Handles reworked changes: a change name reappearing after a ``@tag`` is a
    rework whose earlier occurrence is the as-of-tag snapshot
    ``deploy/<change>@<tag>.sql`` and whose later occurrence is the current
    ``deploy/<change>.sql`` — so the same file is never queued twice.
    """
    try:
        plan = (path / "sqitch.plan").read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise LayoutError(f"cannot read {path / 'sqitch.plan'}: {exc}") from exc
    deploy = path / "deploy"
    files: list[Path] = []
    seen: dict[str, int] = {}
    last_tag: str | None = None
    for raw in plan.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", "%")):
            continue  # comments and pragmas
        token = line.split()[0]
        if token.startswith("@"):
            last_tag = token[1:]  # a tag marks a rework boundary
            continue
        change = token
        if change in seen and last_tag is not None:
            # Rework: the earlier occurrence is the as-of-tag snapshot.
            snapshot = deploy / f"{change}@{last_tag}.sql"
            if snapshot.is_file():
                files[seen[change]] = snapshot
        candidate = deploy / f"{change}.sql"
        if candidate.is_file():
            files.append(candidate)
            seen[change] = len(files) - 1
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

    # A supplied --migrations-glob implies the glob layout, else it would be
    # silently ignored under auto-detection (and the user told to pass it).
    if layout == "auto" and glob_pattern is not None:
        layout = "glob"
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
        # Undo scripts (U*) are never applied in a forward build.
        files = tuple(
            sorted(
                (p for p in path.glob("*.sql") if not _FLYWAY_UNDO.match(p.name)),
                key=_flyway_sort_key,
            )
        )
        if not files:
            raise LayoutError(f"no forward Flyway .sql files under {path}.")
        return MigrationPlan(files=files, layout="flyway", root=path)

    if layout == "sqitch":
        return MigrationPlan(files=_resolve_sqitch(path), layout="sqitch", root=path)

    # glob
    pattern = glob_pattern or "*.sql"
    try:
        matches = sorted(p for p in path.glob(pattern) if p.is_file())
    except (ValueError, NotImplementedError) as exc:
        raise LayoutError(
            f"invalid --migrations-glob pattern {pattern!r}: {exc}. Use a "
            f"pattern relative to {path}, e.g. 'db/migrate/*.sql'."
        ) from exc
    if not matches:
        raise LayoutError(f"pattern {pattern!r} matched no files under {path}.")
    return MigrationPlan(files=tuple(matches), layout="glob", root=path)
