"""Build a :class:`~pgrls.model.Schema` by applying migrations to a throwaway DB.

Powers ``pgrls lint --migrations <dir>``: boot a disposable Postgres
container, apply the project's migration SQL in order, introspect the result,
then tear the container down.
This removes the single biggest onboarding barrier — needing a reachable,
already-migrated database — so the only requirement becomes "Docker is
running."

Requires the ``pgrls[ephemeral]`` extra (testcontainers + Docker), an alias of
``pgrls[diff-apply]``. It uses the same boot -> apply -> introspect approach as
``pgrls diff --apply`` (``cli.py``'s ``_apply_migration_for_diff``); the two
implementations are currently separate.
"""
from __future__ import annotations

import os
from collections.abc import Callable, Sequence
from pathlib import Path

import pglast
import psycopg

from pgrls.introspect import introspect
from pgrls.model import Schema

# Image override env var. A feature-neutral name so ``lint --migrations`` users
# are not told to set a "DIFF_APPLY" variable; falls back to the diff path's
# pin and then the default so a single export covers both.
EPHEMERAL_PG_IMAGE_ENV = "PGRLS_EPHEMERAL_PG_IMAGE"
_DEFAULT_PG_IMAGE = "postgres:17-alpine"

# Supabase ``auth.*`` stubs so Supabase-style policies (``auth.uid()`` etc.)
# parse-analyze at CREATE POLICY time against a stock Postgres image with no
# Supabase stack. Mirrors corpus/harness.py:_PRELUDE and
# demo/cases/_shared.sql — the same prelude pgrls already trusts.
_SUPABASE_PRELUDE = """
CREATE SCHEMA IF NOT EXISTS auth;
CREATE OR REPLACE FUNCTION auth.uid() RETURNS uuid LANGUAGE sql STABLE
    AS $$ SELECT current_setting('request.jwt.claim.sub', true)::uuid $$;
CREATE OR REPLACE FUNCTION auth.role() RETURNS text LANGUAGE sql STABLE
    AS $$ SELECT current_setting('request.jwt.claim.role', true) $$;
CREATE OR REPLACE FUNCTION auth.jwt() RETURNS jsonb LANGUAGE sql STABLE
    AS $$ SELECT current_setting('request.jwt.claims', true)::jsonb $$;
"""
# Roles a Supabase project's policies grant to.
_SUPABASE_ROLES: tuple[str, ...] = ("anon", "authenticated", "service_role")


class EphemeralError(Exception):
    """The ephemeral build could not complete.

    Raised when the ``pgrls[ephemeral]`` extra is missing, Docker is
    unreachable, or a migration failed to apply. The CLI translates this to a
    ``ToolError`` (exit 2); this module stays free of Click/CLI imports.
    """


def resolve_pg_image(pg_image: str | None = None) -> str:
    """The Postgres image to boot: explicit arg, then env vars, then default."""
    return (
        pg_image
        or os.environ.get(EPHEMERAL_PG_IMAGE_ENV)
        or os.environ.get("PGRLS_DIFF_APPLY_PG_IMAGE")
        or _DEFAULT_PG_IMAGE
    )


def build_schema_from_migrations(
    *,
    sql_files: Sequence[Path],
    schemas: list[str],
    extra_roles: Sequence[str] = (),
    provision_supabase: bool = False,
    pg_image: str | None = None,
    verbose_log: Callable[[str], None] = lambda _msg: None,
) -> Schema:
    """Boot an ephemeral Postgres, apply ``sql_files`` in order, introspect.

    Each file is applied in the given order on an autocommit connection; a file
    containing a non-transactional statement (e.g. ``CREATE INDEX
    CONCURRENTLY``) is automatically re-applied statement-by-statement.
    ``extra_roles`` (plus the Supabase roles when ``provision_supabase``) are
    pre-created ``NOLOGIN`` so role-referencing DDL applies; migrations create
    their own extensions. The container is always torn down (context manager),
    on success and on failure.

    Raises :class:`EphemeralError` when testcontainers/Docker is unavailable or
    a file fails to apply (the offending file and the Postgres error are
    named).
    """
    try:
        from testcontainers.postgres import PostgresContainer
    except ImportError as exc:
        raise EphemeralError(
            "linting from migrations requires the `pgrls[ephemeral]` extra "
            "(testcontainers + Docker). Install with `pip install "
            "'pgrls[ephemeral]'` and ensure Docker is running."
        ) from exc

    files = tuple(sql_files)
    if not files:
        raise EphemeralError("no migration SQL files to apply.")

    # Read every file up front so a bad path fails before a container boots.
    sources: list[tuple[Path, str]] = []
    for path in files:
        try:
            sources.append((path, path.read_text(encoding="utf-8")))
        except (OSError, UnicodeDecodeError) as exc:
            raise EphemeralError(f"cannot read migration {path}: {exc}") from exc

    roles: set[str] = {r for r in extra_roles if r and r.upper() != "PUBLIC"}
    if provision_supabase:
        roles.update(_SUPABASE_ROLES)

    image = resolve_pg_image(pg_image)
    verbose_log(f"booting ephemeral Postgres ({image})")

    try:
        with PostgresContainer(
            image, username="postgres", password="postgres", dbname="postgres"
        ) as pg:
            url = pg.get_connection_url(driver=None)
            try:
                with psycopg.connect(url, autocommit=True) as conn, conn.cursor() as cur:
                    if roles:
                        from psycopg import sql as _sql

                        for role in sorted(roles):
                            # Compose the role name as a literal/identifier; a
                            # server-side %s param inside a DO body has no
                            # inferable type (IndeterminateDatatype).
                            cur.execute(
                                _sql.SQL(
                                    "DO $$ BEGIN IF NOT EXISTS ("
                                    "SELECT 1 FROM pg_roles WHERE rolname = {name}"
                                    ") THEN CREATE ROLE {ident} NOLOGIN; "
                                    "END IF; END $$;"
                                ).format(
                                    name=_sql.Literal(role),
                                    ident=_sql.Identifier(role),
                                )
                            )
                        verbose_log(f"created {len(roles)} role(s): {sorted(roles)}")
                    if provision_supabase:
                        cur.execute(_SUPABASE_PRELUDE)
                        verbose_log("provisioned Supabase auth.* stubs")
                    for path, text in sources:
                        try:
                            try:
                                cur.execute(text)
                            except psycopg.errors.ActiveSqlTransaction:
                                # A non-transactional statement (e.g. CREATE
                                # INDEX CONCURRENTLY) cannot run in psycopg's
                                # implicit multi-statement transaction; re-apply
                                # the file statement-by-statement, as the real
                                # migration tools do.
                                try:
                                    statements = pglast.split(text)
                                except Exception as exc:  # noqa: BLE001
                                    raise EphemeralError(
                                        f"migration {path} has a non-"
                                        "transactional statement that could not "
                                        f"be split for retry: {exc}"
                                    ) from exc
                                for stmt in statements:
                                    cur.execute(stmt)
                        except psycopg.Error as exc:
                            raise EphemeralError(
                                f"migration {path} failed to apply: {exc}"
                            ) from exc
                        verbose_log(f"applied {path}")
                with psycopg.connect(url) as conn:
                    return introspect(conn, schemas=schemas)
            except EphemeralError:
                raise
            except psycopg.Error as exc:
                raise EphemeralError(f"ephemeral database error: {exc}") from exc
            except (ValueError, RuntimeError) as exc:
                # e.g. introspect() on a missing/reserved --schemas value:
                # surface the real cause, not the Docker/extra hint below.
                raise EphemeralError(str(exc)) from exc
    except EphemeralError:
        raise
    except Exception as exc:  # noqa: BLE001 - convert any docker/start failure
        raise EphemeralError(
            f"could not run the ephemeral Postgres container ({exc}). Is "
            "Docker running, and is the `pgrls[ephemeral]` extra installed?"
        ) from exc
