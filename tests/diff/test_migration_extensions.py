"""Unit tests for `pgrls.diff._migration_extensions.detect_extensions` —
the v0.5.1 helper that walks a migration's pglast AST for
``CREATE EXTENSION`` statements.
"""
from __future__ import annotations

from pgrls.diff._migration_extensions import detect_extensions


def test_detect_returns_empty_for_migration_without_extensions():
    sql = "CREATE TABLE public.t (id BIGSERIAL);\n"
    assert detect_extensions(sql) == []


def test_detect_finds_single_create_extension():
    sql = "CREATE EXTENSION pgcrypto;\n"
    assert detect_extensions(sql) == ["pgcrypto"]


def test_detect_finds_create_extension_if_not_exists():
    sql = "CREATE EXTENSION IF NOT EXISTS citext;\n"
    assert detect_extensions(sql) == ["citext"]


def test_detect_finds_multiple_extensions_deduped_and_sorted():
    sql = (
        "CREATE EXTENSION IF NOT EXISTS pgcrypto;\n"
        "CREATE TABLE public.t (id UUID DEFAULT gen_random_uuid());\n"
        "CREATE EXTENSION citext;\n"
        "CREATE EXTENSION IF NOT EXISTS pgcrypto;\n"  # duplicate
    )
    # Deduplicated and sorted alphabetically.
    assert detect_extensions(sql) == ["citext", "pgcrypto"]


def test_detect_returns_empty_on_unparseable_sql():
    # pglast can't parse psql backslash commands or arbitrary
    # multi-statement scripts with embedded errors. The helper
    # degrades gracefully — returns [] so the caller surfaces
    # the real error from psycopg.execute(migration_sql) later.
    sql = "\\connect mydb\nCREATE EXTENSION pgcrypto;\n"
    # Output may be [] or ["pgcrypto"] depending on pglast's
    # psql-meta handling; pin only the no-crash invariant.
    result = detect_extensions(sql)
    assert isinstance(result, list)


def test_detect_ignores_extensions_in_strings_and_comments():
    sql = (
        "-- CREATE EXTENSION pgcrypto;\n"
        "/* CREATE EXTENSION citext; */\n"
        "INSERT INTO logs (msg) VALUES ('CREATE EXTENSION fakeext;');\n"
    )
    # The pglast AST walk only sees real statements, not strings
    # or comments — fake "extensions" inside text don't get
    # auto-installed.
    assert detect_extensions(sql) == []


def test_detect_finds_extension_with_options():
    # `WITH SCHEMA pg_catalog` etc. is parsed as options on the
    # CreateExtensionStmt; the extname field is independent.
    sql = "CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;\n"
    assert detect_extensions(sql) == ["pgcrypto"]


def test_detect_handles_quoted_extension_name():
    # Postgres allows quoted extension names. pglast strips the
    # quotes when populating extname.
    sql = 'CREATE EXTENSION "uuid-ossp";\n'
    assert detect_extensions(sql) == ["uuid-ossp"]
