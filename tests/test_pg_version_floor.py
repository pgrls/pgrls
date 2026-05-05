"""Pin the Postgres version-floor claim in README.md.

The README declares "Postgres 15+" as the supported floor. Without
a guard, the only thing actually exercised by `pytest` is whatever
`tests/conftest.py` (or `PGRLS_TEST_PG_IMAGE`) points at — typically
PG16. A future commit that depends on a PG16+ catalog column or
function would silently break PG15 with no failing test.

This file declares the floor as a single source of truth and
asserts the connected Postgres meets it. Set
`PGRLS_TEST_PG_IMAGE=postgres:15-alpine` to verify the floor is
actually satisfied; the floor check below catches the case where a
future change tightens the implicit floor without updating the README
claim.
"""
from __future__ import annotations

import psycopg

# README's stated floor in numeric server_version_num form
# (`MMmmpp` — major*10000 + minor*100 + patch). PG15 is 150000,
# PG16 is 160000, PG17 is 170000. Update this constant — and the
# README — together when the floor moves.
_README_PG_FLOOR_NUM: int = 150000


def test_connected_postgres_meets_readme_floor(
    pg_conn: psycopg.Connection,
) -> None:
    with pg_conn.cursor() as cur:
        cur.execute("SHOW server_version_num")
        row = cur.fetchone()
    assert row is not None
    server_version_num = int(row[0])
    floor_major = _README_PG_FLOOR_NUM // 10000
    actual_major = server_version_num // 10000
    assert server_version_num >= _README_PG_FLOOR_NUM, (
        f"Connected Postgres is {actual_major}, below README "
        f"floor of {floor_major}. Either tighten the README floor "
        "to match what's actually being tested, or run the suite "
        f"against an older image (e.g. "
        f"`PGRLS_TEST_PG_IMAGE=postgres:{floor_major}-alpine`)."
    )
