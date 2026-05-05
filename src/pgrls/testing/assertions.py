"""RLS-specific assertion helpers.

Each helper takes a psycopg connection and a SQL string. The
`PgrlsTestClient` class exposes them as methods (passing
`self._conn`) — but they're equally usable standalone in
non-pgrls.testing contexts (notebooks, ad-hoc scripts, other test
runners).

Failure mode: every helper raises `PgrlsTestAssertionError` (an
`AssertionError` subclass) so pytest renders the failure with its
standard diff machinery.
"""
from __future__ import annotations

import secrets

import psycopg

from pgrls.testing.errors import PgrlsTestAssertionError, PgrlsTestError


def _row_count(
    conn: psycopg.Connection, sql: str
) -> int:
    with conn.cursor() as cur:
        cur.execute(sql)
        return len(cur.fetchall())


def assert_rows(
    conn: psycopg.Connection,
    sql: str,
    *,
    count: int,
) -> None:
    """Assert the query returns exactly `count` rows."""
    actual = _row_count(conn, sql)
    if actual != count:
        raise PgrlsTestAssertionError(
            f"assert_rows: expected {count} row(s), got {actual} "
            f"for query: {sql!r}"
        )


def assert_visible(
    conn: psycopg.Connection, sql: str
) -> None:
    """Assert the query returns at least one row."""
    actual = _row_count(conn, sql)
    if actual == 0:
        raise PgrlsTestAssertionError(
            f"assert_visible: expected at least 1 row, got 0 "
            f"for query: {sql!r}"
        )


def assert_invisible(
    conn: psycopg.Connection, sql: str
) -> None:
    """Assert the query returns zero rows."""
    actual = _row_count(conn, sql)
    if actual != 0:
        raise PgrlsTestAssertionError(
            f"assert_invisible: expected 0 rows, got {actual} "
            f"for query: {sql!r}"
        )


def assert_rejected(
    conn: psycopg.Connection, sql: str
) -> None:
    """Assert that running `sql` raises Postgres InsufficientPrivilege.

    Wraps the query in a savepoint so a failure (which puts the
    transaction in 'aborted' state until rollback) doesn't poison
    subsequent queries in the same test. On success (the query
    raised the expected error), the savepoint is rolled back; on
    failure (the query succeeded or raised a different error),
    a `PgrlsTestAssertionError` is raised.
    """
    savepoint = f"pgrls_check_{secrets.token_hex(4)}"
    with conn.cursor() as cur:
        cur.execute(f"SAVEPOINT {savepoint}")
        try:
            cur.execute(sql)
        except psycopg.errors.InsufficientPrivilege:
            cur.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
            return
        except psycopg.Error as exc:
            cur.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
            raise PgrlsTestAssertionError(
                f"assert_rejected: expected "
                f"InsufficientPrivilege (SQLSTATE 42501), got "
                f"{type(exc).__name__}: {exc}"
            ) from exc
        cur.execute(f"RELEASE SAVEPOINT {savepoint}")
        raise PgrlsTestAssertionError(
            f"assert_rejected: query succeeded but expected RLS "
            f"rejection: {sql!r}"
        )


def assert_silently_dropped(
    conn: psycopg.Connection, sql: str
) -> None:
    """Assert that a DML with RETURNING returns zero rows.

    Models the Postgres RLS shape where an UPDATE or DELETE
    finds no rows because the policy's USING expression filters
    them all out — the operation succeeds with no error and
    RETURNING yields zero rows. This is distinct from a
    permission rejection (which raises InsufficientPrivilege)
    and from a missing-row case (which is just an empty
    SELECT).

    Note on INSERT: in Postgres, INSERT ... RETURNING does NOT
    silently drop. When a SELECT policy's USING fails on the
    new row, the engine raises "new row violates row-level
    security policy" rather than returning zero rows. The silent-
    drop shape only happens for UPDATE/DELETE ... RETURNING,
    where USING acts as a pre-operation row filter.

    Distinct from `assert_rejected` (which expects the write to
    raise InsufficientPrivilege) and `assert_invisible` (which
    is a SELECT-side check). The helper requires the SQL to
    contain RETURNING — without it, the row count is not the
    relevant signal.

    Unlike `assert_rejected`, this helper does NOT wrap the
    query in a savepoint. The contract is "the DML succeeds
    silently with no rows" — if the query raises (typo, bad
    column reference, accidental WITH CHECK violation), the
    outer transaction enters aborted state. That's the test
    author's bug to fix; the helper deliberately doesn't try
    to recover, so the failure surfaces loudly via pytest's
    standard error path rather than being swallowed. If you
    want savepoint-tolerant rejection assertions, use
    `assert_rejected` for the raise path.

    Side-effect note: the SQL runs to completion before the
    statement-verb check rejects a non-UPDATE/DELETE call.
    Passing a SELECT or INSERT here therefore executes the
    statement (potentially side-effecting) and *then* raises
    `PgrlsTestError`. Don't rely on the verb-gate to short-
    circuit destructive SQL; only call this with UPDATE/DELETE
    that you actually want to run.
    """
    with conn.cursor() as cur:
        cur.execute(sql)
        # `statusmessage` is psycopg's command-tag exposure: "UPDATE
        # 5", "DELETE 0", "SELECT 12", etc. Gate on the verb so a
        # SELECT (which produces a result set whether or not it
        # returns rows) can't silently masquerade as the
        # silent-drop shape — `assert_silently_dropped("SELECT * FROM
        # t WHERE 1=0")` would otherwise pass with zero rows even
        # though no RLS-aware DML ran.
        status = (cur.statusmessage or "").upper()
        verb = status.split(" ", 1)[0] if status else ""
        if verb not in {"UPDATE", "DELETE"}:
            raise PgrlsTestError(
                "assert_silently_dropped is for UPDATE/DELETE … "
                "RETURNING (USING acts as a row pre-filter); "
                "INSERT … RETURNING does NOT silently drop — "
                "Postgres raises InsufficientPrivilege on a WITH "
                "CHECK violation. Use assert_invisible for SELECT "
                "and assert_rejected for INSERT."
                f" Got command verb {verb or '(unknown)'!r} for "
                f"query: {sql!r}"
            )
        try:
            rows = cur.fetchall()
        except psycopg.ProgrammingError as exc:
            # No result set produced — the UPDATE/DELETE didn't have
            # a RETURNING clause; without it the row count is not
            # the relevant signal.
            raise PgrlsTestError(
                "assert_silently_dropped requires the SQL to use "
                "RETURNING — the helper checks that the affected "
                "row was hidden from the current role by counting "
                "RETURNING's output. "
                f"Query produced no result set: {sql!r}"
            ) from exc
    if rows:
        raise PgrlsTestAssertionError(
            f"assert_silently_dropped: expected RETURNING to "
            f"yield 0 rows, got {len(rows)} row(s) for query: "
            f"{sql!r}"
        )
