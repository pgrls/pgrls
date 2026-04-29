"""PgrlsTestClient — Layer 2 of the pgrls test architecture.

Wraps a psycopg Connection with the operations a pgrls test
needs: per-test transaction, role-and-claims switching, parameter-
ized SQL execution, and RLS-specific assertion helpers.

Pure psycopg, no pytest dependency — usable from notebooks,
ad-hoc scripts, or other Python test runners that aren't pytest.
The pytest plugin (`pgrls.testing.pytest_plugin`) wires this into
a `pgrls_db` fixture.
"""
from __future__ import annotations

import json
import secrets
from collections.abc import Generator, Sequence
from contextlib import contextmanager
from typing import TYPE_CHECKING

import psycopg

if TYPE_CHECKING:
    from typing import Any, Self


class PgrlsTestClient:
    """Wrap a psycopg connection with pgrls test conveniences.

    Construct directly when you have a connection
    (`PgrlsTestClient(conn)`); use `connect(database_url)` when
    you want pgrls.testing to open the connection for you.
    """

    def __init__(self, conn: psycopg.Connection) -> None:
        # Force non-autocommit so transaction()'s rollback is the
        # real transaction boundary regardless of how the caller
        # opened the connection. Both `connect()` (psycopg default
        # is autocommit=False, so this is a no-op) and tests using
        # an autocommit=True fixture connection see the same
        # contract.
        conn.autocommit = False
        self._conn = conn

    @classmethod
    @contextmanager
    def connect(
        cls, database_url: str
    ) -> Generator[Self, None, None]:
        """Open a connection and yield a client.

        The connection closes when the context exits.
        """
        with psycopg.connect(database_url) as conn:
            yield cls(conn)

    @contextmanager
    def transaction(self) -> Generator[None, None, None]:
        """Open a transaction; ROLLBACK on exit (always).

        Per-test isolation: the test body seeds data, switches
        roles, asserts. ROLLBACK at end means nothing persists.
        Pytest's standard exception flow propagates as usual; the
        `finally` here guarantees the rollback runs even when the
        body raises.

        Relies on the connection being in psycopg's default
        non-autocommit mode (set in `__init__`); the first statement
        inside the `with` block implicitly starts a transaction,
        `rollback()` ends it.
        """
        try:
            yield
        finally:
            self._conn.rollback()

    def exec(
        self, sql: str, *, params: Sequence[Any] = ()
    ) -> None:
        """Execute a single SQL statement with optional parameters."""
        with self._conn.cursor() as cur:
            cur.execute(sql, params)

    def fetchall(
        self, sql: str, *, params: Sequence[Any] = ()
    ) -> list[dict[str, object]]:
        """Run a query and return rows as a list of column→value dicts.

        Uses psycopg's `dict_row` row factory locally so the result
        shape is stable regardless of the connection's default row
        factory. Empty result returns `[]`.
        """
        from psycopg.rows import dict_row

        with self._conn.cursor(row_factory=dict_row) as cur:
            cur.execute(sql, params)
            return list(cur.fetchall())

    @contextmanager
    def as_role(
        self,
        role: str,
        *,
        claims: dict[str, Any] | None = None,
    ) -> Generator[None, None, None]:
        """Switch role and JWT claims for the duration of the block.

        Implementation:
          1. Capture the current role and `request.jwt.claims` GUC
             so the prior state can be restored on clean exit.
          2. SAVEPOINT pgrls_actor_<random> — so role and GUC
             changes can be unwound without affecting the outer
             transaction.
          3. SET LOCAL ROLE <role> — `SET LOCAL` is bound to the
             current transaction; rollback resets it.
          4. set_config('request.jwt.claims', json, true) — the
             procedural form of SET LOCAL for keys with dots.
          5. yield — test body runs.
          6. On clean exit: RELEASE SAVEPOINT, then explicitly
             restore the captured prior role + claims.
          7. On exception: ROLLBACK TO SAVEPOINT, which restores
             SET LOCAL state automatically; the exception
             propagates past the finally block.

        Nested `as_role` blocks are supported — the inner block
        captures the outer role and claims on entry and restores
        them on clean exit. Nesting means the outer block's body
        can run as actor A, an inner block can switch to actor B,
        and the outer body resumes as actor A after the inner
        block exits.

        Role names are quoted via pgrls.fixers._idents.quote_ident
        to handle reserved keywords (`select`, `from`, etc.) and
        identifiers needing double-quoting (mixed case, spaces).
        """
        from pgrls.fixers._idents import quote_ident

        # Name is locally generated (token_hex), not user input —
        # safe to interpolate without quoting.
        savepoint = f"pgrls_actor_{secrets.token_hex(4)}"
        # Capture state BEFORE the savepoint so we can restore it
        # on clean exit. RELEASE SAVEPOINT keeps SET LOCAL changes
        # merged into the outer transaction; without explicit
        # restoration, nested as_role blocks would lose the outer
        # role.
        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT current_user, "
                "current_setting('request.jwt.claims', true)"
            )
            row = cur.fetchone()
            assert row is not None  # SELECT always returns one row here
            prev_user, prev_claims = row

        with self._conn.cursor() as cur:
            cur.execute(f"SAVEPOINT {savepoint}")
        # SAVEPOINT now exists — every subsequent failure path
        # must run ROLLBACK TO SAVEPOINT, so move SET LOCAL ROLE
        # and set_config inside the try.
        ok = False
        try:
            with self._conn.cursor() as cur:
                cur.execute(f"SET LOCAL ROLE {quote_ident(role)}")
                if claims is not None:
                    cur.execute(
                        "SELECT set_config("
                        "'request.jwt.claims', %s, true)",
                        (json.dumps(claims),),
                    )
            yield
            ok = True
        finally:
            with self._conn.cursor() as cur:
                if ok:
                    cur.execute(f"RELEASE SAVEPOINT {savepoint}")
                    # Restore prior role + claims explicitly so
                    # nested as_role blocks return to the outer
                    # state.
                    cur.execute(
                        f"SET LOCAL ROLE {quote_ident(prev_user)}"
                    )
                    if prev_claims is not None:
                        # Outer had claims; restore them whether or
                        # not inner changed them (a no-op set is
                        # cheap).
                        cur.execute(
                            "SELECT set_config("
                            "'request.jwt.claims', %s, true)",
                            (prev_claims,),
                        )
                    elif claims is not None:
                        # Outer had no claims; inner set some.
                        # Clear the GUC value via `set_config(name,
                        # NULL, true)`. Postgres collapses NULL to
                        # the empty string on custom GUCs once
                        # they've been touched in the session — so
                        # `current_setting('request.jwt.claims',
                        # true)` returns `''` rather than NULL —
                        # but the inner-block JSON is gone, so a
                        # downstream policy doing
                        # `current_setting(...)::jsonb` raises
                        # `invalid input syntax for type json`
                        # instead of silently authorizing as the
                        # inner-block actor.
                        cur.execute(
                            "SELECT set_config("
                            "'request.jwt.claims', NULL, true)"
                        )
                    # else: outer had no claims and inner didn't
                    # set any — the GUC was never touched, no
                    # restore needed.
                else:
                    # ROLLBACK TO SAVEPOINT restores SET LOCAL
                    # state from before the savepoint —
                    # role and GUC both revert automatically.
                    cur.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")

    def seed(
        self,
        table: str,
        rows: list[dict[str, Any]],
    ) -> None:
        """Bulk-insert rows into `table` in the current (admin) context.

        All rows must have the same keys (the column set). Empty
        list is a no-op. Identifiers are double-quoted via
        `pgrls.fixers._idents.quote_ident`, so reserved keywords
        and mixed-case names are handled correctly.

        Schema-qualified table names work: pass `"app.invoices"`
        and the helper splits on the rightmost dot, quoting each
        segment independently (`app."invoices"`). pg_catalog
        rejects `.` in `nspname` and `relname` at CREATE time, so
        the rightmost-split is unambiguous for any name that
        could have come from real introspection. Names with more
        than one dot (e.g. `"db.schema.table"`) are rejected with
        a clear error — cross-database references aren't supported.

        For richer factory needs (sequencing, faker integration,
        post-insert hooks) use whatever Python factory framework
        the project already has — pgrls.testing intentionally
        ships a tiny seeder, not a factory framework.
        """
        from pgrls.fixers._idents import quote_ident, quote_qualified

        from pgrls.testing.errors import PgrlsTestError

        if not rows:
            return
        keys = list(rows[0].keys())
        key_set = set(keys)
        for i, row in enumerate(rows[1:], start=1):
            if set(row.keys()) != key_set:
                raise PgrlsTestError(
                    f"seed rows must all have the same keys; row "
                    f"0 has {sorted(key_set)!r}, row {i} has "
                    f"{sorted(row.keys())!r}"
                )
        cols = ", ".join(quote_ident(k) for k in keys)
        placeholders = ", ".join("%s" for _ in keys)
        # Right-split on `.` so a single dot means schema.table;
        # absent dot means an unqualified name in the current
        # search_path. Wrap quote_ident's bare ValueError into a
        # PgrlsTestError so the seed helper raises a uniform error
        # type ("`.foo`" → empty schema, "`foo.`" → empty table,
        # "" → empty whole-arg all surface here).
        try:
            if "." in table:
                if table.count(".") > 1:
                    raise PgrlsTestError(
                        f"seed: table name {table!r} contains more "
                        "than one dot. Cross-database table references "
                        "aren't supported — pass an unqualified name "
                        "(uses search_path) or a qualified "
                        "'schema.table'."
                    )
                schema_name, _, table_name = table.rpartition(".")
                quoted_table = quote_qualified(schema_name, table_name)
            else:
                quoted_table = quote_ident(table)
        except ValueError as exc:
            raise PgrlsTestError(
                f"seed: invalid table name {table!r}: {exc}"
            ) from exc
        sql = (
            f"INSERT INTO {quoted_table} ({cols}) "
            f"VALUES ({placeholders})"
        )
        values = [tuple(r[k] for k in keys) for r in rows]
        with self._conn.cursor() as cur:
            cur.executemany(sql, values)

    def assert_rows(self, sql: str, *, count: int) -> None:
        from pgrls.testing.assertions import assert_rows

        assert_rows(self._conn, sql, count=count)

    def assert_visible(self, sql: str) -> None:
        from pgrls.testing.assertions import assert_visible

        assert_visible(self._conn, sql)

    def assert_invisible(self, sql: str) -> None:
        from pgrls.testing.assertions import assert_invisible

        assert_invisible(self._conn, sql)

    def assert_rejected(self, sql: str) -> None:
        from pgrls.testing.assertions import assert_rejected

        assert_rejected(self._conn, sql)

    def assert_silently_dropped(self, sql: str) -> None:
        from pgrls.testing.assertions import assert_silently_dropped

        assert_silently_dropped(self._conn, sql)
