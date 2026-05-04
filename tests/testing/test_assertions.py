"""Unit tests for row-count assertion helpers."""
from __future__ import annotations

import psycopg
import pytest

from pgrls.testing.client import PgrlsTestClient
from pgrls.testing.errors import PgrlsTestAssertionError


def test_assert_rows_passes_on_exact_count(
    testing_pg_conn: psycopg.Connection,
) -> None:
    client = PgrlsTestClient(testing_pg_conn)
    with client.transaction():
        client.exec(
            "INSERT INTO rls_widgets (owner) VALUES "
            "('a'), ('b'), ('c')"
        )
        client.assert_rows("SELECT * FROM rls_widgets", count=3)


def test_assert_rows_fails_on_wrong_count(
    testing_pg_conn: psycopg.Connection,
) -> None:
    client = PgrlsTestClient(testing_pg_conn)
    with client.transaction():
        client.exec("INSERT INTO rls_widgets (owner) VALUES ('a')")
        with pytest.raises(PgrlsTestAssertionError, match="expected 5"):
            client.assert_rows("SELECT * FROM rls_widgets", count=5)


def test_assert_visible_passes_when_at_least_one_row(
    testing_pg_conn: psycopg.Connection,
) -> None:
    client = PgrlsTestClient(testing_pg_conn)
    with client.transaction():
        client.exec("INSERT INTO rls_widgets (owner) VALUES ('a')")
        client.assert_visible("SELECT * FROM rls_widgets")


def test_assert_visible_fails_on_zero_rows(
    testing_pg_conn: psycopg.Connection,
) -> None:
    client = PgrlsTestClient(testing_pg_conn)
    with client.transaction():
        with pytest.raises(
            PgrlsTestAssertionError, match="expected at least 1"
        ):
            client.assert_visible("SELECT * FROM rls_widgets")


def test_assert_invisible_passes_on_zero_rows(
    testing_pg_conn: psycopg.Connection,
) -> None:
    client = PgrlsTestClient(testing_pg_conn)
    with client.transaction():
        client.assert_invisible("SELECT * FROM rls_widgets")


def test_assert_invisible_fails_when_any_rows(
    testing_pg_conn: psycopg.Connection,
) -> None:
    client = PgrlsTestClient(testing_pg_conn)
    with client.transaction():
        client.exec("INSERT INTO rls_widgets (owner) VALUES ('a')")
        with pytest.raises(
            PgrlsTestAssertionError, match="expected 0"
        ):
            client.assert_invisible("SELECT * FROM rls_widgets")


def test_row_count_assertions_under_role_switch(
    testing_pg_conn: psycopg.Connection,
) -> None:
    # End-to-end shape: seed in admin, switch role + claim,
    # assert visibility filters per RLS policy.
    client = PgrlsTestClient(testing_pg_conn)
    with client.transaction():
        client.seed(
            "rls_widgets",
            [{"owner": "alice"}, {"owner": "bob"}],
        )
        with client.as_role(
            "pgrls_test_actor", claims={"sub": "alice"}
        ):
            client.assert_rows(
                "SELECT * FROM rls_widgets", count=1
            )
            client.assert_visible(
                "SELECT * FROM rls_widgets WHERE owner='alice'"
            )
            client.assert_invisible(
                "SELECT * FROM rls_widgets WHERE owner='bob'"
            )


def test_assert_rejected_passes_on_rls_violation(
    testing_pg_conn: psycopg.Connection,
) -> None:
    # As pgrls_test_actor with sub="alice", inserting a row
    # owned by "bob" violates the WITH CHECK and Postgres raises
    # InsufficientPrivilege (SQLSTATE 42501).
    client = PgrlsTestClient(testing_pg_conn)
    with client.transaction():
        with client.as_role(
            "pgrls_test_actor", claims={"sub": "alice"}
        ):
            client.assert_rejected(
                "INSERT INTO rls_widgets (owner) VALUES ('bob')"
            )


def test_assert_rejected_fails_when_query_succeeds(
    testing_pg_conn: psycopg.Connection,
) -> None:
    client = PgrlsTestClient(testing_pg_conn)
    with client.transaction():
        with client.as_role(
            "pgrls_test_actor", claims={"sub": "alice"}
        ):
            with pytest.raises(
                PgrlsTestAssertionError,
                match="expected RLS rejection",
            ):
                client.assert_rejected(
                    "INSERT INTO rls_widgets (owner) VALUES ('alice')"
                )


def test_assert_rejected_fails_on_other_error_class(
    testing_pg_conn: psycopg.Connection,
) -> None:
    # A SYNTAX error (SQLSTATE 42601, SyntaxError) is NOT an RLS
    # rejection. The helper must distinguish — otherwise a typo
    # in test SQL would silently pass `assert_rejected`.
    client = PgrlsTestClient(testing_pg_conn)
    with client.transaction():
        with pytest.raises(
            PgrlsTestAssertionError,
            match="expected InsufficientPrivilege",
        ):
            client.assert_rejected("THIS IS NOT VALID SQL")


def test_assert_rejected_does_not_corrupt_outer_transaction(
    testing_pg_conn: psycopg.Connection,
) -> None:
    # The savepoint inside assert_rejected must isolate the
    # failed query from the outer transaction. After a successful
    # assert_rejected, subsequent SQL in the same test must
    # continue to work.
    client = PgrlsTestClient(testing_pg_conn)
    with client.transaction():
        client.exec(
            "INSERT INTO rls_widgets (owner) VALUES ('alice')"
        )
        with client.as_role(
            "pgrls_test_actor", claims={"sub": "alice"}
        ):
            client.assert_rejected(
                "INSERT INTO rls_widgets (owner) VALUES ('bob')"
            )
        # After rejection, admin context still works.
        rows = client.fetchall(
            "SELECT count(*) AS n FROM rls_widgets"
        )
        assert rows[0]["n"] == 1


def test_assert_silently_dropped_passes_when_returning_empty(
    testing_pg_conn: psycopg.Connection,
) -> None:
    # Seed an audit row as admin. Then as actor with a non-admin
    # claim, UPDATE ... RETURNING finds zero rows because the
    # UPDATE policy's USING (admin-only) silently filters them
    # out — that's "silently dropped". (INSERT ... RETURNING
    # would raise "new row violates RLS" instead; UPDATE/DELETE
    # are the operations that actually silently drop.)
    client = PgrlsTestClient(testing_pg_conn)
    with client.transaction():
        client.exec(
            "INSERT INTO rls_audit (actor, event) "
            "VALUES ('alice', 'logged-in')"
        )
        with client.as_role(
            "pgrls_test_actor",
            claims={"sub": "alice", "role": "user"},
        ):
            client.assert_silently_dropped(
                "UPDATE rls_audit SET event = 'modified' "
                "RETURNING id"
            )


def test_assert_silently_dropped_fails_when_returning_has_rows(
    testing_pg_conn: psycopg.Connection,
) -> None:
    # As admin (role='admin' claim), the UPDATE policy admits
    # the row. RETURNING returns 1 row. The helper must fail.
    client = PgrlsTestClient(testing_pg_conn)
    with client.transaction():
        client.exec(
            "INSERT INTO rls_audit (actor, event) "
            "VALUES ('admin', 'review')"
        )
        with client.as_role(
            "pgrls_test_actor",
            claims={"sub": "admin", "role": "admin"},
        ):
            with pytest.raises(
                PgrlsTestAssertionError,
                match="expected RETURNING to yield 0 rows",
            ):
                client.assert_silently_dropped(
                    "UPDATE rls_audit SET event = 'reviewed' "
                    "RETURNING id"
                )


def test_assert_silently_dropped_rejects_sql_without_returning(
    testing_pg_conn: psycopg.Connection,
) -> None:
    # The helper checks RETURNING's row count; SQL without
    # RETURNING gives no signal. The implementation gates on the
    # statement verb first (UPDATE/DELETE only), so an INSERT
    # raises with the verb-mismatch message rather than running
    # to the fetchall path.
    from pgrls.testing.errors import PgrlsTestError

    client = PgrlsTestClient(testing_pg_conn)
    with client.transaction():
        with pytest.raises(PgrlsTestError, match="UPDATE|DELETE"):
            client.assert_silently_dropped(
                "INSERT INTO rls_audit (actor, event) "
                "VALUES ('a', 'b')"
            )


def test_assert_silently_dropped_rejects_select(
    testing_pg_conn: psycopg.Connection,
) -> None:
    # SELECT produces a result set whether or not it returns rows.
    # Without a verb gate, a typo'd test like
    # `assert_silently_dropped("SELECT * FROM t WHERE 1=0")` would
    # silently pass with zero rows even though no RLS-aware DML
    # ran. Pin the verb-check rejection so the false-pass shape
    # can't regress.
    from pgrls.testing.errors import PgrlsTestError

    client = PgrlsTestClient(testing_pg_conn)
    with client.transaction():
        with pytest.raises(PgrlsTestError, match="SELECT"):
            client.assert_silently_dropped(
                "SELECT id FROM rls_audit WHERE 1 = 0"
            )


def test_assert_silently_dropped_passes_on_update_returning_empty(
    testing_pg_conn: psycopg.Connection,
) -> None:
    # The happy path: an UPDATE … RETURNING that hits no rows (the
    # silent-drop shape) passes cleanly under the new verb-gate.
    client = PgrlsTestClient(testing_pg_conn)
    with client.transaction():
        client.assert_silently_dropped(
            "UPDATE rls_audit SET actor = 'x' "
            "WHERE actor = 'never-exists' RETURNING id"
        )


def test_assert_silently_dropped_string_literal_returning_falls_through_verb_gate(
    testing_pg_conn: psycopg.Connection,
) -> None:
    # An INSERT carrying the word RETURNING inside a string literal
    # used to slip past a regex pre-check and surface a confusing
    # psycopg error from fetchall() later. The current verb-gate
    # rejects it cleanly because the statement verb is INSERT, not
    # UPDATE/DELETE — the test pins the verb-rejection path so the
    # earlier shape can't regress.
    from pgrls.testing.errors import PgrlsTestError

    client = PgrlsTestClient(testing_pg_conn)
    with client.transaction():
        with client.as_role(
            "pgrls_test_actor", claims={"sub": "alice"}
        ):
            # No actual RETURNING; the literal 'returning'
            # would have falsely passed the regex check.
            with pytest.raises(PgrlsTestError, match="RETURNING"):
                client.assert_silently_dropped(
                    "INSERT INTO rls_widgets (owner, label) "
                    "VALUES ('alice', 'returning visit')"
                )
