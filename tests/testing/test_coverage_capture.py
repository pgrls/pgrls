"""Live-DB tests for the coverage capture wired into PgrlsTestClient.

The pytest plugin attaches the capture sink in production; here we attach
a list sink directly and drive the client against the session
testcontainer, asserting the recorded `(schema, relation, role, command)`
tuples.
"""
from __future__ import annotations

import psycopg

from pgrls.coverage import ExercisedTuple
from pgrls.testing.client import PgrlsTestClient


def _capturing_client(conn: psycopg.Connection) -> tuple[PgrlsTestClient, list]:
    client = PgrlsTestClient(conn)
    captured: list[ExercisedTuple] = []
    client._coverage_sink = captured.extend
    return client, captured


def test_capture_records_select_under_actor_role(
    testing_pg_conn: psycopg.Connection,
) -> None:
    client, captured = _capturing_client(testing_pg_conn)
    with client.transaction():
        client.seed("rls_widgets", [{"owner": "alice"}, {"owner": "bob"}])
        with client.as_role("pgrls_test_actor", claims={"sub": "alice"}):
            client.assert_rows("SELECT id FROM rls_widgets", count=1)
            client.assert_invisible(
                "SELECT id FROM rls_widgets WHERE owner = 'bob'"
            )
    # seed runs as admin and is NOT captured; only the two SELECTs under
    # the actor role are. Schema is None (unqualified table in the SQL).
    assert ExercisedTuple(None, "rls_widgets", "pgrls_test_actor", "SELECT") in captured
    assert all(t.command == "SELECT" for t in captured)
    assert all(t.role == "pgrls_test_actor" for t in captured)


def test_capture_records_write_command(
    testing_pg_conn: psycopg.Connection,
) -> None:
    client, captured = _capturing_client(testing_pg_conn)
    with client.transaction():
        with client.as_role(
            "pgrls_test_actor", claims={"sub": "alice", "role": "user"}
        ):
            # Permissive INSERT policy on rls_audit accepts this.
            client.exec(
                "INSERT INTO rls_audit (actor, event) VALUES ('alice', 'x')"
            )
    assert (
        ExercisedTuple(None, "rls_audit", "pgrls_test_actor", "INSERT")
        in captured
    )


def test_capture_role_outside_block_is_connection_role(
    testing_pg_conn: psycopg.Connection,
) -> None:
    client, captured = _capturing_client(testing_pg_conn)
    with client.transaction():
        client.fetchall("SELECT id FROM rls_widgets")
    # One SELECT, recorded under the connecting (admin) role, not the actor.
    assert len(captured) == 1
    assert captured[0].relation == "rls_widgets"
    assert captured[0].command == "SELECT"
    assert captured[0].role != "pgrls_test_actor"
    assert captured[0].role  # non-empty


def test_no_capture_without_sink(
    testing_pg_conn: psycopg.Connection,
) -> None:
    # Default client (no plugin) captures nothing and never errors.
    client = PgrlsTestClient(testing_pg_conn)
    with client.transaction():
        assert client.fetchall("SELECT 1 AS x") == [{"x": 1}]
