"""Unit tests for pgrls.testing.client.PgrlsTestClient."""
from __future__ import annotations

import json

import psycopg

from pgrls.testing.client import PgrlsTestClient


def test_client_constructor_takes_connection(
    testing_pg_conn: psycopg.Connection,
) -> None:
    # DI-style: tests construct directly with a connection. The
    # `connect(database_url)` factory wraps `psycopg.connect()`
    # and is exercised separately.
    client = PgrlsTestClient(testing_pg_conn)
    assert client is not None


def test_transaction_rolls_back_on_exit(
    testing_pg_conn: psycopg.Connection,
) -> None:
    # The whole point of the per-test transaction: anything
    # written inside it must not persist. Verify by inserting,
    # exiting the transaction, then re-querying outside.
    client = PgrlsTestClient(testing_pg_conn)
    with client.transaction():
        with testing_pg_conn.cursor() as cur:
            cur.execute(
                "INSERT INTO rls_widgets (owner, label) VALUES (%s, %s)",
                ("alice", "transient"),
            )
    with testing_pg_conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM rls_widgets")
        row = cur.fetchone()
    assert row is not None
    assert row[0] == 0


def test_transaction_rolls_back_on_exception(
    testing_pg_conn: psycopg.Connection,
) -> None:
    # If the test body raises, the transaction must still roll
    # back — pytest will see the exception, but no data should
    # leak.
    client = PgrlsTestClient(testing_pg_conn)
    try:
        with client.transaction():
            with testing_pg_conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO rls_widgets (owner) VALUES ('bob')"
                )
            raise RuntimeError("test failure")
    except RuntimeError:
        pass
    with testing_pg_conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM rls_widgets")
        row = cur.fetchone()
    assert row is not None
    assert row[0] == 0


def test_exec_runs_parameterized_sql(
    testing_pg_conn: psycopg.Connection,
) -> None:
    client = PgrlsTestClient(testing_pg_conn)
    with client.transaction():
        client.exec(
            "INSERT INTO rls_widgets (owner, label) VALUES (%s, %s)",
            params=("alice", "thing"),
        )
        with testing_pg_conn.cursor() as cur:
            cur.execute("SELECT owner, label FROM rls_widgets")
            row = cur.fetchone()
        assert row == ("alice", "thing")


def test_fetchall_returns_list_of_dicts(
    testing_pg_conn: psycopg.Connection,
) -> None:
    client = PgrlsTestClient(testing_pg_conn)
    with client.transaction():
        client.exec(
            "INSERT INTO rls_widgets (owner, label) VALUES "
            "('alice', 'a'), ('bob', 'b')"
        )
        rows = client.fetchall(
            "SELECT owner, label FROM rls_widgets ORDER BY owner"
        )
        assert rows == [
            {"owner": "alice", "label": "a"},
            {"owner": "bob", "label": "b"},
        ]


def test_fetchall_with_params(testing_pg_conn: psycopg.Connection) -> None:
    client = PgrlsTestClient(testing_pg_conn)
    with client.transaction():
        client.exec(
            "INSERT INTO rls_widgets (owner) VALUES ('alice'), ('bob')"
        )
        rows = client.fetchall(
            "SELECT owner FROM rls_widgets WHERE owner = %s",
            params=("alice",),
        )
        assert rows == [{"owner": "alice"}]


def test_fetchall_empty_result_returns_empty_list(
    testing_pg_conn: psycopg.Connection,
) -> None:
    client = PgrlsTestClient(testing_pg_conn)
    with client.transaction():
        rows = client.fetchall("SELECT owner FROM rls_widgets")
        assert rows == []


def test_as_role_switches_role_for_block(
    testing_pg_conn: psycopg.Connection,
) -> None:
    client = PgrlsTestClient(testing_pg_conn)
    with client.transaction():
        with client.as_role("pgrls_test_actor"):
            rows = client.fetchall("SELECT current_user AS u")
            assert rows == [{"u": "pgrls_test_actor"}]
        # Outside the block: back to admin (the connecting role).
        rows = client.fetchall("SELECT current_user AS u")
        assert rows[0]["u"] != "pgrls_test_actor"


def test_as_role_sets_jwt_claims_guc(
    testing_pg_conn: psycopg.Connection,
) -> None:
    client = PgrlsTestClient(testing_pg_conn)
    with client.transaction():
        with client.as_role(
            "pgrls_test_actor", claims={"sub": "alice", "role": "user"}
        ):
            rows = client.fetchall(
                "SELECT current_setting('request.jwt.claims', true) AS c"
            )
            assert rows[0]["c"] is not None
            parsed = json.loads(rows[0]["c"])
            assert parsed == {"sub": "alice", "role": "user"}


def test_as_role_filters_rows_by_claim(
    testing_pg_conn: psycopg.Connection,
) -> None:
    # The end-to-end shape: seed two rows, switch role + claim,
    # observe RLS-filtered visibility.
    client = PgrlsTestClient(testing_pg_conn)
    with client.transaction():
        client.exec(
            "INSERT INTO rls_widgets (owner) VALUES "
            "('alice'), ('bob')"
        )
        with client.as_role(
            "pgrls_test_actor", claims={"sub": "alice"}
        ):
            rows = client.fetchall("SELECT owner FROM rls_widgets")
            assert rows == [{"owner": "alice"}]


def test_as_role_unwinds_on_exception(
    testing_pg_conn: psycopg.Connection,
) -> None:
    # Exception inside the block must roll back the savepoint
    # AND reset the role, so the outer transaction sees a clean
    # admin context for any cleanup queries.
    client = PgrlsTestClient(testing_pg_conn)
    with client.transaction():
        try:
            with client.as_role("pgrls_test_actor"):
                raise RuntimeError("inside as_role")
        except RuntimeError:
            pass
        rows = client.fetchall("SELECT current_user AS u")
        assert rows[0]["u"] != "pgrls_test_actor"


def test_nested_as_role_blocks_dont_leak_claims(
    testing_pg_conn: psycopg.Connection,
) -> None:
    # Two sequential as_role blocks in the same test: claims set
    # by the first block must not bleed into the second's role
    # assertions.
    client = PgrlsTestClient(testing_pg_conn)
    with client.transaction():
        with client.as_role(
            "pgrls_test_actor", claims={"sub": "alice"}
        ):
            pass
        with client.as_role(
            "pgrls_test_actor", claims={"sub": "bob"}
        ):
            rows = client.fetchall(
                "SELECT current_setting('request.jwt.claims', true) AS c"
            )
            parsed = json.loads(rows[0]["c"])
            assert parsed["sub"] == "bob"


def test_nested_as_role_restores_outer_role_on_inner_clean_exit(
    testing_pg_conn: psycopg.Connection,
) -> None:
    # The inner as_role block must restore the outer role on
    # clean exit, not RESET to admin. Two nested actor switches:
    # outer runs as pgrls_test_actor with claim sub=alice, inner
    # runs as pgrls_test_actor with claim sub=bob, and after the
    # inner block exits the outer block must still see sub=alice.
    client = PgrlsTestClient(testing_pg_conn)
    with client.transaction():
        with client.as_role(
            "pgrls_test_actor", claims={"sub": "alice"}
        ):
            with client.as_role(
                "pgrls_test_actor", claims={"sub": "bob"}
            ):
                rows = client.fetchall(
                    "SELECT current_setting("
                    "'request.jwt.claims', true) AS c"
                )
                parsed = json.loads(rows[0]["c"])
                assert parsed["sub"] == "bob"
            # After inner exits: outer role + claims restored.
            rows = client.fetchall(
                "SELECT current_user AS u, current_setting("
                "'request.jwt.claims', true) AS c"
            )
            assert rows[0]["u"] == "pgrls_test_actor"
            parsed = json.loads(rows[0]["c"])
            assert parsed["sub"] == "alice"


def test_as_role_setup_exception_runs_cleanup(
    testing_pg_conn: psycopg.Connection,
) -> None:
    # If `claims` can't be JSON-encoded (e.g., contains a non-
    # string key), the helper must still leave the connection
    # in a clean state — savepoint rolled back, role reset.
    import pytest

    client = PgrlsTestClient(testing_pg_conn)
    with client.transaction():
        non_serializable = {object(): "x"}  # type: ignore[dict-item]
        with pytest.raises(TypeError):
            with client.as_role(
                "pgrls_test_actor", claims=non_serializable
            ):
                pass  # never reached
        # Connection still works after the failed setup.
        rows = client.fetchall("SELECT current_user AS u")
        assert rows[0]["u"] != "pgrls_test_actor"


def test_seed_inserts_rows_with_consistent_keys(
    testing_pg_conn: psycopg.Connection,
) -> None:
    client = PgrlsTestClient(testing_pg_conn)
    with client.transaction():
        client.seed(
            "rls_widgets",
            [
                {"owner": "alice", "label": "thing-a"},
                {"owner": "bob", "label": "thing-b"},
            ],
        )
        rows = client.fetchall(
            "SELECT owner, label FROM rls_widgets ORDER BY owner"
        )
        assert rows == [
            {"owner": "alice", "label": "thing-a"},
            {"owner": "bob", "label": "thing-b"},
        ]


def test_seed_empty_list_is_noop(
    testing_pg_conn: psycopg.Connection,
) -> None:
    client = PgrlsTestClient(testing_pg_conn)
    with client.transaction():
        client.seed("rls_widgets", [])
        rows = client.fetchall("SELECT count(*) AS n FROM rls_widgets")
        assert rows[0]["n"] == 0


def test_seed_rejects_inconsistent_keys() -> None:
    import pytest

    from pgrls.testing.errors import PgrlsTestError

    client = PgrlsTestClient.__new__(PgrlsTestClient)  # no DB needed
    client._conn = None  # type: ignore[assignment]
    with pytest.raises(PgrlsTestError, match="same keys"):
        client.seed(
            "rls_widgets",
            [{"owner": "alice"}, {"owner": "bob", "label": "x"}],
        )


def test_seed_quotes_table_and_column_identifiers(
    testing_pg_conn: psycopg.Connection,
) -> None:
    # `quote_ident` already handles mixed case and reserved
    # keywords (pinned in tests/test_fixers.py). Confirm the seed
    # helper uses it.
    with testing_pg_conn.cursor() as cur:
        cur.execute(
            'CREATE TABLE "Mixed Case Table" '
            '("From" TEXT, "To" TEXT)'
        )
    client = PgrlsTestClient(testing_pg_conn)
    with client.transaction():
        client.seed(
            "Mixed Case Table",
            [{"From": "a", "To": "b"}],
        )
        rows = client.fetchall(
            'SELECT "From", "To" FROM "Mixed Case Table"'
        )
        assert rows == [{"From": "a", "To": "b"}]


def test_seed_wraps_invalid_table_name_in_pgrls_test_error() -> None:
    # `.foo`, `foo.`, and `""` all hit `quote_ident("")` somewhere
    # inside the rpartition path. The bare `ValueError` from
    # `_idents.py` is wrapped into a `PgrlsTestError` so seed()'s
    # error shape is uniform with its other validation failures.
    import pytest

    from pgrls.testing.errors import PgrlsTestError

    client = PgrlsTestClient.__new__(PgrlsTestClient)  # no DB needed
    client._conn = None  # type: ignore[assignment]
    for bad in (".foo", "foo.", ""):
        with pytest.raises(
            PgrlsTestError, match="invalid table name"
        ):
            client.seed(bad, [{"x": 1}])


def test_seed_rejects_three_part_table_names() -> None:
    # rpartition on `"db.schema.table"` would yield
    # `("db.schema", ".", "table")` and produce
    # `INSERT INTO "db.schema"."table" ...`, which Postgres
    # rejects with a confusing `schema "db.schema" does not
    # exist`. Reject >2-part names explicitly so the error names
    # the actual problem (cross-database refs aren't supported).
    import pytest

    from pgrls.testing.errors import PgrlsTestError

    client = PgrlsTestClient.__new__(PgrlsTestClient)  # no DB needed
    client._conn = None  # type: ignore[assignment]
    with pytest.raises(PgrlsTestError, match="more than one dot"):
        client.seed("db.public.users", [{"x": 1}])


def test_seed_accepts_schema_qualified_table_name(
    testing_pg_conn: psycopg.Connection,
) -> None:
    # Pass `"schema.table"` and the helper splits on the
    # rightmost dot, quoting each segment independently. The
    # original v0.1 seed naively quoted the whole arg as one
    # identifier, which produced `"schema.table"` (a single
    # weird name) and failed with UndefinedTable. The split
    # is unambiguous because pg_catalog rejects `.` in nspname
    # and relname at CREATE time.
    with testing_pg_conn.cursor() as cur:
        cur.execute("CREATE SCHEMA seed_schema")
        cur.execute(
            "CREATE TABLE seed_schema.qualified_target ("
            "id BIGSERIAL PRIMARY KEY, label TEXT)"
        )
    client = PgrlsTestClient(testing_pg_conn)
    with client.transaction():
        client.seed(
            "seed_schema.qualified_target",
            [{"label": "alpha"}, {"label": "beta"}],
        )
        rows = client.fetchall(
            "SELECT label FROM seed_schema.qualified_target "
            "ORDER BY id"
        )
        assert rows == [{"label": "alpha"}, {"label": "beta"}]


def test_as_role_clean_exit_does_not_leak_inner_claims_when_outer_had_none(
    testing_pg_conn: psycopg.Connection,
) -> None:
    # When the outer scope had no claims and the inner block set
    # some, clean exit must NOT leave the inner claims visible to
    # the outer. (Postgres custom GUCs cannot truly return to NULL
    # once `set_config` has touched them in a session — they
    # collapse to the empty string. The contract this test pins is
    # that no JSON content remains, so a downstream policy doing
    # `::jsonb->>'sub'` on the empty string fails fast and visibly
    # rather than silently authorizing as the inner-block actor.)
    client = PgrlsTestClient(testing_pg_conn)
    with client.transaction():
        with client.as_role(
            "pgrls_test_actor", claims={"sub": "alice"}
        ):
            pass  # inner sets claims; clean exit
        rows = client.fetchall(
            "SELECT current_setting('request.jwt.claims', true) AS c"
        )
        # Either NULL (ideal) or empty string (Postgres reality on
        # touched custom GUCs) — both are acceptable; what matters
        # is the inner-block JSON does NOT survive into the outer
        # context.
        assert rows[0]["c"] in (None, ""), (
            f"inner claims leaked into outer scope: got "
            f"{rows[0]['c']!r}"
        )


def test_as_role_clean_exit_no_restore_when_neither_outer_nor_inner_set_claims(
    testing_pg_conn: psycopg.Connection,
) -> None:
    # Sanity check: when neither outer nor inner sets claims,
    # the helper makes no claims-related set_config call. The
    # GUC should remain NULL throughout.
    client = PgrlsTestClient(testing_pg_conn)
    with client.transaction():
        with client.as_role("pgrls_test_actor"):
            pass
        rows = client.fetchall(
            "SELECT current_setting('request.jwt.claims', true) AS c"
        )
        assert rows[0]["c"] is None


def test_as_role_with_explicit_empty_claims_sets_guc_to_empty_object(
    testing_pg_conn: psycopg.Connection,
) -> None:
    # Protocol-level distinction: claims=None skips set_config
    # entirely (no claims set); claims={} emits the call with
    # the literal '{}' JSON string (an actor whose JWT carries
    # no claims). The two are NOT equivalent — a refactor that
    # collapsed `if claims is not None:` to `if claims:` would
    # silently break the protocol.
    client = PgrlsTestClient(testing_pg_conn)
    with client.transaction():
        with client.as_role("pgrls_test_actor", claims={}):
            rows = client.fetchall(
                "SELECT current_setting('request.jwt.claims', true) AS c"
            )
            # Must be the literal '{}' JSON, not None or ''.
            assert rows[0]["c"] == "{}"
