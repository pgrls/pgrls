"""Run the cross-language conformance manifest with the Python client.

Same fixture set a future TS / Go port runs against. Each case in
`manifest.json` becomes a parametrized pytest case here.
"""
from __future__ import annotations

import json
from pathlib import Path

import psycopg
import pytest

from pgrls.testing.client import PgrlsTestClient

PROTOCOL_DIR = Path(__file__).parent
MANIFEST = json.loads(
    (PROTOCOL_DIR / "manifest.json").read_text(encoding="utf-8")
)


@pytest.fixture
def conformance_pg_conn(
    pg_conn: psycopg.Connection,
) -> psycopg.Connection:
    # Apply schema + seed in admin context. Per-test transaction
    # rollback (driven by PgrlsTestClient.transaction()) below
    # unwinds the per-case writes; schema is reset by the parent
    # `pg_conn` fixture between top-level tests.
    #
    # Resolve fixture paths via the manifest's `fixture` block —
    # not by hard-coding `schema.sql` / `seed.sql` — so a TS / Go
    # port mirrors the same indirection the Python reference
    # runner uses, and renaming the SQL files only requires the
    # manifest update.
    schema_sql = (
        PROTOCOL_DIR / MANIFEST["fixture"]["schema"]
    ).read_text(encoding="utf-8")
    seed_sql = (
        PROTOCOL_DIR / MANIFEST["fixture"]["seed"]
    ).read_text(encoding="utf-8")
    with pg_conn.cursor() as cur:
        cur.execute("DROP ROLE IF EXISTS pgrls_protocol_actor")
        cur.execute(schema_sql)
        cur.execute(seed_sql)
    yield pg_conn
    # Cleanup: drop policy-bearing table first (its policy
    # references the role and would otherwise block DROP ROLE),
    # then REVOKE remaining grants and DROP ROLE so the role
    # doesn't leak into the next pytest session (cluster-global).
    with pg_conn.cursor() as cur:
        cur.execute("DROP TABLE IF EXISTS protocol_invoices CASCADE")
        cur.execute(
            "REVOKE ALL ON ALL TABLES IN SCHEMA public FROM "
            "pgrls_protocol_actor"
        )
        cur.execute(
            "REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM "
            "pgrls_protocol_actor"
        )
        cur.execute(
            "REVOKE ALL ON SCHEMA public FROM pgrls_protocol_actor"
        )
        cur.execute("DROP ROLE IF EXISTS pgrls_protocol_actor")


def test_manifest_protocol_version_is_1() -> None:
    assert MANIFEST["protocol_version"] == 1


def test_manifest_matches_published_schema() -> None:
    # Hand-rolled validation against `manifest.schema.json` so a TS
    # or Go port writing its own runner can rely on the same
    # structural invariants the Python runner depends on. Avoids
    # pulling `jsonschema` as a hard dependency just for one test.
    schema = json.loads(
        (PROTOCOL_DIR / "manifest.schema.json").read_text(
            encoding="utf-8"
        )
    )
    assert schema["properties"]["protocol_version"]["const"] == 1
    valid_kinds = set(
        schema["$defs"]["case"]["properties"]["kind"]["enum"]
    )
    fetchall_kinds = {"fetchall"}
    assert_kinds = valid_kinds - fetchall_kinds

    # Top-level keys.
    assert set(MANIFEST.keys()) == {
        "protocol_version",
        "fixture",
        "cases",
    }
    assert set(MANIFEST["fixture"].keys()) == {"schema", "seed"}

    # Per-case shape.
    case_required = {"name", "role", "claims", "kind", "sql"}
    case_optional = {"expect"}
    for case in MANIFEST["cases"]:
        keys = set(case.keys())
        assert case_required.issubset(keys), (
            f"case {case.get('name', '?')!r} missing required keys: "
            f"{case_required - keys}"
        )
        assert keys.issubset(case_required | case_optional), (
            f"case {case.get('name', '?')!r} has unknown keys: "
            f"{keys - case_required - case_optional}"
        )
        assert case["kind"] in valid_kinds, (
            f"case {case['name']!r}: unknown kind {case['kind']!r}"
        )
        # `expect` is required for fetchall and forbidden for asserts.
        if case["kind"] in fetchall_kinds:
            assert "expect" in case, (
                f"case {case['name']!r}: 'fetchall' requires 'expect'"
            )
        if case["kind"] in assert_kinds:
            assert "expect" not in case, (
                f"case {case['name']!r}: '{case['kind']}' must not "
                "carry 'expect'"
            )
        # `claims` is null or a JSON object.
        assert case["claims"] is None or isinstance(
            case["claims"], dict
        )

    # Case names must be unique — duplicates produce ambiguous
    # pytest parametrize ids and one case's pass/fail masks the
    # other's. JSON Schema can't express this directly; we assert
    # it here.
    names = [case["name"] for case in MANIFEST["cases"]]
    assert len(names) == len(set(names)), (
        "manifest case names must be unique; got duplicates: "
        f"{[n for n in names if names.count(n) > 1]}"
    )


@pytest.mark.parametrize(
    "case",
    MANIFEST["cases"],
    ids=[c["name"] for c in MANIFEST["cases"]],
)
def test_protocol_case(
    conformance_pg_conn: psycopg.Connection,
    case: dict,
) -> None:
    client = PgrlsTestClient(conformance_pg_conn)
    with client.transaction():
        with client.as_role(case["role"], claims=case["claims"]):
            kind = case["kind"]
            sql = case["sql"]
            if kind == "fetchall":
                rows = client.fetchall(sql)
                assert rows == case["expect"], (
                    f"case {case['name']!r}: expected "
                    f"{case['expect']!r}, got {rows!r}"
                )
            elif kind == "assert_visible":
                client.assert_visible(sql)
            elif kind == "assert_invisible":
                client.assert_invisible(sql)
            elif kind == "assert_rejected":
                client.assert_rejected(sql)
            elif kind == "assert_silently_dropped":
                client.assert_silently_dropped(sql)
            else:
                pytest.fail(
                    f"unknown manifest kind {kind!r} in case "
                    f"{case['name']!r}"
                )
