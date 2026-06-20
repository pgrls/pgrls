"""Tests for the `pgrls mcp` server.

Most tests are OFFLINE — they call the MCP tool functions
(`pgrls.mcp.server.lint` / `verify` / `explain_rule` / `list_rules`) and the
`pgrls.mcp._schema_sources` helpers directly, with no live MCP client and no
database. The headline crux is the offline `sql=` analysis path: pgrls lints +
Z3-verifies raw DDL with no Postgres.

A few parity tests are gated behind `requires_docker` (the same marker
`test_probe.py` uses): they boot a throwaway Postgres, apply DDL, and assert the
`database_url=` path matches the `sql=` path.

The lazy-import test pins the headline safety property: importing `pgrls.cli`
(the normal CLI path) must NOT import `fastmcp`.
"""
from __future__ import annotations

import json
import subprocess
import sys

import pytest

from pgrls.mcp import server
from pgrls.mcp._schema_sources import (
    SchemaSourceError,
    resolve_schema,
    schema_from_sql,
)
from pgrls.rules import all_rules

# A SEC004 inverted-auth policy: the `auth.uid() IS NULL OR …` disjunct opens
# the table to an anonymous (un-authenticated) session — the flagship leak.
SEC004_DDL = """
CREATE TABLE public.docs (id uuid, tenant_id uuid, body text);
ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON public.docs FOR SELECT TO anon, authenticated
  USING (auth.uid() IS NULL OR tenant_id = auth.uid());
"""

# A clean tenant-scoped policy: anon can't read (auth.uid() is NULL → no row).
CLEAN_DDL = """
CREATE TABLE public.docs (id uuid, tenant_id uuid, body text);
ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON public.docs FOR SELECT TO authenticated
  USING (tenant_id = auth.uid());
"""


def _docker_available() -> bool:
    try:
        import docker  # noqa: PLC0415

        docker.from_env().ping()
        return True
    except Exception:
        return False


requires_docker = pytest.mark.skipif(
    not _docker_available(), reason="Docker not available for live introspection"
)


# --- catalog tools ---------------------------------------------------------


def test_list_rules_count_matches_registry() -> None:
    result = server.list_rules()
    assert result["count"] == len(list(all_rules()))
    assert result["count"] == len(result["rules"])
    # Every rule carries the documented fields.
    for entry in result["rules"]:
        assert set(entry) == {"id", "severity", "title", "fixable"}
    # Version is echoed (matches the package version).
    from pgrls import __version__

    assert result["pgrls_version"] == __version__


def test_explain_rule_known() -> None:
    result = server.explain_rule("SEC004")
    assert result["id"] == "SEC004"
    assert result["reference"]  # non-empty reference body
    assert set(result) == {"id", "severity", "title", "fixable", "reference"}


def test_explain_rule_case_insensitive() -> None:
    assert server.explain_rule("sec004")["id"] == "SEC004"


def test_explain_rule_unknown_is_structured_error() -> None:
    result = server.explain_rule("nope")
    assert result["error"]["kind"] == "unknown_rule"
    assert "nope" in result["error"]["message"]


# --- offline sql= crux (no DB) ---------------------------------------------


def test_lint_sql_flags_sec004() -> None:
    """The crux: lint raw inverted-auth DDL offline → SEC004 + SEC038."""
    result = server.lint(sql=SEC004_DDL)
    assert result["schema_source"] == "sql"
    ids = {v["rule_id"] for v in result["violations"]}
    assert "SEC004" in ids
    assert "SEC038" in ids
    # The sql= path must warn that absence-of-finding is not a proof.
    assert result["warnings"]
    assert any("NOT a proof" in w for w in result["warnings"])


def test_verify_sql_anon_leak() -> None:
    """The crux: verify the inverted-auth DDL offline → anon leak verdict."""
    result = server.verify(sql=SEC004_DDL, mode="anon")
    assert result["schema_source"] == "sql"
    assert result["mode"] == "anon"
    assert result["summary"]["leak"] == 1
    verdicts = {t["table"]: t["verdict"] for t in result["tables"]}
    assert verdicts["public.docs"] == "leak"


def test_lint_sql_clean_policy_no_sec004() -> None:
    result = server.lint(sql=CLEAN_DDL)
    ids = {v["rule_id"] for v in result["violations"]}
    assert "SEC004" not in ids


def test_verify_sql_clean_policy_anon_isolated() -> None:
    result = server.verify(sql=CLEAN_DDL, mode="anon")
    verdicts = {t["table"]: t["verdict"] for t in result["tables"]}
    assert verdicts["public.docs"] == "isolated"
    assert result["summary"]["isolated"] == 1


def test_in_membership_normalizes_to_canonical_form() -> None:
    # Regression (review CRITICAL #1): `col IN (auth.uid())` is an idiomatic
    # single-value membership form. pg_get_expr normalizes it to `col = …` (the
    # only shape the rules / Z3 encoder recognize), but the offline parse
    # preserved the raw `IN`, so verify under-claimed `unverified` and SEC038
    # went silent. The offline path must match a live DB.
    leak_ddl = (
        "CREATE TABLE public.docs (id uuid, tenant_id uuid);"
        "ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;"
        "CREATE POLICY p ON public.docs FOR SELECT TO authenticated "
        "  USING (auth.uid() IS NULL OR tenant_id IN (auth.uid()));"
    )
    verify_result = server.verify(sql=leak_ddl, mode="anon")
    assert verify_result["tables"][0]["verdict"] == "leak"  # not "unverified"
    ids = {v["rule_id"] for v in server.lint(sql=leak_ddl)["violations"]}
    assert "SEC038" in ids
    # A clean single-value-IN scoping must prove isolated (not under-claim).
    clean_ddl = (
        "CREATE TABLE public.acct (id uuid, tenant_id uuid);"
        "ALTER TABLE public.acct ENABLE ROW LEVEL SECURITY;"
        "CREATE POLICY p ON public.acct FOR SELECT TO authenticated "
        "  USING (tenant_id IN (auth.uid()));"
    )
    clean = server.verify(sql=clean_ddl, mode="cross-tenant")
    assert clean["tables"][0]["verdict"] == "isolated"


def test_column_grant_of_pii_to_low_trust_flags_sec045() -> None:
    # Regression (review CRITICAL #2): a column-level GRANT of a PII column to a
    # low-trust role is the exact SEC045 trigger. The offline builder dropped
    # column grants, so SEC045 was silent (a false-clean) AND it was not in the
    # catalog-only inert set, so no warning told the agent.
    ddl = (
        "CREATE TABLE public.users (id uuid, ssn text, tenant_id uuid);"
        "ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;"
        "CREATE POLICY p ON public.users FOR SELECT TO authenticated "
        "  USING (tenant_id = auth.uid());"
        "GRANT SELECT (ssn) ON public.users TO anon;"
    )
    ids = {v["rule_id"] for v in server.lint(sql=ddl)["violations"]}
    assert "SEC045" in ids


def test_schema_from_sql_maps_ddl_faithfully() -> None:
    """Regression net for the DDL→model mapping (the false-clean risk)."""
    schema = schema_from_sql(
        "CREATE TABLE public.docs (id uuid, tenant_id uuid, amount numeric(10,2));"
        "ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;"
        "ALTER TABLE public.docs FORCE ROW LEVEL SECURITY;"
        "CREATE POLICY p ON public.docs AS RESTRICTIVE FOR INSERT TO authenticated "
        "  WITH CHECK (tenant_id = auth.uid());"
        "GRANT SELECT, INSERT ON public.docs TO anon;"
    )
    assert len(schema.tables) == 1
    table = schema.tables[0]
    assert table.qualified_name == "public.docs"
    assert table.rls_enabled is True
    assert table.force_rls is True
    # Columns + their data types are captured (numeric(10,2) round-trips).
    types = {c.name: c.data_type for c in table.column_details}
    assert types == {"id": "uuid", "tenant_id": "uuid", "amount": "numeric(10, 2)"}
    # The policy: command, AS RESTRICTIVE, roles, and a populated WITH CHECK AST.
    policy = table.policies[0]
    assert policy.command == "INSERT"
    assert policy.permissive is False
    assert policy.roles == ("authenticated",)
    assert policy.with_check_sql is not None
    assert policy.with_check_ast is not None
    # The GRANT attaches with both privileges.
    grant = table.grants[0]
    assert grant.role == "anon"
    assert set(grant.privileges) == {"SELECT", "INSERT"}


def test_schema_from_sql_unqualified_defaults_public() -> None:
    schema = schema_from_sql("CREATE TABLE docs (id int);")
    assert schema.tables[0].schema == "public"


def test_schema_from_sql_grant_all_expands() -> None:
    schema = schema_from_sql(
        "CREATE TABLE public.t (id int);"
        "GRANT ALL ON public.t TO anon;"
    )
    grant = schema.tables[0].grants[0]
    # `GRANT ALL` expands to the privilege set aclexplode would materialize.
    assert "SELECT" in grant.privileges
    assert "DELETE" in grant.privileges


def test_schema_from_sql_skips_unknown_statements() -> None:
    """Tolerant walk: an unmodeled statement must not raise — just be skipped."""
    schema = schema_from_sql(
        "CREATE TABLE public.t (id int);"
        "CREATE INDEX idx ON public.t (id);"  # unmodeled — skipped
        "CREATE FUNCTION f() RETURNS int LANGUAGE sql AS 'SELECT 1';"  # skipped
        "GRANT SELECT ON ALL TABLES IN SCHEMA public TO anon;"  # skipped (not a table object)
    )
    assert len(schema.tables) == 1
    # The ALL-IN-SCHEMA grant is not attached to the table (it's not a direct
    # GRANT ON <table>).
    assert schema.tables[0].grants == ()


def test_schema_from_sql_policy_before_table() -> None:
    """A policy/grant preceding its CREATE TABLE still attaches (two-pass walk)."""
    schema = schema_from_sql(
        "CREATE POLICY p ON public.t FOR SELECT USING (tenant_id = auth.uid());"
        "CREATE TABLE public.t (id int, tenant_id uuid);"
        "ALTER TABLE public.t ENABLE ROW LEVEL SECURITY;"
    )
    table = schema.tables[0]
    assert len(table.policies) == 1
    assert table.policies[0].using_ast is not None


# --- snapshot path (AST re-parse trap) -------------------------------------


def test_snapshot_path_reparses_asts(tmp_path) -> None:
    """The no-AST snapshot trap: verify must work after the re-parse.

    A snapshot serializes only using_sql (not the AST). Without re-parsing,
    verify returns all-`unverified`. The resolver must rebuild the ASTs so
    verify gives a real verdict.
    """
    snap = schema_from_sql(CLEAN_DDL).to_snapshot()
    path = tmp_path / "snap.json"
    path.write_text(json.dumps(snap), encoding="utf-8")

    schema, source = resolve_schema(snapshot=str(path))
    assert source == "snapshot"
    # ASTs were rebuilt on load.
    assert schema.tables[0].policies[0].using_ast is not None

    # lint works.
    lint_result = server.lint(snapshot=str(path))
    assert lint_result["schema_source"] == "snapshot"
    # snapshot path sees the full catalog → no sql-only caveat warnings.
    assert lint_result["warnings"] == []

    # verify gives a real verdict (NOT unverified — the trap).
    verify_result = server.verify(snapshot=str(path), mode="anon")
    verdicts = {t["table"]: t["verdict"] for t in verify_result["tables"]}
    assert verdicts["public.docs"] == "isolated"
    assert verify_result["summary"]["unverified"] == 0


# --- schema-source guards --------------------------------------------------


def test_zero_sources_is_structured_error() -> None:
    result = server.lint()
    assert result["error"]["kind"] == "no_schema_source"


def test_multiple_sources_is_structured_error() -> None:
    result = server.lint(sql="CREATE TABLE t (id int);", snapshot="/tmp/x.json")
    assert result["error"]["kind"] == "multiple_schema_sources"


def test_malformed_sql_is_structured_error_not_raise() -> None:
    # Must NOT raise — returns a structured bad_sql error.
    result = server.lint(sql="CREATE TABLE (((;")
    assert result["error"]["kind"] == "bad_sql"


def test_verify_malformed_sql_is_structured_error() -> None:
    result = server.verify(sql="this is not sql", mode="anon")
    assert result["error"]["kind"] == "bad_sql"


def test_verify_bad_mode_is_structured_error() -> None:
    result = server.verify(sql="CREATE TABLE t (id int);", mode="bogus")
    assert result["error"]["kind"] == "bad_sql"


def test_lint_unknown_rule_filter_is_structured_error() -> None:
    result = server.lint(sql="CREATE TABLE t (id int);", rules=["SEC999"])
    assert result["error"]["kind"] == "unknown_rule"


def test_lint_min_severity_filters() -> None:
    # error-only should drop the warning/info findings.
    result = server.lint(sql=SEC004_DDL, min_severity="error")
    assert all(v["severity"] == "error" for v in result["violations"])
    # ...and SEC004 (error) survives the filter.
    assert any(v["rule_id"] == "SEC004" for v in result["violations"])


def test_lint_rule_filter_restricts() -> None:
    result = server.lint(sql=SEC004_DDL, rules=["SEC004"])
    ids = {v["rule_id"] for v in result["violations"]}
    assert ids == {"SEC004"}


def test_resolve_schema_zero_sources_raises_typed() -> None:
    with pytest.raises(SchemaSourceError) as exc:
        resolve_schema()
    assert exc.value.kind == "no_schema_source"


def test_resolve_schema_multiple_sources_raises_typed() -> None:
    with pytest.raises(SchemaSourceError) as exc:
        resolve_schema(sql="CREATE TABLE t (id int);", database_url="postgres://x")
    assert exc.value.kind == "multiple_schema_sources"


# --- lazy-import isolation (the headline safety pin) ------------------------


def test_importing_cli_does_not_import_fastmcp() -> None:
    """Importing `pgrls.cli` must NOT pull in fastmcp (keeps the CLI slim)."""
    # Use a fresh subprocess so a prior in-process import of fastmcp (this test
    # module imports `pgrls.mcp.server`, which imports fastmcp) can't mask a
    # leak — the assertion must hold in a clean interpreter.
    code = (
        "import sys; import pgrls.cli; "
        "assert 'fastmcp' not in sys.modules, 'fastmcp leaked into pgrls.cli'; "
        "print('ok')"
    )
    proc = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True
    )
    assert proc.returncode == 0, proc.stderr
    assert "ok" in proc.stdout


def test_run_stdio_is_importable() -> None:
    from pgrls.mcp.server import run_stdio

    assert callable(run_stdio)


# --- Docker-gated parity: sql= path matches database_url= path -------------

_AUTH_STUB = (
    "CREATE SCHEMA IF NOT EXISTS auth;"
    "CREATE OR REPLACE FUNCTION auth.uid() RETURNS uuid LANGUAGE sql STABLE AS "
    "$$ SELECT NULLIF(current_setting('request.jwt.claim.sub', true), '')::uuid $$;"
)

_LIVE_SEC004_DDL = (
    "CREATE TABLE public.docs (id uuid, tenant_id uuid, body text);"
    "ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;"
    "CREATE POLICY p ON public.docs FOR SELECT TO PUBLIC "
    "  USING (auth.uid() IS NULL OR tenant_id = auth.uid());"
)


@requires_docker
def test_database_url_path_matches_sql_path(pg_url: str) -> None:
    """Apply the SEC004 DDL to a live DB; lint/verify(database_url=) must agree
    with lint/verify(sql=) on the headline finding/verdict."""
    import psycopg

    with psycopg.connect(pg_url, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute("DROP TABLE IF EXISTS public.docs CASCADE;")
            cur.execute(_AUTH_STUB)
            cur.execute(_LIVE_SEC004_DDL)

    try:
        live_lint = server.lint(database_url=pg_url)
        assert live_lint["schema_source"] == "database_url"
        # database_url path sees the full catalog → no sql-only caveat warnings.
        assert live_lint["warnings"] == []
        live_ids = {v["rule_id"] for v in live_lint["violations"]}
        assert "SEC004" in live_ids

        live_verify = server.verify(database_url=pg_url, mode="anon")
        live_verdicts = {t["table"]: t["verdict"] for t in live_verify["tables"]}
        assert live_verdicts["public.docs"] == "leak"

        # Same headline conclusions on the offline sql= path.
        sql_ids = {v["rule_id"] for v in server.lint(sql=SEC004_DDL)["violations"]}
        assert "SEC004" in sql_ids
        sql_verify = server.verify(sql=SEC004_DDL, mode="anon")
        sql_verdicts = {t["table"]: t["verdict"] for t in sql_verify["tables"]}
        assert sql_verdicts["public.docs"] == "leak"
    finally:
        with psycopg.connect(pg_url, autocommit=True) as conn:
            with conn.cursor() as cur:
                cur.execute("DROP TABLE IF EXISTS public.docs CASCADE;")


def test_database_url_error_is_sanitized() -> None:
    """A bad database_url must return db_unreachable WITHOUT echoing the DSN.

    No Docker needed — this connects to a refused port so psycopg raises, and
    the point is that the sanitized message never contains the credentials.
    """
    secret_url = "postgresql://user:SUPERSECRET@127.0.0.1:1/nonexistent"
    result = server.lint(database_url=secret_url)
    assert result["error"]["kind"] == "db_unreachable"
    # The credential must never appear in the returned message.
    assert "SUPERSECRET" not in result["error"]["message"]
    assert secret_url not in result["error"]["message"]
