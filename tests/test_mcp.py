"""Tests for the `pgrls mcp` server.

Most tests are OFFLINE — they call the MCP tool functions
(`pgrls.mcp.server.lint` / `verify` / `explain_rule` / `list_rules`) and the
`pgrls.schema_sources` helpers directly, with no live MCP client and no
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
from pgrls.model import SNAPSHOT_VERSION
from pgrls.schema_sources import (
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
    # went silent. The offline path must match a live DB. `TO PUBLIC` so the
    # anon leak is genuinely reachable (a `TO authenticated` policy the anon
    # session cannot invoke is soundly abstained offline — see the anon role
    # gate — which would mask the IN-normalization this test pins).
    leak_ddl = (
        "CREATE TABLE public.docs (id uuid, tenant_id uuid);"
        "ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;"
        "CREATE POLICY p ON public.docs FOR SELECT TO PUBLIC "
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


def test_verify_anon_roles_gates_a_custom_anon_role() -> None:
    # A project whose anonymous role is not named `anon` (PostgREST's `web_anon`)
    # must be able to tell verify so — else a `TO web_anon` inverted-auth leak is
    # mis-proven (offline: soundly abstained; a live DB: false `isolated`). The
    # `anon_roles` param threads it, mirroring `[lint.rules.SEC004].anon_roles`.
    leak_ddl = (
        "CREATE TABLE public.docs (id uuid, tenant_id uuid);"
        "ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;"
        "CREATE POLICY p ON public.docs FOR SELECT TO web_anon "
        "  USING (auth.uid() IS NULL OR tenant_id = auth.uid());"
    )
    # Default {anon, PUBLIC}: `web_anon` is not anon-reachable and the sql source
    # carries no role graph → the leak is soundly abstained, never guessed.
    default = server.verify(sql=leak_ddl, mode="anon")
    assert default["tables"][0]["verdict"] == "unverified"
    # Naming `web_anon` the anon role proves the leak.
    named = server.verify(sql=leak_ddl, mode="anon", anon_roles=["web_anon"])
    assert named["tables"][0]["verdict"] == "leak"
    # A malformed anon_roles is a clean structured error, not a crash.
    bad = server.verify(sql=leak_ddl, mode="anon", anon_roles="web_anon")  # type: ignore[arg-type]
    assert bad["error"]


def test_verify_accepts_escalation_mode() -> None:
    # Regression (0.47.0): the CLI grew a fourth `escalation` threat model, but
    # the MCP verify() mode allowlist still rejected it. build_verification
    # already dispatches escalation -> build_escalation, so the tool only needs
    # to let it through. An `sql` source carries no role graph, so escalation
    # finds nothing — but it must return a clean payload, not a bad_sql error.
    ddl = (
        "CREATE TABLE public.docs (id uuid, tenant_id uuid);"
        "ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;"
        "CREATE POLICY p ON public.docs FOR SELECT TO authenticated "
        "  USING (tenant_id = auth.uid());"
    )
    result = server.verify(sql=ddl, mode="escalation")
    assert result["mode"] == "escalation"
    assert result["summary"]["tables"] == 0
    # A genuinely unknown mode is still rejected, now naming all four.
    bad = server.verify(sql=ddl, mode="bogus")
    assert bad["error"]["kind"] == "bad_sql"
    assert "escalation" in bad["error"]["message"]


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


def test_column_grants_merge_per_role_column_like_introspection() -> None:
    # Two separate GRANT (col) statements on the same (role, column) must merge
    # into one ColumnGrant with unioned privileges — as introspection groups
    # them — so SEC045 reports one finding per exposed column, not one per
    # GRANT statement.
    schema = schema_from_sql(
        "CREATE TABLE public.users (id uuid, ssn text);"
        "GRANT SELECT (ssn) ON public.users TO anon;"
        "GRANT UPDATE (ssn) ON public.users TO anon;"
    )
    table = schema.tables[0]
    ssn_grants = [g for g in table.column_grants if g.column == "ssn"]
    assert len(ssn_grants) == 1
    assert set(ssn_grants[0].privileges) == {"SELECT", "UPDATE"}


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

    schema, source, version = resolve_schema(snapshot=str(path))
    assert source == "snapshot"
    assert version == SNAPSHOT_VERSION
    # ASTs were rebuilt on load.
    assert schema.tables[0].policies[0].using_ast is not None

    # lint works.
    lint_result = server.lint(snapshot=str(path))
    assert lint_result["schema_source"] == "snapshot"
    # snapshot path warns conservatively (catalog fields may be absent in older snapshots).
    assert any("snapshot" in w.lower() for w in lint_result["warnings"])

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


# --- fix / generate tools (EMIT-ONLY remediation) --------------------------

# A schema with several mechanically-fixable findings: RLS enabled but not
# FORCE'd (SEC002), an inverted-auth SEC004 disjunct, a missing WITH CHECK on
# the permissive FOR ALL policy (SEC006), and no index on the discriminator.
_FIXABLE_DDL = """
CREATE TABLE public.t (id int, tenant_id int);
ALTER TABLE public.t ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON public.t FOR ALL TO authenticated
  USING (auth.uid() IS NULL OR tenant_id = 1);
"""

# Bare multi-tenant tables with no row security — the `generate` target shape.
_BARE_TENANT_DDL = (
    "CREATE TABLE public.posts (id uuid, tenant_id uuid NOT NULL, body text);"
)


def test_fix_sql_emits_narrowing_remediation() -> None:
    """The crux: fix returns SQL that closes the offline findings, emit-only."""
    result = server.fix(sql=_FIXABLE_DDL)
    assert result["schema_source"] == "sql"
    assert result["count"] == len(result["fixes"]) > 0
    ids = {f["rule_id"] for f in result["fixes"]}
    # The flagship inverted-auth strip is among the emitted fixes.
    assert "SEC004" in ids
    for f in result["fixes"]:
        assert set(f) == {"rule_id", "location", "sql", "description"}
        assert f["sql"].strip()
    # The migration bundles the statements as a copy-pasteable .sql file.
    assert result["migration"].startswith("--")
    # sql= path warns that an empty result is not a proof of clean.
    assert any("NOT a proof" in w for w in result["warnings"])


def test_fix_rule_filter_restricts() -> None:
    result = server.fix(sql=_FIXABLE_DDL, rules=["SEC004"])
    assert {f["rule_id"] for f in result["fixes"]} == {"SEC004"}


def test_fix_exclude_rules_drops_a_rule() -> None:
    result = server.fix(sql=_FIXABLE_DDL, exclude_rules=["SEC004"])
    ids = {f["rule_id"] for f in result["fixes"]}
    assert "SEC004" not in ids
    assert ids  # other fixable findings remain


def test_fix_nothing_to_fix_has_empty_migration() -> None:
    # SEC004 does not fire on the clean policy → no fixes, empty migration.
    result = server.fix(sql=CLEAN_DDL, rules=["SEC004"])
    assert result["count"] == 0
    assert result["fixes"] == []
    assert result["migration"] == ""


def test_fix_unknown_rule_filter_is_structured_error() -> None:
    result = server.fix(sql=_FIXABLE_DDL, rules=["SEC999"])
    assert result["error"]["kind"] == "unknown_rule"


def test_fix_zero_sources_is_structured_error() -> None:
    assert server.fix()["error"]["kind"] == "no_schema_source"


def test_fix_never_executes_only_emits() -> None:
    # Emit-only contract: a bad DSN means introspection is *attempted* (and
    # fails cleanly), never a mutation — the same db_unreachable lint returns,
    # with the credential scrubbed.
    secret = "postgresql://u:TOPSECRET@127.0.0.1:1/none"
    result = server.fix(database_url=secret)
    assert result["error"]["kind"] == "db_unreachable"
    assert "TOPSECRET" not in result["error"]["message"]


def test_generate_sql_scaffolds_gold_standard() -> None:
    result = server.generate(sql=_BARE_TENANT_DDL)
    assert result["schema_source"] == "sql"
    assert result["count"] == len(result["statements"]) > 0
    sqls = [s["sql"] for s in result["statements"]]
    assert any("FORCE ROW LEVEL SECURITY" in s for s in sqls)
    assert any(
        "current_setting('app.tenant_id'" in s for s in sqls
    ), sqls
    # Restrictive floor is emitted by default.
    assert any("AS RESTRICTIVE" in s for s in sqls)
    # Never scaffolds a PUBLIC policy (would trip SEC003).
    assert not any("TO PUBLIC" in s for s in sqls)
    assert result["migration"].startswith("--")


def test_generate_postgrest_convention_uses_jwt_claim() -> None:
    result = server.generate(sql=_BARE_TENANT_DDL, convention="postgrest")
    sqls = [s["sql"] for s in result["statements"]]
    assert any("request.jwt.claim.tenant_id" in s for s in sqls), sqls


def test_generate_skips_already_policied_table() -> None:
    # A table that already has a policy is reported in `skipped`, never
    # clobbered, and produces no statements.
    result = server.generate(sql=CLEAN_DDL)
    assert result["count"] == 0
    assert any("public.docs" in s["table"] for s in result["skipped"])


def test_generate_table_override_uses_named_column() -> None:
    ddl = "CREATE TABLE public.orders (id uuid, org_id uuid NOT NULL);"
    result = server.generate(sql=ddl, tables=["public.orders:org_id"])
    sqls = [s["sql"] for s in result["statements"]]
    assert any("org_id" in s for s in sqls), sqls


def test_generate_bad_model_is_structured_error() -> None:
    result = server.generate(sql=_BARE_TENANT_DDL, model="nope")
    assert result["error"]["kind"] == "bad_sql"


def test_generate_bad_convention_is_structured_error() -> None:
    result = server.generate(sql=_BARE_TENANT_DDL, convention="nope")
    assert result["error"]["kind"] == "bad_sql"


def test_generate_supabase_with_tenant_model_is_rejected() -> None:
    # Parity with the CLI: `supabase` is an owner-model convention; pairing it
    # with the (default) tenant model would scaffold silently-wrong RLS.
    result = server.generate(sql=_BARE_TENANT_DDL, convention="supabase")
    assert result["error"]["kind"] == "bad_sql"
    assert "owner" in result["error"]["message"]


def test_generate_owner_model_defaults_user_id_column() -> None:
    # The discriminator column defaults to user_id for the owner model.
    ddl = "CREATE TABLE public.notes (id uuid, user_id uuid NOT NULL);"
    result = server.generate(sql=ddl, model="owner", convention="supabase")
    assert result["count"] > 0
    sqls = [s["sql"] for s in result["statements"]]
    assert any("user_id = (SELECT auth.uid())" in s for s in sqls), sqls


def test_generate_zero_sources_is_structured_error() -> None:
    assert server.generate()["error"]["kind"] == "no_schema_source"


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


def test_mcp_warnings_name_every_inert_rule():
    from pgrls.schema_sources import inert_rule_ids, schema_source_warnings
    text = " ".join(schema_source_warnings("sql"))
    for rid in inert_rule_ids("sql"):
        assert rid in text
