"""Unit + CLI tests for `pgrls generate` (no live DB; see test_generate_e2e)."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from pgrls.cli import main
from pgrls.generate import GenerateOptions, plan_generation, session_predicate
from pgrls.model import Column, Policy, Schema, Table


def _table(
    name: str,
    columns: tuple[Column, ...],
    *,
    policies: tuple[Policy, ...] = (),
    rls: bool = False,
    force: bool = False,
    schema: str = "public",
) -> Table:
    return Table(
        schema=schema,
        name=name,
        rls_enabled=rls,
        force_rls=force,
        policies=policies,
        columns=tuple(c.name for c in columns),
        column_details=columns,
    )


_ID = Column("id", "uuid", is_nullable=False)
_TID = Column("tenant_id", "uuid", is_nullable=False)


# ---------- session_predicate ----------


def test_predicate_app_guc_default_with_cast() -> None:
    p = session_predicate("tenant_id", "uuid", GenerateOptions())
    assert p == "tenant_id = (SELECT current_setting('app.tenant_id', true)::uuid)"


def test_predicate_postgrest_convention() -> None:
    p = session_predicate(
        "tenant_id", "uuid", GenerateOptions(convention="postgrest")
    )
    assert (
        p
        == "tenant_id = (SELECT current_setting('request.jwt.claim.tenant_id', true)::uuid)"
    )


def test_predicate_text_column_omits_cast() -> None:
    p = session_predicate("org", "text", GenerateOptions())
    assert p == "org = (SELECT current_setting('app.org', true))"


def test_predicate_explicit_setting_name_and_bigint_cast() -> None:
    p = session_predicate(
        "org_id", "bigint", GenerateOptions(setting_name="app.current_org")
    )
    assert p == "org_id = (SELECT current_setting('app.current_org', true)::bigint)"


def test_predicate_escapes_quote_in_setting_name() -> None:
    p = session_predicate(
        "c", "text", GenerateOptions(setting_name="weird'name")
    )
    assert "(SELECT current_setting('weird''name', true))" in p


# ---------- owner model ----------

_UID = Column("user_id", "uuid", is_nullable=False)


def test_predicate_owner_app_guc() -> None:
    p = session_predicate(
        "user_id", "uuid", GenerateOptions(model="owner")
    )
    assert p == "user_id = (SELECT current_setting('app.user_id', true)::uuid)"


def test_predicate_owner_postgrest_uses_sub_claim() -> None:
    p = session_predicate(
        "user_id", "uuid", GenerateOptions(model="owner", convention="postgrest")
    )
    assert (
        p == "user_id = (SELECT current_setting('request.jwt.claim.sub', true)::uuid)"
    )


def test_predicate_owner_supabase_uses_auth_uid() -> None:
    p = session_predicate(
        "user_id", "uuid", GenerateOptions(model="owner", convention="supabase")
    )
    assert p == "user_id = (SELECT auth.uid())"


def test_predicate_supabase_custom_auth_function_quoted() -> None:
    p = session_predicate(
        "user_id",
        "uuid",
        GenerateOptions(model="owner", convention="supabase", auth_function="auth.user_id"),
    )
    assert p == "user_id = (SELECT auth.user_id())"


def test_predicate_supabase_unqualified_auth_function() -> None:
    # An --auth-function with NO schema qualifier (no dot) takes the
    # bare-name branch: quote_ident the single component, no schema
    # prefix. `uid` → `(SELECT uid())`.
    p = session_predicate(
        "user_id",
        "uuid",
        GenerateOptions(model="owner", convention="supabase", auth_function="uid"),
    )
    assert p == "user_id = (SELECT uid())"


def test_predicate_supabase_unqualified_auth_function_needs_quoting() -> None:
    # A bare auth-function name that is a reserved word / mixed-case must
    # be quoted by quote_ident on the bare-name branch — proving the
    # branch routes through quote_ident, not a raw splice.
    p = session_predicate(
        "user_id",
        "uuid",
        GenerateOptions(model="owner", convention="supabase", auth_function="User"),
    )
    assert p == 'user_id = (SELECT "User"())'


def test_owner_model_uses_owner_policy_names() -> None:
    schema = Schema(tables=(_table("posts", (_ID, _UID)),))
    opts = GenerateOptions(model="owner", tenant_column="user_id", convention="supabase")
    sqls = "\n".join(f.sql for f in plan_generation(schema, opts).statements)
    assert "CREATE POLICY posts_owner_isolation ON public.posts" in sqls
    assert "posts_owner_floor" in sqls
    assert "tenant" not in sqls  # no tenant-model naming leaked
    assert "user_id = (SELECT auth.uid())" in sqls


def test_owner_via_table_override_and_no_restrictive() -> None:
    # Owner model + explicit --table column override + supabase + no floor,
    # all at once.
    ownercol = Column("creator_id", "uuid", is_nullable=False)
    schema = Schema(tables=(_table("docs", (_ID, ownercol)),))
    opts = GenerateOptions(
        model="owner",
        restrictive=False,
        convention="supabase",
        tables=(("public", "docs", "creator_id"),),
    )
    sqls = "\n".join(f.sql for f in plan_generation(schema, opts).statements)
    assert "CREATE POLICY docs_owner_isolation ON public.docs" in sqls
    assert "creator_id = (SELECT auth.uid())" in sqls
    assert "AS RESTRICTIVE" not in sqls and "docs_owner_floor" not in sqls
    assert "CREATE INDEX ON public.docs (creator_id)" in sqls


def test_cli_supabase_requires_owner_model() -> None:
    res = _run(Schema(tables=()), ["--convention", "supabase"])  # default model=tenant
    assert res.exit_code == 2
    assert "supabase is for --model owner" in res.output


def test_cli_model_owner_defaults_to_user_id_column() -> None:
    # Auto-detect uses user_id (not tenant_id) under --model owner.
    schema = Schema(
        tables=(
            _table("posts", (_ID, _UID)),  # has user_id
            _table("orgs", (_ID, _TID)),   # has tenant_id (not a target in owner mode)
        )
    )
    res = _run(schema, ["--model", "owner"])
    assert res.exit_code == 0, res.output
    assert "CREATE POLICY posts_owner_isolation" in res.output
    assert "orgs" not in res.output  # tenant_id table not auto-detected in owner mode


# ---------- plan_generation: targeting ----------


def test_auto_detect_emits_full_setup() -> None:
    schema = Schema(tables=(_table("posts", (_ID, _TID)),))
    sqls = [f.sql for f in plan_generation(schema, GenerateOptions()).statements]
    joined = "\n".join(sqls)
    assert "ENABLE ROW LEVEL SECURITY" in joined
    assert "FORCE ROW LEVEL SECURITY" in joined
    assert "CREATE POLICY posts_tenant_isolation ON public.posts" in joined
    assert "AS RESTRICTIVE" in joined  # the floor
    assert "CREATE INDEX ON public.posts (tenant_id)" in joined


def test_skip_already_policied_table_with_reason() -> None:
    pol = Policy("p", "ALL", True, ("authenticated",), "true", None)
    schema = Schema(tables=(_table("posts", (_ID, _TID), policies=(pol,)),))
    result = plan_generation(schema, GenerateOptions())
    assert result.statements == ()
    assert result.skipped == (
        ("public.posts", "already has policies — refine with `pgrls lint` / `fix`"),
    )


def test_table_without_discriminator_is_ignored() -> None:
    schema = Schema(tables=(_table("logs", (_ID,)),))
    result = plan_generation(schema, GenerateOptions())
    assert result.statements == ()
    assert result.skipped == ()


def test_explicit_table_override_for_nonconventional_column() -> None:
    orgcol = Column("org_id", "bigint", is_nullable=False)
    schema = Schema(tables=(_table("orgs", (_ID, orgcol)),))
    opts = GenerateOptions(tables=(("public", "orgs", "org_id"),))
    sqls = "\n".join(f.sql for f in plan_generation(schema, opts).statements)
    assert "org_id = (SELECT current_setting('app.org_id', true)::bigint)" in sqls
    assert "CREATE INDEX ON public.orgs (org_id)" in sqls


def test_explicit_table_not_found_is_reported() -> None:
    schema = Schema(tables=(_table("posts", (_ID, _TID)),))
    opts = GenerateOptions(tables=(("public", "ghost", "org_id"),))
    result = plan_generation(schema, opts)
    assert ("public.ghost", "table not found in scanned schemas") in result.skipped


def test_partition_child_skipped_parent_targeted() -> None:
    # A partitioned parent gets the full setup; its children are skipped
    # (the parent's index cascades and RLS on it covers parent-routed
    # queries), so no per-child duplicate index is emitted.
    parent = _table("events", (_ID, _TID))  # partition_of is None
    child = Table(
        schema="public",
        name="events_2026",
        rls_enabled=False,
        force_rls=False,
        policies=(),
        columns=("id", "tenant_id"),
        column_details=(_ID, _TID),
        partition_of=("public", "events"),
    )
    result = plan_generation(Schema(tables=(parent, child)), GenerateOptions())
    sqls = "\n".join(f.sql for f in result.statements)
    # Parent set up (incl. its cascading index); no statement touches the child.
    assert "CREATE INDEX ON public.events (tenant_id)" in sqls
    assert "events_2026" not in sqls
    # Child reported as skipped, pointing at the parent.
    assert any(
        q == "public.events_2026" and "partition of public.events" in r
        for q, r in result.skipped
    )


def test_partition_skip_message_names_root_for_multilevel() -> None:
    # root → mid → leaf. Only the root is generated; both mid and leaf are
    # skipped and their reason names the ROOT (the table that gets the RLS),
    # not the immediate parent (which is itself a skipped child).
    root = _table("events", (_ID, _TID))  # partition_of is None
    mid = Table(
        schema="public", name="events_2026", rls_enabled=False, force_rls=False,
        policies=(), columns=("id", "tenant_id"), column_details=(_ID, _TID),
        partition_of=("public", "events"),
    )
    leaf = Table(
        schema="public", name="events_2026_q1", rls_enabled=False, force_rls=False,
        policies=(), columns=("id", "tenant_id"), column_details=(_ID, _TID),
        partition_of=("public", "events_2026"),
    )
    result = plan_generation(Schema(tables=(root, mid, leaf)), GenerateOptions())
    reasons = dict(result.skipped)
    # Trailing space distinguishes "public.events " from "public.events_2026".
    assert "partition of public.events " in reasons["public.events_2026"]
    assert "partition of public.events " in reasons["public.events_2026_q1"]
    assert "CREATE INDEX ON public.events (tenant_id)" in "\n".join(
        f.sql for f in result.statements
    )


def test_explicit_table_targeting_partition_child_is_skipped() -> None:
    child = Table(
        schema="public",
        name="events_2026",
        rls_enabled=False,
        force_rls=False,
        policies=(),
        columns=("id", "tenant_id"),
        column_details=(_ID, _TID),
        partition_of=("public", "events"),
    )
    opts = GenerateOptions(tables=(("public", "events_2026", "tenant_id"),))
    result = plan_generation(Schema(tables=(child,)), opts)
    assert result.statements == ()
    assert any(
        q == "public.events_2026" and "partition of public.events" in r
        for q, r in result.skipped
    )


def test_no_restrictive_omits_floor() -> None:
    schema = Schema(tables=(_table("posts", (_ID, _TID)),))
    sqls = "\n".join(
        f.sql for f in plan_generation(schema, GenerateOptions(restrictive=False)).statements
    )
    assert "AS RESTRICTIVE" not in sqls
    assert "posts_tenant_floor" not in sqls
    assert "posts_tenant_isolation" in sqls


def test_role_override_in_policy() -> None:
    schema = Schema(tables=(_table("posts", (_ID, _TID)),))
    sqls = "\n".join(
        f.sql for f in plan_generation(schema, GenerateOptions(role="app_user")).statements
    )
    assert "TO app_user" in sqls


def test_nullable_discriminator_emits_note() -> None:
    nullable_tid = Column("tenant_id", "uuid", is_nullable=True)
    schema = Schema(tables=(_table("posts", (_ID, nullable_tid)),))
    result = plan_generation(schema, GenerateOptions())
    assert result.statements  # still generates
    assert any("nullable" in n and "SET NOT NULL" in n for n in result.notes)


def test_idempotent_when_only_partial_state_missing() -> None:
    # RLS already on+forced, but no policies → still generate policies+index,
    # and DON'T re-emit ENABLE/FORCE.
    schema = Schema(tables=(_table("posts", (_ID, _TID), rls=True, force=True),))
    rule_ids = [f.rule_id for f in plan_generation(schema, GenerateOptions()).statements]
    assert "SEC001" not in rule_ids and "SEC002" not in rule_ids
    assert rule_ids.count("RLS") == 2  # permissive + floor
    assert "PERF003" in rule_ids


# ---------- CLI (mocked introspection) ----------


def _run(schema: Schema, args: list[str]):
    cm = MagicMock()
    cm.__enter__.return_value = MagicMock()
    cm.__exit__.return_value = False
    with patch("pgrls.cli.psycopg.connect", return_value=cm), patch(
        "pgrls.cli.introspect", return_value=schema
    ):
        return CliRunner().invoke(
            main, ["generate", "--database-url", "postgresql://x", *args]
        )


def test_cli_dry_run_prints_sql_and_skips() -> None:
    pol = Policy("p", "ALL", True, ("authenticated",), "true", None)
    schema = Schema(
        tables=(
            _table("posts", (_ID, _TID)),
            _table("locked", (_ID, _TID), policies=(pol,)),
        )
    )
    res = _run(schema, [])
    assert res.exit_code == 0, res.output
    assert "CREATE POLICY posts_tenant_isolation" in res.output
    assert "skipped public.locked" in res.output
    assert "dry-run" in res.output


def test_cli_output_and_apply_rejected() -> None:
    res = _run(Schema(tables=()), ["--output", "/tmp/x.sql", "--apply"])
    assert res.exit_code == 2
    assert "cannot be combined" in res.output


def test_cli_bad_table_flag() -> None:
    res = _run(Schema(tables=()), ["--table", "no-colon"])
    assert res.exit_code == 2
    assert "schema.table:column" in res.output


def test_cli_config_and_dburl_errors_precede_bad_table(
    tmp_path, monkeypatch
) -> None:
    # generate() must surface a config-parse error and a missing-db-url
    # error BEFORE a bad --table syntax error — matching the pre-refactor
    # order (config-parse, db-url-missing, then --table). Pins the
    # precedence so the connect/introspect preamble dedup cannot silently
    # reorder which of several simultaneous user errors surfaces first
    # (the generate() analogue of
    # test_fix_bad_toml_precedes_unknown_rule). _run() always injects
    # --database-url, so this exercises the omitted combination directly.
    monkeypatch.delenv("DATABASE_URL", raising=False)
    runner = CliRunner()

    # (1) malformed --config + bad --table → the config-parse error wins.
    bad = tmp_path / "pgrls.toml"
    bad.write_text("[database\n")  # malformed TOML
    res = runner.invoke(
        main, ["generate", "--config", str(bad), "--table", "no-colon"]
    )
    assert res.exit_code == 2, res.output
    assert "schema.table:column" not in res.output  # not the --table error
    assert "Traceback" not in res.output

    # (2) valid --config, no db-url, bad --table → the db-url error wins.
    good = tmp_path / "good.toml"
    good.write_text("")  # valid (empty) config
    res = runner.invoke(
        main, ["generate", "--config", str(good), "--table", "no-colon"]
    )
    assert res.exit_code == 2, res.output
    assert "No database connection" in res.output
    assert "schema.table:column" not in res.output


def test_cli_nothing_to_generate() -> None:
    res = _run(Schema(tables=(_table("logs", (_ID,)),)), [])
    assert res.exit_code == 0
    assert "nothing to generate" in res.output


def test_cli_output_writes_file_and_force_guard(tmp_path) -> None:
    schema = Schema(tables=(_table("posts", (_ID, _TID)),))
    out = tmp_path / "rls.sql"
    res = _run(schema, ["--output", str(out)])
    assert res.exit_code == 0, res.output
    text = out.read_text()
    assert "CREATE POLICY posts_tenant_isolation" in text
    # Second write without --force is rejected.
    res2 = _run(schema, ["--output", str(out)])
    assert res2.exit_code == 2
    assert "already exists" in res2.output
    # With --force it overwrites.
    res3 = _run(schema, ["--output", str(out), "--force"])
    assert res3.exit_code == 0, res3.output
