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
