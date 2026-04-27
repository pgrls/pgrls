"""Demo tests: run pgrls against the 15-use-case fixture.

Each test maps to one use case in `setup.sql` and asserts the rule
that case demonstrates either fires (for violation cases) or stays
silent (for clean cases). Read top-to-bottom as a guided tour of
what pgrls catches.

Run modes:
- `pytest demo/test_demo.py` (default): spin up a fresh Postgres via
  testcontainers and apply `setup.sql`.
- `DATABASE_URL=... pytest demo/test_demo.py`: apply `setup.sql` to
  an existing DB (e.g. the one started by `demo/run.sh`).
"""
from __future__ import annotations

import os
from collections.abc import Generator
from pathlib import Path

import psycopg
import pytest
from click.testing import CliRunner
from testcontainers.postgres import PostgresContainer

from pgrls.cli import main

DEMO_DIR = Path(__file__).parent
SETUP_SQL = DEMO_DIR / "setup.sql"
PGRLS_TOML = DEMO_DIR / "pgrls.toml"

_ALL_RULE_IDS = (
    "SEC001",
    "SEC002",
    "SEC003",
    "SEC004",
    "SEC005",
    "SEC006",
    "SEC007",
    "SEC008",
    "PERF001",
    "HYG001",
)


def _apply_setup(url: str) -> None:
    # psycopg3 / libpq supports multi-statement execute when there
    # are no parameters. This avoids hand-rolling a SQL splitter
    # that has to know about `--` line comments, `/* */` block
    # comments, single-quoted strings, and double-quoted identifiers.
    sql = SETUP_SQL.read_text()
    with psycopg.connect(url, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(sql)


@pytest.fixture(scope="module")
def demo_db() -> Generator[str, None, None]:
    """A connection URL with the demo fixture applied."""
    existing = os.environ.get("DATABASE_URL")
    if existing:
        _apply_setup(existing)
        yield existing
        return
    with PostgresContainer(
        "postgres:16-alpine",
        username="demo",
        password="demo",
        dbname="demo",
    ) as pg:
        url = pg.get_connection_url(driver=None)
        _apply_setup(url)
        yield url


@pytest.fixture(scope="module")
def lint_output(demo_db: str) -> str:
    runner = CliRunner()
    # The demo's pgrls.toml uses `database.url = "$DATABASE_URL"` to
    # show the env-var-expansion path. Set DATABASE_URL on the
    # invocation so config loading succeeds; --database-url still
    # overrides for the actual connection.
    result = runner.invoke(
        main,
        [
            "lint",
            "--database-url",
            demo_db,
            "--config",
            str(PGRLS_TOML),
        ],
        env={"DATABASE_URL": demo_db},
    )
    return result.output


# ============================================================
# Use case 01 — clean tenant table (no rule fires)
# ============================================================

def test_uc01_clean_tenant_table_passes_all_rules(
    lint_output: str,
) -> None:
    # Substring "X  app.documents" matches both the table-level
    # location and the policy-level location (`app.documents.tenant_isolation`).
    # Either kind of fire is unacceptable for the canonical clean
    # example.
    for rule_id in _ALL_RULE_IDS:
        line = f"{rule_id}  app.documents"
        assert line not in lint_output, (
            f"{rule_id} unexpectedly fired on app.documents:\n"
            f"{lint_output}"
        )


# ============================================================
# Use case 02 — reference table allowlisted
# ============================================================

def test_uc02_reference_table_silenced_by_allowlist(
    lint_output: str,
) -> None:
    # `app.countries` has no RLS but is in the SEC001 allowlist.
    assert "SEC001  app.countries" not in lint_output


# ============================================================
# Use cases 03-12 — one rule per case
# ============================================================

def test_uc03_missing_rls_fires_sec001(lint_output: str) -> None:
    assert "SEC001  app.legacy_orders\n" in lint_output


def test_uc04_missing_force_fires_sec002(lint_output: str) -> None:
    assert "SEC002  app.notes\n" in lint_output


def test_uc05_permissive_public_fires_sec003(lint_output: str) -> None:
    assert "SEC003  app.posts.everyone_reads\n" in lint_output


def test_uc06_inverted_auth_fires_sec004(lint_output: str) -> None:
    assert "SEC004  app.accounts.allow_unset_user\n" in lint_output


def test_uc07_session_state_only_fires_sec005(lint_output: str) -> None:
    assert "SEC005  app.singletons.admin_only\n" in lint_output


def test_uc08_update_without_with_check_fires_sec006(
    lint_output: str,
) -> None:
    assert "SEC006  app.invoices.update_without_check\n" in lint_output


def test_uc09_all_permissive_fires_sec007(lint_output: str) -> None:
    assert "SEC007  app.tags\n" in lint_output


def test_uc10_using_true_fires_sec008(lint_output: str) -> None:
    assert "SEC008  app.feature_flags.public_flags\n" in lint_output


def test_uc11_unwrapped_auth_fires_perf001(lint_output: str) -> None:
    assert "PERF001  app.messages.messages_owner\n" in lint_output


def test_uc12_orphaned_column_fires_hyg001(lint_output: str) -> None:
    assert "HYG001  app.comments.archived_filter\n" in lint_output


# ============================================================
# Use cases 13-15 — partition-aware paths
# ============================================================

def test_uc13_partitioned_parent_with_rls_keeps_all_silent(
    lint_output: str,
) -> None:
    # Parent has RLS; SEC001 walks each child's chain and finds
    # the RLS-enabled root, suppressing the child violation.
    # Neither parent nor any child should fire.
    for table in ("app.events", "app.events_2025", "app.events_2026"):
        assert f"SEC001  {table}\n" not in lint_output, (
            f"SEC001 unexpectedly fired on {table}"
        )


def test_uc14_cross_schema_partition_emits_unscoped_message(
    lint_output: str,
) -> None:
    # Parent in `private` (not in pgrls.toml `schemas`); child in
    # `app`. SEC001 fires on the child with the differentiated
    # "leaves the scanned schemas" message.
    assert "SEC001  app.audit_log_2026\n" in lint_output
    assert "leaves the scanned schemas" in lint_output


def test_uc15_visible_root_partition_message_names_the_root(
    lint_output: str,
) -> None:
    # Both parent and child are in scope and lack RLS. Parent
    # gets the classic message; child gets the visible-root
    # variant naming the parent.
    assert "SEC001  app.bare_metrics\n" in lint_output
    assert "SEC001  app.bare_metrics_2026\n" in lint_output
    assert "is a partition of app.bare_metrics" in lint_output


# ============================================================
# Use cases 16-22 — additional clean and rule-variant patterns
# ============================================================

def test_uc16_correlated_exists_membership_clean(
    lint_output: str,
) -> None:
    # The C2 fix scenario: a correlated EXISTS that references the
    # outer table's column via correlation. Before the fix, SEC005
    # falsely fired here because exclude_sublinks=True discarded
    # the correlated own-col ref. The demo pins it as clean.
    for rule_id in _ALL_RULE_IDS:
        line = f"{rule_id}  app.team_documents"
        assert line not in lint_output, (
            f"{rule_id} unexpectedly fired on app.team_documents"
        )


def test_uc17_asymmetric_using_with_check_clean(
    lint_output: str,
) -> None:
    # Read team's tickets, write only your own. USING and WITH
    # CHECK do different things by design; pgrls accepts that.
    for rule_id in _ALL_RULE_IDS:
        line = f"{rule_id}  app.tickets"
        assert line not in lint_output, (
            f"{rule_id} unexpectedly fired on app.tickets"
        )


def test_uc18_soft_delete_pattern_clean(lint_output: str) -> None:
    # `deleted_at IS NULL` is a column-IS-NULL test, not an
    # `auth_func() IS NULL` — SEC004 must distinguish them.
    for rule_id in _ALL_RULE_IDS:
        line = f"{rule_id}  app.users_v2"
        assert line not in lint_output, (
            f"{rule_id} unexpectedly fired on app.users_v2"
        )


def test_uc19_supabase_auth_uid_inverted_fires_sec004(
    lint_output: str,
) -> None:
    assert "SEC004  app.profiles.allow_anon\n" in lint_output


def test_uc20_supabase_auth_uid_unwrapped_fires_perf001(
    lint_output: str,
) -> None:
    assert "PERF001  app.todos.todos_owner\n" in lint_output


def test_uc21_perf001_silent_when_auth_only_in_with_check(
    lint_output: str,
) -> None:
    # Pins the USING-only contract: `auth.uid()` in WITH CHECK
    # alone must NOT trigger PERF001. A future regression
    # extending the rule to WITH CHECK breaks this test loudly.
    assert (
        "PERF001  app.audit_inserts.insert_self_only" not in lint_output
    )


def test_uc22_hyg001_fires_on_orphan_in_with_check(
    lint_output: str,
) -> None:
    # The dropped column is referenced only in WITH CHECK. Pins
    # that HYG001 walks both clauses, not just USING.
    assert "HYG001  app.posts_v2.only_approved_writes\n" in lint_output


# ============================================================
# Use cases 23-24 — extra partition shapes
# ============================================================

def test_uc23_three_level_partition_with_rls_root_silent(
    lint_output: str,
) -> None:
    # Sub-partitioning: deep_events -> deep_events_t1 ->
    # deep_events_t1_2026. RLS only on the root, but SEC001's
    # iterative ancestor walk reaches it from any depth.
    for table in (
        "app.deep_events",
        "app.deep_events_t1",
        "app.deep_events_t1_2026",
    ):
        assert f"SEC001  {table}\n" not in lint_output, (
            f"SEC001 unexpectedly fired on {table}"
        )


def test_uc24_partition_leaf_rls_only_fires_on_parent(
    lint_output: str,
) -> None:
    # Parent bare, leaf has its own RLS. Pin the asymmetry —
    # SEC001 must fire on the parent (no RLS there, no ancestor
    # to cover it) but stay silent on the leaf (rls_enabled=true
    # on the leaf itself).
    assert "SEC001  app.leaf_metrics\n" in lint_output
    assert "SEC001  app.leaf_metrics_2026" not in lint_output


# ============================================================
# Use case 25 — relkind filtering
# ============================================================

def test_uc25_view_invisible_to_introspector(
    lint_output: str,
) -> None:
    # The introspector filters to relkind IN ('r', 'p'). Views
    # (relkind='v') don't enter the table list, so no rule
    # mentions `app.documents_view` even though it sits on top
    # of an RLS-enabled table.
    assert "app.documents_view" not in lint_output


# ============================================================
# Tour-level sanity checks
# ============================================================

def test_lint_summary_shows_every_severity_class(
    lint_output: str,
) -> None:
    # Demo intentionally exercises all three severities; the
    # text formatter prints `N errors, M warnings, K infos.`
    # as the summary line.
    assert "errors" in lint_output
    assert "warnings" in lint_output
    assert "infos" in lint_output


def test_lint_exits_nonzero_on_demo_db(demo_db: str) -> None:
    # `fail_on = "error"` in pgrls.toml. The fixture has plenty
    # of error-severity violations (SEC001/2/3/4/6/HYG001), so
    # the exit code must be 1.
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "lint",
            "--database-url",
            demo_db,
            "--config",
            str(PGRLS_TOML),
        ],
        env={"DATABASE_URL": demo_db},
    )
    assert result.exit_code == 1


# ============================================================
# Use cases 26-31 — realistic application shapes
# ============================================================

def test_uc26_blog_admin_override_fires_sec003_on_public_permissive(
    lint_output: str,
) -> None:
    # The RESTRICTIVE tenant floor is silent. The PERMISSIVE
    # admin-or-author SELECT policy is granted to PUBLIC, so
    # SEC003 fires on it — uc31 demos the canonical fix.
    assert (
        "SEC003  app.blog_posts.blog_admin_or_author_read\n" in lint_output
    )
    assert "SEC003  app.blog_posts.blog_tenant_floor" not in lint_output


def test_uc27_delete_policy_without_with_check_clean(
    lint_output: str,
) -> None:
    # DELETE is exempt from SEC006 by design — pin the contract
    # against a future regression that broadens SEC006 to all
    # write commands.
    for rule_id in _ALL_RULE_IDS:
        line = f"{rule_id}  app.todos_archive"
        assert line not in lint_output, (
            f"{rule_id} unexpectedly fired on app.todos_archive"
        )


def test_uc28_jwt_based_tenant_clean(lint_output: str) -> None:
    # `auth.jwt()` is wrapped via `(SELECT auth.jwt())` — pin
    # that PERF001 doesn't fire on the wrapped form even when
    # combined with the `->>` JSON extractor.
    for rule_id in _ALL_RULE_IDS:
        line = f"{rule_id}  app.jwt_documents"
        assert line not in lint_output, (
            f"{rule_id} unexpectedly fired on app.jwt_documents"
        )


def test_uc29_public_or_tenant_mix_clean(lint_output: str) -> None:
    # `is_public OR tenant_id = ...` — both branches reference
    # table columns; SEC005 stays silent (own-col present).
    for rule_id in _ALL_RULE_IDS:
        line = f"{rule_id}  app.kb_articles"
        assert line not in lint_output, (
            f"{rule_id} unexpectedly fired on app.kb_articles"
        )


def test_uc30_composite_tenant_key_clean(lint_output: str) -> None:
    # Multi-column tenancy: `tenant_id = ... AND env = ...`.
    # Both columns are own-table refs.
    for rule_id in _ALL_RULE_IDS:
        line = f"{rule_id}  app.composite_tenant"
        assert line not in lint_output, (
            f"{rule_id} unexpectedly fired on app.composite_tenant"
        )


def test_uc31_permissive_policy_to_specific_role_silences_sec003(
    lint_output: str,
) -> None:
    # The RESTRICTIVE tenant_floor is silent; the PERMISSIVE
    # auth_role_read is granted to `app_authenticated`
    # (NOT PUBLIC), so SEC003 doesn't fire on it. This is the
    # canonical fix for the SEC003 violation in uc26.
    assert "SEC003  app.scoped_views" not in lint_output


# ============================================================
# Use cases 32-37 — Postgres feature & rule shape coverage
# ============================================================

def test_uc32_case_expression_in_policy_clean(
    lint_output: str,
) -> None:
    # `CASE visibility WHEN 'public' THEN true WHEN 'private'
    # THEN user_id = ... END`. Pins that extract_column_refs
    # walks CASE branches — `visibility` and `user_id` are
    # both reachable, so SEC005 stays silent.
    for rule_id in _ALL_RULE_IDS:
        line = f"{rule_id}  app.case_policy"
        assert line not in lint_output, (
            f"{rule_id} unexpectedly fired on app.case_policy"
        )


def test_uc33_classic_inherits_does_not_set_partition_of(
    lint_output: str,
) -> None:
    # Pre-declarative INHERITS still goes through pg_inherits,
    # but `relispartition` is false on classic-inherits
    # children. The introspector filters on relispartition, so
    # neither parent nor child gets a `partition_of`. SEC001
    # fires on both with the standalone classic message —
    # NOT the "is a partition of" variant.
    assert "SEC001  app.legacy_parent\n" in lint_output
    assert "SEC001  app.legacy_child\n" in lint_output
    # The child's message must NOT name the parent (which
    # would be the visible-root variant from uc15 — wrong here).
    legacy_child_section = lint_output.split(
        "SEC001  app.legacy_child"
    )[1].split("\n\n")[0]
    assert (
        "is a partition of app.legacy_parent" not in legacy_child_section
    )


def test_uc34_sec004_nested_is_null_under_and_clean(
    lint_output: str,
) -> None:
    # The expression is `user_id = auth.uid() AND flag_name IS NOT NULL`.
    # SEC004 fires only on TOP-LEVEL OR disjuncts where one is
    # `auth_func() IS NULL`. Top-level AND with a column
    # IS-NOT-NULL stays silent. Pin the distinction.
    assert "SEC004  app.flags_table" not in lint_output


def test_uc35_using_one_eq_one_fires_sec005_not_sec008(
    lint_output: str,
) -> None:
    # `USING (1=1)` is logically equivalent to `USING (true)`
    # but the AST is different — SEC008 keys on the literal
    # Boolean A_Const, not on the runtime value. Pin both:
    # SEC005 fires (no own-col ref), SEC008 stays silent.
    assert "SEC005  app.always_open.trivially_open\n" in lint_output
    assert "SEC008  app.always_open" not in lint_output


def test_uc36_pg_has_role_admin_escape_clean(lint_output: str) -> None:
    # `pg_has_role(current_user, 'pg_read_all_data', 'MEMBER')`
    # is a built-in admin escape. Not in PERF001's default
    # auth_functions set, so unwrapped is fine. RESTRICTIVE
    # silences SEC003.
    for rule_id in _ALL_RULE_IDS:
        line = f"{rule_id}  app.admin_overrides"
        assert line not in lint_output, (
            f"{rule_id} unexpectedly fired on app.admin_overrides"
        )


def test_uc37_hyg001_isolated_to_offending_policy(
    lint_output: str,
) -> None:
    # Two policies on `app.partial_orphan`: `clean_owner` (no
    # orphan) and `orphan_filter` (refs the dropped `gone`
    # column). HYG001 must fire ONLY on the offending policy.
    assert (
        "HYG001  app.partial_orphan.orphan_filter\n" in lint_output
    )
    assert (
        "HYG001  app.partial_orphan.clean_owner" not in lint_output
    )


# ============================================================
# Use case 38 — PERF001 walks the JSON extractor
# ============================================================

def test_uc38_perf001_on_unwrapped_jwt_json_access(
    lint_output: str,
) -> None:
    # `auth.jwt() ->> 'sub'` — the `->>` operator wraps the
    # auth call. Pin that find_func_calls walks operator
    # arguments correctly.
    assert (
        "PERF001  app.jwt_unwrapped.jwt_unwrapped_owner\n" in lint_output
    )


# ============================================================
# Use cases 44-47 — built-ins, partition variants, extra types
# ============================================================

def test_uc44_current_user_in_policy_does_not_fire_perf001(
    lint_output: str,
) -> None:
    # `current_user` is a SQLValueFunction (cheap); PERF001's
    # default auth_functions set deliberately excludes it.
    # Pin the asymmetry so a future "broaden the default set"
    # change is deliberate.
    assert "PERF001  app.current_user_check" not in lint_output
    # The whole table should be clean — `visibility` column
    # ref keeps SEC005 silent, RESTRICTIVE silences SEC003.
    for rule_id in _ALL_RULE_IDS:
        line = f"{rule_id}  app.current_user_check"
        assert line not in lint_output


def test_uc45_default_partition_inherits_rls_via_ancestor_walk(
    lint_output: str,
) -> None:
    # `PARTITION OF parent DEFAULT` is just another partition
    # (relispartition=true, inhparent=root). SEC001's ancestor
    # walk reaches the RLS-enabled root from any leaf, default
    # included.
    for table in (
        "app.region_metrics",
        "app.region_metrics_us",
        "app.region_metrics_default",
    ):
        assert f"SEC001  {table}\n" not in lint_output, (
            f"SEC001 unexpectedly fired on {table}"
        )


def test_uc46_generated_column_referenced_in_policy_clean(
    lint_output: str,
) -> None:
    # `GENERATED ALWAYS AS (...) STORED` columns appear in
    # pg_attribute alongside regular columns. HYG001 sees them
    # as present; SEC005 sees them as own-col refs.
    for rule_id in _ALL_RULE_IDS:
        line = f"{rule_id}  app.gen_cols"
        assert line not in lint_output


def test_uc47_array_any_membership_clean(lint_output: str) -> None:
    # `<scalar> = ANY(array_col)` — pins that
    # extract_column_refs walks ArrayExpr / ANY arguments
    # so the `tags` column ref counts as own.
    for rule_id in _ALL_RULE_IDS:
        line = f"{rule_id}  app.array_tags"
        assert line not in lint_output


# ============================================================
# Use cases 39-43 — configuration-driven scenarios
# ============================================================

def _run_lint(
    db: str,
    *,
    extra_args: tuple[str, ...] = (),
    config: Path | None = None,
) -> str:
    runner = CliRunner()
    args = ["lint", "--database-url", db, *extra_args]
    if config is not None:
        args.extend(["--config", str(config)])
    return runner.invoke(
        main, args, env={"DATABASE_URL": db}
    ).output


_BASE_CONFIG = (
    '[database]\nschemas = ["app"]\n'
    '[lint.rules.SEC001]\nallowlist = ["app.countries"]\n'
)


def test_uc39_custom_auth_function_detected_via_config(
    demo_db: str, tmp_path: Path
) -> None:
    # `app.current_user_id()` is silent under the default
    # PERF001 auth_functions list. Override the list to add it,
    # and PERF001 fires on `app.user_workspaces.workspace_owner`.
    # Note: an override REPLACES the default list, so we
    # re-include the defaults to avoid losing other detection.
    cfg = tmp_path / "p.toml"
    cfg.write_text(
        _BASE_CONFIG
        + '[lint.rules.PERF001]\n'
        'auth_functions = ["auth.uid", "auth.role", "auth.jwt", '
        '"current_setting", "app.current_user_id"]\n'
    )
    out = _run_lint(demo_db, config=cfg)
    # Default config: silent on user_workspaces.
    default_out = _run_lint(demo_db, config=PGRLS_TOML)
    assert "PERF001  app.user_workspaces" not in default_out
    # Custom config: fires.
    assert (
        "PERF001  app.user_workspaces.workspace_owner\n" in out
    )


def test_uc40_sec005_allowlist_silences_admin_audit(
    demo_db: str, tmp_path: Path
) -> None:
    # admin_audit's policy is legitimately session-state-only.
    # SEC005 fires by default; allowlisting the qualified
    # policy ID silences it.
    default_out = _run_lint(demo_db, config=PGRLS_TOML)
    assert (
        "SEC005  app.admin_audit.admin_only_read\n" in default_out
    )

    cfg = tmp_path / "p.toml"
    cfg.write_text(
        _BASE_CONFIG
        + '[lint.rules.SEC005]\n'
        'allowlist = ["app.admin_audit.admin_only_read"]\n'
    )
    out = _run_lint(demo_db, config=cfg)
    assert "SEC005  app.admin_audit" not in out


def test_uc41_disable_via_config_turns_off_sec007(
    demo_db: str, tmp_path: Path
) -> None:
    # uc09's app.tags fires SEC007 in the default run. Adding
    # SEC007 to `[lint].disable` skips the rule entirely;
    # nothing in the output mentions it.
    default_out = _run_lint(demo_db, config=PGRLS_TOML)
    assert "SEC007  app.tags\n" in default_out

    cfg = tmp_path / "p.toml"
    cfg.write_text(
        _BASE_CONFIG
        + '[lint]\ndisable = ["SEC007"]\n'
    )
    out = _run_lint(demo_db, config=cfg)
    assert "SEC007" not in out


def test_uc42_multi_schema_scan_picks_up_other_schema(
    demo_db: str, tmp_path: Path
) -> None:
    # `tenant.tenant_orphans` is in a schema the default
    # config doesn't scan. Adding `tenant` via --schemas
    # surfaces SEC001 on it.
    default_out = _run_lint(demo_db, config=PGRLS_TOML)
    assert "SEC001  tenant.tenant_orphans" not in default_out

    out = _run_lint(
        demo_db,
        config=PGRLS_TOML,
        extra_args=("--schemas", "app,tenant"),
    )
    assert "SEC001  tenant.tenant_orphans\n" in out


def test_uc43_sec003_allowlist_silences_intentional_public_read(
    demo_db: str, tmp_path: Path
) -> None:
    # `app.public_metadata.metadata_read` is a deliberate
    # PUBLIC SELECT policy on a documentation table. SEC003
    # fires by default; allowlisting silences it.
    default_out = _run_lint(demo_db, config=PGRLS_TOML)
    assert (
        "SEC003  app.public_metadata.metadata_read\n" in default_out
    )

    cfg = tmp_path / "p.toml"
    cfg.write_text(
        _BASE_CONFIG
        + '[lint.rules.SEC003]\n'
        'allowlist = ["app.public_metadata.metadata_read"]\n'
    )
    out = _run_lint(demo_db, config=cfg)
    assert "SEC003  app.public_metadata" not in out
