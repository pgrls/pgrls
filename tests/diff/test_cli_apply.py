"""End-to-end tests for `pgrls diff --apply migration.sql`.

The flag spins up an ephemeral Postgres testcontainer, restores
the captured baseline via `Schema.to_sql()`, applies the
migration, and introspects the result for the head schema.
"""
from __future__ import annotations

import json
from pathlib import Path

import psycopg
from click.testing import CliRunner

from pgrls.cli import main


def _capture_baseline(pg_url: str) -> Path:
    """Run `pgrls snapshot` against `pg_url` and return path to the JSON."""
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["snapshot", "--database-url", pg_url, "--schemas", "public"],
    )
    assert result.exit_code == 0, result.output
    return result.output  # JSON string


def test_diff_apply_classifies_safe_migration_as_clean(
    pg_url: str, apply_sql, tmp_path: Path
) -> None:
    """A migration that adds a SAFE-class change (e.g. RESTRICTIVE
    policy add) should classify accordingly. End-to-end smoke test
    for the --apply path: snapshot a baseline, write a migration
    that ALTERs the schema, run `pgrls diff base.json --apply`."""
    apply_sql(
        """
        CREATE TABLE public.invoices (
            id BIGSERIAL,
            tenant_id UUID NOT NULL,
            amount NUMERIC(12, 2)
        );
        ALTER TABLE public.invoices ENABLE ROW LEVEL SECURITY;
        ALTER TABLE public.invoices FORCE ROW LEVEL SECURITY;
        """
    )

    runner = CliRunner()
    snap_result = runner.invoke(
        main,
        ["snapshot", "--database-url", pg_url, "--schemas", "public"],
    )
    assert snap_result.exit_code == 0, snap_result.output
    base_path = tmp_path / "base.json"
    base_path.write_text(snap_result.output, encoding="utf-8")

    migration_path = tmp_path / "migration.sql"
    migration_path.write_text(
        # Adding a RESTRICTIVE policy is SAFE (tightens access).
        "CREATE POLICY tenant_lock ON public.invoices "
        "AS RESTRICTIVE FOR ALL TO PUBLIC "
        "USING (tenant_id IS NOT NULL) "
        "WITH CHECK (tenant_id IS NOT NULL);\n",
        encoding="utf-8",
    )

    result = runner.invoke(
        main,
        [
            "diff",
            str(base_path),
            "--apply",
            str(migration_path),
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    # Adding a RESTRICTIVE policy is SAFE — the diff JSON reuses
    # the lint Violation shape (`violations`, with each entry
    # exposing `rule_id`, `severity`, `title`, `message`,
    # `location`). The DIFF_POLICY_ADDED_RESTRICTIVE rule_id maps
    # to severity=info (SAFE classification per AGENTS.md).
    rule_ids = {v["rule_id"] for v in payload["violations"]}
    assert "DIFF_POLICY_ADDED_RESTRICTIVE" in rule_ids


def test_diff_apply_classifies_dangerous_migration_as_failing(
    pg_url: str, apply_sql, tmp_path: Path
) -> None:
    """A migration that adds a DANGEROUS-class change should make
    `pgrls diff --apply` exit 1 (the default --fail-on=dangerous)."""
    apply_sql(
        """
        CREATE TABLE public.users_apply_test (
            id BIGSERIAL,
            email TEXT,
            tenant_id UUID NOT NULL
        );
        ALTER TABLE public.users_apply_test ENABLE ROW LEVEL SECURITY;
        ALTER TABLE public.users_apply_test FORCE ROW LEVEL SECURITY;
        CREATE POLICY tenant_lock ON public.users_apply_test
            AS RESTRICTIVE FOR ALL TO PUBLIC
            USING (tenant_id IS NOT NULL);
        """
    )

    runner = CliRunner()
    snap_result = runner.invoke(
        main,
        ["snapshot", "--database-url", pg_url, "--schemas", "public"],
    )
    assert snap_result.exit_code == 0
    base_path = tmp_path / "base.json"
    base_path.write_text(snap_result.output, encoding="utf-8")

    migration_path = tmp_path / "migration.sql"
    migration_path.write_text(
        # Adding a PERMISSIVE-PUBLIC policy is DANGEROUS (broadens
        # access). With --fail-on=dangerous (default), exit 1.
        "CREATE POLICY public_read ON public.users_apply_test "
        "FOR SELECT TO PUBLIC USING (true);\n",
        encoding="utf-8",
    )

    result = runner.invoke(
        main,
        [
            "diff",
            str(base_path),
            "--apply",
            str(migration_path),
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 1, result.output
    payload = json.loads(result.output)
    # Dangerous changes surface as severity=error in the violation
    # JSON shape (per diff.formatters' Change → Violation map).
    error_violations = [
        v for v in payload["violations"] if v["severity"] == "error"
    ]
    assert error_violations, payload


def test_diff_apply_rejects_combined_with_head_argument(
    tmp_path: Path,
) -> None:
    """`<head>` and --apply are mutually exclusive — pin the error."""
    base = tmp_path / "base.json"
    base.write_text(
        json.dumps({"version": 5, "tables": [], "policies": [], "views": [], "security_definer_functions": []}),
        encoding="utf-8",
    )
    migration = tmp_path / "m.sql"
    migration.write_text("-- empty\n", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "diff",
            str(base),
            "postgres://x/y",
            "--apply",
            str(migration),
        ],
    )
    assert result.exit_code != 0
    assert "--apply" in result.output and "head" in result.output


def test_diff_apply_surfaces_migration_sql_error_clearly(
    pg_url: str, apply_sql, tmp_path: Path
) -> None:
    """A migration with bad SQL should surface the psycopg error
    via the `--apply: migration <path> failed` ToolError shape."""
    apply_sql(
        """
        CREATE TABLE public.things_apply_err (id BIGSERIAL);
        ALTER TABLE public.things_apply_err ENABLE ROW LEVEL SECURITY;
        ALTER TABLE public.things_apply_err FORCE ROW LEVEL SECURITY;
        """
    )

    runner = CliRunner()
    snap_result = runner.invoke(
        main,
        ["snapshot", "--database-url", pg_url, "--schemas", "public"],
    )
    assert snap_result.exit_code == 0
    base_path = tmp_path / "base.json"
    base_path.write_text(snap_result.output, encoding="utf-8")

    migration_path = tmp_path / "broken.sql"
    migration_path.write_text(
        "CREATE POLICY my_policy ON public.does_not_exist FOR SELECT TO PUBLIC USING (true);\n",
        encoding="utf-8",
    )

    result = runner.invoke(
        main,
        [
            "diff",
            str(base_path),
            "--apply",
            str(migration_path),
        ],
    )
    assert result.exit_code != 0
    assert "--apply" in result.output
    assert "failed" in result.output


def test_diff_apply_with_extension_flag_pre_installs_extension(
    pg_url: str, apply_sql, tmp_path: Path
) -> None:
    """`--extension citext` pre-installs the extension in the
    testcontainer before restoring the baseline. Without the flag,
    a baseline that uses ``citext`` columns would fail to restore
    because the type is unknown until the extension is installed.

    Pin the v0.5.1 contract: passing --extension makes the migration
    apply succeed against a baseline whose Schema.to_sql() emits a
    ``citext`` column type.
    """
    # Baseline uses citext — the extension is installed in the
    # *source* DB so introspection captures the column as
    # data_type='citext'. The testcontainer used by --apply is
    # ephemeral and does NOT have citext, hence --extension.
    apply_sql(
        """
        CREATE EXTENSION IF NOT EXISTS citext;
        CREATE TABLE public.contacts_ext_test (
            id BIGSERIAL,
            email CITEXT,
            tenant_id UUID NOT NULL
        );
        ALTER TABLE public.contacts_ext_test ENABLE ROW LEVEL SECURITY;
        ALTER TABLE public.contacts_ext_test FORCE ROW LEVEL SECURITY;
        """
    )

    runner = CliRunner()
    snap_result = runner.invoke(
        main,
        ["snapshot", "--database-url", pg_url, "--schemas", "public"],
    )
    assert snap_result.exit_code == 0, snap_result.output
    base_path = tmp_path / "base.json"
    base_path.write_text(snap_result.output, encoding="utf-8")

    # Sanity check: baseline really does carry a citext column.
    # If snapshot stopped emitting that, the test would silently
    # stop covering the case.
    base_payload = json.loads(snap_result.output)
    contacts = next(
        t for t in base_payload["tables"]
        if t["schema"] == "public" and t["name"] == "contacts_ext_test"
    )
    assert any(
        col["data_type"] == "citext"
        for col in contacts.get("column_details", [])
    ), contacts

    # Migration that doesn't touch citext at all — only adds a new
    # plain-text column. Without --extension citext, the baseline
    # restore inside the testcontainer would fail at the
    # `email CITEXT` line.
    migration_path = tmp_path / "migration.sql"
    migration_path.write_text(
        "ALTER TABLE public.contacts_ext_test ADD COLUMN note TEXT;\n",
        encoding="utf-8",
    )

    result = runner.invoke(
        main,
        [
            "diff",
            str(base_path),
            "--apply",
            str(migration_path),
            "--extension",
            "citext",
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 0, result.output
    # The migration only adds a column — no diff classification
    # should fire. Pin the smoke-test invariant: empty violations
    # list (column adds aren't an RLS-related diff change).
    payload = json.loads(result.output)
    assert payload["violations"] == [], payload


def test_diff_apply_auto_detects_create_extension_in_migration(
    pg_url: str, apply_sql, tmp_path: Path
) -> None:
    """A migration with ``CREATE EXTENSION pgcrypto;`` followed by a
    column default that calls ``gen_random_uuid()`` should apply
    cleanly without --extension, because the v0.5.1 auto-detect
    walks the migration AST and pre-installs every extension it
    declares.
    """
    apply_sql(
        """
        CREATE TABLE public.tokens_autodetect (
            id BIGSERIAL,
            tenant_id UUID NOT NULL
        );
        ALTER TABLE public.tokens_autodetect ENABLE ROW LEVEL SECURITY;
        ALTER TABLE public.tokens_autodetect FORCE ROW LEVEL SECURITY;
        """
    )

    runner = CliRunner()
    snap_result = runner.invoke(
        main,
        ["snapshot", "--database-url", pg_url, "--schemas", "public"],
    )
    assert snap_result.exit_code == 0, snap_result.output
    base_path = tmp_path / "base.json"
    base_path.write_text(snap_result.output, encoding="utf-8")

    # Migration declares the extension itself; auto-detect picks
    # it up from the migration's CreateExtensionStmt — no
    # --extension flag needed. Pre-installing under `IF NOT EXISTS`
    # is idempotent with the migration's own statement.
    migration_path = tmp_path / "migration.sql"
    migration_path.write_text(
        "CREATE EXTENSION IF NOT EXISTS pgcrypto;\n"
        "ALTER TABLE public.tokens_autodetect "
        "ADD COLUMN token UUID DEFAULT gen_random_uuid();\n",
        encoding="utf-8",
    )

    result = runner.invoke(
        main,
        [
            "diff",
            str(base_path),
            "--apply",
            str(migration_path),
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 0, result.output


def test_diff_apply_baseline_cache_creates_image_on_first_run_and_reuses_on_second(
    pg_url: str, apply_sql, tmp_path: Path
) -> None:
    """v0.5.2 baseline cache: the first --apply run for a given
    (pg_image, baseline, roles, extensions) combination boots a
    fresh container, restores the baseline, commits the result
    into a tagged docker image, then continues. The second run
    with the same inputs short-circuits — boots directly from the
    cached image, skips the baseline restore.

    Pin the cache contract by checking:
      1. After run 1, the cached image exists in the local docker daemon.
      2. Both runs return the same diff output (cache reuse must
         not change observable behaviour).
      3. The cached image carries the `org.pgrls.cache=baseline`
         label so users can `docker image prune --filter` it.
    """
    import docker
    from docker.errors import ImageNotFound

    from pgrls.diff import _apply_cache
    from pgrls.model import Schema

    apply_sql(
        """
        CREATE TABLE public.cache_test_orders (
            id BIGSERIAL,
            tenant_id UUID NOT NULL
        );
        ALTER TABLE public.cache_test_orders ENABLE ROW LEVEL SECURITY;
        ALTER TABLE public.cache_test_orders FORCE ROW LEVEL SECURITY;
        """
    )

    runner = CliRunner()
    snap_result = runner.invoke(
        main,
        ["snapshot", "--database-url", pg_url, "--schemas", "public"],
    )
    assert snap_result.exit_code == 0, snap_result.output
    base_path = tmp_path / "base.json"
    base_path.write_text(snap_result.output, encoding="utf-8")

    migration_path = tmp_path / "migration.sql"
    migration_path.write_text(
        "CREATE POLICY tenant_lock ON public.cache_test_orders "
        "AS RESTRICTIVE FOR ALL TO PUBLIC "
        "USING (tenant_id IS NOT NULL) "
        "WITH CHECK (tenant_id IS NOT NULL);\n",
        encoding="utf-8",
    )

    # Compute the expected cache key so we can assert on the
    # specific image tag and clean it up at the end.
    base_schema = Schema.from_snapshot(json.loads(snap_result.output))
    baseline_sql = base_schema.to_sql()
    expected_key = _apply_cache.compute_cache_key(
        pg_image="postgres:17-alpine",
        baseline_sql=baseline_sql,
        roles=set(),  # no roles in this baseline
        extensions=set(),  # no extensions
    )
    expected_tag = _apply_cache.cached_image_tag(expected_key)

    # Pre-clean: remove any cache image left from a prior test
    # run so we observe a clean miss → hit transition.
    docker_client = docker.from_env()
    try:
        docker_client.images.remove(expected_tag, force=True)
    except ImageNotFound:
        pass  # already absent — that's the desired starting state

    # Run 1 — cache miss. Should create the image.
    result1 = runner.invoke(
        main,
        [
            "diff",
            str(base_path),
            "--apply",
            str(migration_path),
            "--format",
            "json",
        ],
    )
    assert result1.exit_code == 0, result1.output

    # Verify the image exists with the expected label.
    image = docker_client.images.get(expected_tag)
    labels = image.attrs.get("Config", {}).get("Labels") or {}
    assert labels.get(_apply_cache.CACHE_LABEL_KEY) == _apply_cache.CACHE_LABEL_VALUE, (
        f"Expected label {_apply_cache.CACHE_LABEL_KEY}="
        f"{_apply_cache.CACHE_LABEL_VALUE}, got {labels}"
    )

    # Run 2 — cache hit. Should produce identical output.
    result2 = runner.invoke(
        main,
        [
            "diff",
            str(base_path),
            "--apply",
            str(migration_path),
            "--format",
            "json",
        ],
    )
    assert result2.exit_code == 0, result2.output
    assert result1.output == result2.output, (
        "Cached run must produce identical output to fresh run; "
        f"got\nrun1:\n{result1.output}\nrun2:\n{result2.output}"
    )

    # Cleanup — leave the daemon as we found it.
    try:
        docker_client.images.remove(expected_tag, force=True)
    except ImageNotFound:
        pass


def test_diff_apply_verbose_emits_cache_and_timing_telemetry(
    pg_url: str, apply_sql, tmp_path: Path
) -> None:
    """v0.5.3 ``-v / --verbose`` flag emits cache miss/hit + per-
    step timings to stderr while leaving stdout (the diff JSON
    payload) machine-parsable.

    Pin: stderr contains the cache state, baseline-restore
    timing, migration apply timing. stdout JSON parses cleanly
    without verbose noise leaking into it.
    """
    import docker
    from docker.errors import ImageNotFound

    from pgrls.diff import _apply_cache
    from pgrls.model import Schema

    apply_sql(
        """
        CREATE TABLE public.verbose_test_orders (
            id BIGSERIAL,
            tenant_id UUID NOT NULL
        );
        ALTER TABLE public.verbose_test_orders ENABLE ROW LEVEL SECURITY;
        ALTER TABLE public.verbose_test_orders FORCE ROW LEVEL SECURITY;
        """
    )

    runner = CliRunner()
    snap_result = runner.invoke(
        main,
        ["snapshot", "--database-url", pg_url, "--schemas", "public"],
    )
    assert snap_result.exit_code == 0, snap_result.output
    base_path = tmp_path / "base.json"
    base_path.write_text(snap_result.output, encoding="utf-8")

    migration_path = tmp_path / "migration.sql"
    migration_path.write_text(
        "ALTER TABLE public.verbose_test_orders ADD COLUMN note TEXT;\n",
        encoding="utf-8",
    )

    # Pre-clean any existing cache image so we observe the miss
    # path's full telemetry on run 1.
    base_schema = Schema.from_snapshot(json.loads(snap_result.output))
    expected_key = _apply_cache.compute_cache_key(
        pg_image="postgres:17-alpine",
        baseline_sql=base_schema.to_sql(),
        roles=set(),
        extensions=set(),
    )
    expected_tag = _apply_cache.cached_image_tag(expected_key)
    docker_client = docker.from_env()
    try:
        docker_client.images.remove(expected_tag, force=True)
    except ImageNotFound:
        pass

    # Click 8.3+ exposes result.stdout / result.stderr separately
    # by default — no mix_stderr knob needed. We rely on this so
    # the verbose telemetry and the diff JSON payload can be
    # asserted on independently.
    result = runner.invoke(
        main,
        [
            "diff",
            str(base_path),
            "--apply",
            str(migration_path),
            "--verbose",
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 0, (result.stdout, result.stderr)

    # stdout: clean JSON payload, no verbose lines mixed in.
    payload = json.loads(result.stdout)
    assert "violations" in payload, payload

    # stderr: cache miss line + boot/baseline/migration/introspect timings.
    err = result.stderr
    assert "cache: miss" in err, err
    assert "booted in" in err, err
    assert "baseline restored in" in err, err
    assert "committed baseline cache" in err, err
    assert "migration applied in" in err, err
    assert "introspected in" in err, err

    # Run 2 — should now hit the cache. Different stderr shape:
    # "cache: hit" instead of "cache: miss", and no "baseline
    # restored" / "committed" lines (those are skipped on hit).
    result2 = runner.invoke(
        main,
        [
            "diff",
            str(base_path),
            "--apply",
            str(migration_path),
            "--verbose",
            "--format",
            "json",
        ],
    )
    assert result2.exit_code == 0, (result2.stdout, result2.stderr)
    err2 = result2.stderr
    assert "cache: hit" in err2, err2
    # The hit path skips the role/extension/baseline restore +
    # commit steps, so neither line should appear.
    assert "baseline restored in" not in err2, err2
    assert "committed baseline cache" not in err2, err2
    # Migration apply + introspect still happen on every run.
    assert "migration applied in" in err2, err2

    # Cleanup.
    try:
        docker_client.images.remove(expected_tag, force=True)
    except ImageNotFound:
        pass


def test_diff_apply_baseline_cache_can_be_disabled_via_env(
    pg_url: str, apply_sql, tmp_path: Path, monkeypatch
) -> None:
    """Set ``PGRLS_DIFF_APPLY_NO_CACHE=1`` and the cache must not
    be touched — no image lookup, no commit. Useful as an escape
    hatch when debugging cache-related issues.
    """
    import docker
    from docker.errors import ImageNotFound

    from pgrls.diff import _apply_cache
    from pgrls.model import Schema

    monkeypatch.setenv(_apply_cache.DISABLE_ENV_VAR, "1")

    apply_sql(
        """
        CREATE TABLE public.cache_disabled_test (
            id BIGSERIAL,
            tenant_id UUID NOT NULL
        );
        ALTER TABLE public.cache_disabled_test ENABLE ROW LEVEL SECURITY;
        ALTER TABLE public.cache_disabled_test FORCE ROW LEVEL SECURITY;
        """
    )

    runner = CliRunner()
    snap_result = runner.invoke(
        main,
        ["snapshot", "--database-url", pg_url, "--schemas", "public"],
    )
    assert snap_result.exit_code == 0, snap_result.output
    base_path = tmp_path / "base.json"
    base_path.write_text(snap_result.output, encoding="utf-8")

    base_schema = Schema.from_snapshot(json.loads(snap_result.output))
    baseline_sql = base_schema.to_sql()
    expected_key = _apply_cache.compute_cache_key(
        pg_image="postgres:17-alpine",
        baseline_sql=baseline_sql,
        roles=set(),
        extensions=set(),
    )
    expected_tag = _apply_cache.cached_image_tag(expected_key)

    # Pre-clean: confirm the image is absent before the run.
    docker_client = docker.from_env()
    try:
        docker_client.images.remove(expected_tag, force=True)
    except ImageNotFound:
        pass

    migration_path = tmp_path / "migration.sql"
    migration_path.write_text(
        "ALTER TABLE public.cache_disabled_test ADD COLUMN note TEXT;\n",
        encoding="utf-8",
    )

    result = runner.invoke(
        main,
        [
            "diff",
            str(base_path),
            "--apply",
            str(migration_path),
        ],
    )
    assert result.exit_code == 0, result.output

    # Cache was disabled, so no image should have been created.
    try:
        docker_client.images.get(expected_tag)
        # If we got here, the env-var disable mechanism is broken.
        # Clean up anyway, then fail loudly.
        docker_client.images.remove(expected_tag, force=True)
        raise AssertionError(
            f"Cache was disabled but {expected_tag} was still committed"
        )
    except ImageNotFound:
        pass  # the expected state — nothing was committed


def test_diff_apply_rejects_v4_baseline_with_clear_message(
    tmp_path: Path,
) -> None:
    """A v4 baseline (no column_details) → clear "re-capture against
    v0.5+" error rather than a confusing internal traceback."""
    v4_payload = {
        "version": 4,
        "tables": [
            {
                "schema": "public",
                "name": "t",
                "rls_enabled": False,
                "force_rls": False,
                "columns": ["id"],
                "partition_of": None,
                "grants": [],
            }
        ],
        "policies": [],
        "views": [],
        "security_definer_functions": [],
    }
    base = tmp_path / "base.json"
    base.write_text(json.dumps(v4_payload), encoding="utf-8")
    migration = tmp_path / "m.sql"
    migration.write_text("CREATE TABLE public.x (id INT);\n", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(
        main,
        ["diff", str(base), "--apply", str(migration)],
    )
    assert result.exit_code != 0
    assert "column_details" in result.output
    assert "v0.5" in result.output or "0.5" in result.output


def test_diff_apply_provisions_non_public_baseline_role(
    pg_url: str, apply_sql, tmp_path: Path
) -> None:
    """A baseline whose policies reference a non-PUBLIC role (e.g.
    `authenticated`) must apply cleanly.

    Regression for the role-provisioning DO block in
    `_apply_migration_for_diff`: it used a server-side ``%s`` parameter
    inside the DO body, which has no inferable type, so Postgres raised
    ``IndeterminateDatatype`` the moment any non-PUBLIC role appeared in the
    captured baseline. (PUBLIC is special-cased and never hit the path, which
    is why no prior --apply test caught it.) The role name is now composed
    client-side with ``psycopg.sql``.
    """
    # Idempotently create the non-PUBLIC role the policy targets. apply_sql
    # splits on `;`, so it can't run a DO block — use a direct cursor.
    with psycopg.connect(pg_url, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute(
            "DO $$ BEGIN "
            "IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'pgrls_diffapply_auth') "
            "THEN CREATE ROLE pgrls_diffapply_auth NOLOGIN; END IF; END $$;"
        )

    apply_sql(
        """
        CREATE TABLE public.acct (id BIGSERIAL, tenant_id UUID NOT NULL);
        ALTER TABLE public.acct ENABLE ROW LEVEL SECURITY;
        ALTER TABLE public.acct FORCE ROW LEVEL SECURITY;
        CREATE POLICY acct_isolation ON public.acct
            FOR ALL TO pgrls_diffapply_auth
            USING (tenant_id = current_setting('app.tenant', true)::uuid)
            WITH CHECK (tenant_id = current_setting('app.tenant', true)::uuid);
        """
    )

    runner = CliRunner()
    snap = runner.invoke(
        main, ["snapshot", "--database-url", pg_url, "--schemas", "public"]
    )
    assert snap.exit_code == 0, snap.output
    base_path = tmp_path / "base.json"
    base_path.write_text(snap.output, encoding="utf-8")
    # Guard: the baseline must actually carry the non-PUBLIC role, else the
    # test would pass vacuously without exercising role provisioning.
    assert "pgrls_diffapply_auth" in snap.output

    migration_path = tmp_path / "migration.sql"
    migration_path.write_text(
        "ALTER TABLE public.acct ADD COLUMN note text;\n", encoding="utf-8"
    )

    result = runner.invoke(
        main,
        ["diff", str(base_path), "--apply", str(migration_path), "--format", "json"],
    )
    # The fix: restoring the baseline pre-creates pgrls_diffapply_auth in the
    # ephemeral container without IndeterminateDatatype; an additive column is
    # a neutral change, so the diff exits 0.
    assert result.exit_code == 0, result.output
    assert "IndeterminateDatatype" not in result.output
    assert "could not determine data type" not in result.output
