"""Click entry point for the `pgrls` console script.

Exit codes:

  0  — lint completed; no findings at or above the fail-on threshold
       (or `pgrls fix` ran successfully, dry-run or apply).

  1  — lint completed; findings met or exceeded the fail-on
       threshold. CI scripts can rely on this to block deploys.

  2  — pgrls itself failed to run. Bad TOML config, missing
       --database-url, unknown schema, DB connection error, fixer
       SQL failure under --apply, etc. Distinct from exit 1 so a
       CI pipeline can tell "your schema has an RLS bug" apart
       from "pgrls can't reach the database / your config is
       broken." Most lint tools (ESLint, ruff, mypy) follow this
       three-tier convention.
"""
from __future__ import annotations

import json
import os
import sys
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any

import click
import psycopg

from pgrls import __version__
from pgrls.baseline import (
    BaselineError,
    load_baseline,
    partition,
    write_baseline,
)
from pgrls.config import (
    DIFF_FAIL_ON_VALUES,
    Config,
    ConfigError,
    load_config,
)
from pgrls.diff import Change, diff_schemas
from pgrls.diff.formatters import (
    DIFF_SUPPORTED_FORMATS,
    format_diff_json,
    format_diff_sarif,
    format_diff_text,
)
from pgrls.fixers import default_fixers, generate_fixes
from pgrls.formatters import SUPPORTED_FORMATS, format_violations
from pgrls.introspect import introspect
from pgrls.model import Schema
from pgrls.rules import default_registry
from pgrls.violations import (
    ALL_SEVERITIES,
    Severity,
    Violation,
    coerce_severity,
    is_at_or_above,
)


class ToolError(click.ClickException):
    """`pgrls` couldn't even run the lint — config / network / fixer error.

    Exits with code 2 to distinguish "tool failed to start" from
    `sys.exit(1)` (lint completed, findings exceeded threshold).
    Without this distinction CI alerts cannot route "DB unreachable"
    differently from "schema has an RLS bug" — the operator sees
    `exit 1` for both and can't tell what action to take.
    """

    exit_code = 2


@click.group()
@click.version_option(__version__, prog_name="pgrls")
def main() -> None:
    """Framework-agnostic linter and testing toolkit for Postgres Row-Level Security."""


@main.command()
@click.option(
    "--database-url",
    envvar="DATABASE_URL",
    help="Postgres connection string. Falls back to $DATABASE_URL.",
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True, dir_okay=False),
    default=None,
    help="Path to pgrls.toml. Defaults to ./pgrls.toml if present.",
)
@click.option(
    "--schemas",
    default=None,
    help="Comma-separated schemas to lint (overrides config).",
)
@click.option(
    "--fail-on",
    type=click.Choice(list(ALL_SEVERITIES), case_sensitive=False),
    default=None,
    help="Severity threshold that triggers nonzero exit.",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(SUPPORTED_FORMATS, case_sensitive=False),
    default="text",
    show_default=True,
    help="Output format.",
)
@click.option(
    "--baseline",
    "baseline_path",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help=(
        "Baseline file. On the first run (file absent) records the "
        "current findings and exits 0; on later runs reports and "
        "fails only on findings not in the baseline."
    ),
)
def lint(
    database_url: str | None,
    config_path: str | None,
    schemas: str | None,
    fail_on: str | None,
    output_format: str,
    baseline_path: Path | None,
) -> None:
    """Lint Postgres RLS policies for security and hygiene issues."""
    try:
        config = load_config(config_path)
    except ConfigError as exc:
        raise ToolError(str(exc)) from exc

    effective = _merge_overrides(
        config,
        database_url=database_url,
        schemas_csv=schemas,
        fail_on=fail_on,
    )

    if effective.database_url is None:
        raise ToolError(
            "No database connection: pass --database-url or set DATABASE_URL."
        )

    try:
        with psycopg.connect(effective.database_url) as conn:
            schema = introspect(conn, schemas=effective.schemas)
    except psycopg.Error as exc:
        raise ToolError(f"Database error: {exc}") from exc
    except ValueError as exc:
        raise ToolError(str(exc)) from exc

    try:
        violations = _run_rules(schema, config=effective)
    except (TypeError, ValueError, RuntimeError) as exc:
        raise ToolError(str(exc)) from exc

    if baseline_path is not None:
        filtered = _apply_baseline(violations, baseline_path)
        if filtered is None:
            return  # first run — baseline written, nothing to report
        violations = filtered

    click.echo(format_violations(violations, format=output_format), nl=False)

    if _should_fail(violations, threshold=effective.fail_on):
        sys.exit(1)


def _merge_overrides(
    config: Config,
    *,
    database_url: str | None,
    schemas_csv: str | None,
    fail_on: str | None,
) -> Config:
    if schemas_csv:
        schemas = [s.strip() for s in schemas_csv.split(",") if s.strip()]
        if not schemas:
            raise ToolError(
                f"--schemas {schemas_csv!r} produced an empty schema list. "
                "Check for trailing commas or whitespace-only values."
            )
    else:
        schemas = config.schemas
    # `coerce_severity` validates AND narrows. `cast` would have
    # been a no-op at runtime — a programmatic caller passing
    # garbage from a non-Click code path would silently land in
    # `is_at_or_above` and KeyError there.
    effective_fail_on: Severity = (
        coerce_severity(fail_on) if fail_on is not None else config.fail_on
    )
    return Config(
        database_url=database_url or config.database_url,
        schemas=schemas,
        disable=list(config.disable),
        fail_on=effective_fail_on,
        rule_options=dict(config.rule_options),
        severity_overrides=dict(config.severity_overrides),
        diff_fail_on=config.diff_fail_on,
    )


def _run_rules(schema: Schema, *, config: Config) -> list[Violation]:
    registry = default_registry()
    rules = registry.enabled(disabled_ids=config.disable)
    out: list[Violation] = []
    for rule in rules:
        try:
            found = rule.check(schema, config.rule_options.get(rule.id, {}))
        except RecursionError as exc:
            # Pathologically deep policy AST (thousands of nested
            # ANDs/ORs) blows the default Python recursion limit
            # in any of the AST walkers. Real-world policies are
            # nowhere near this depth, but a hand-crafted policy
            # could trigger it. Surface a clean error instead of
            # crashing the whole lint run.
            raise RuntimeError(
                f"{rule.id}: policy AST too deep to walk "
                "(RecursionError in rule check). Increase "
                "sys.setrecursionlimit or simplify the policy."
            ) from exc
        # Apply a per-rule severity override, if configured. The
        # rule stamps its own declared severity on every Violation;
        # the override remaps them here, before exit-code (`_should_
        # fail`) and output, so a promoted/demoted rule counts and
        # displays at the configured severity.
        override = config.severity_overrides.get(rule.id)
        if override is not None:
            found = [replace(v, severity=override) for v in found]
        out.extend(found)
    return out


def _should_fail(violations: list[Violation], *, threshold: Severity) -> bool:
    return any(is_at_or_above(v.severity, threshold) for v in violations)


def _apply_baseline(
    violations: list[Violation], path: Path
) -> list[Violation] | None:
    """Apply a `--baseline` file to `violations`.

    First run (file absent): write the baseline, report it on
    stderr, and return None — the caller exits 0 without printing
    findings (the run's job was to record the baseline). Later
    runs: return only the findings absent from the baseline,
    reporting the suppressed count on stderr so the operator can
    see the baseline is in effect.
    """
    if not path.exists():
        try:
            count = write_baseline(
                path, violations, tool_version=__version__
            )
        except BaselineError as exc:
            raise ToolError(str(exc)) from exc
        click.echo(
            f"pgrls: wrote baseline with {count} finding(s) to "
            f"{path}. Future `pgrls lint --baseline` runs report "
            "only findings not recorded in it.",
            err=True,
        )
        return None

    try:
        baseline = load_baseline(path)
    except BaselineError as exc:
        raise ToolError(str(exc)) from exc
    new, baselined = partition(violations, baseline)
    if baselined:
        click.echo(
            f"pgrls: {len(baselined)} finding(s) suppressed by "
            f"baseline {path}.",
            err=True,
        )
    return new


def _fix_apply_failure_message(
    i: int,
    total: int,
    fix: object,  # Fix dataclass; loose-typed to avoid circular import
    exc: psycopg.Error,
) -> str:
    """Compose the all-or-nothing rollback message for `fix --apply`.

    Includes the failing SQL (truncated to keep the message
    readable when a complex PERF001 ALTER POLICY runs long), the
    psycopg error string, and a remediation hint pointing the
    user toward the next concrete action — so they don't have to
    scroll back through stdout to figure out what broke.
    """
    sql = getattr(fix, "sql", "")
    sql_preview = sql if len(sql) <= 200 else sql[:197] + "..."
    return (
        f"fix {i}/{total} failed "
        f"({fix.rule_id} on {fix.location}).\n"  # type: ignore[attr-defined]
        f"  SQL: {sql_preview}\n"
        f"  psycopg error: {exc}\n"
        "No fixes were applied — the transaction was rolled back, "
        "your database is unchanged. Re-run `pgrls lint` to confirm "
        "state, then either apply the remaining SQL by hand or "
        "address the underlying error (permissions, concurrent "
        "migration, etc.) and retry."
    )


@main.command()
@click.option(
    "--database-url",
    envvar="DATABASE_URL",
    help="Postgres connection string. Falls back to $DATABASE_URL.",
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True, dir_okay=False),
    default=None,
    help="Path to pgrls.toml. Defaults to ./pgrls.toml if present.",
)
@click.option(
    "--schemas",
    default=None,
    help="Comma-separated schemas to scan (overrides config).",
)
@click.option(
    "--rule",
    "rules",
    multiple=True,
    help="Only generate fixes for these rule IDs (repeat for multiple).",
)
@click.option(
    "--apply",
    is_flag=True,
    default=False,
    help="Execute the fixes. Default: dry-run (print SQL only).",
)
def fix(
    database_url: str | None,
    config_path: str | None,
    schemas: str | None,
    rules: tuple[str, ...],
    apply: bool,
) -> None:
    """Auto-remediate violations whose fix is mechanical.

    Currently fixes SEC001 (`ALTER TABLE … ENABLE ROW LEVEL
    SECURITY`), SEC002 (`ALTER TABLE … FORCE ROW LEVEL
    SECURITY`), SEC006 (`ALTER POLICY … WITH CHECK` mirroring
    USING), PERF001 (wrap unwrapped auth calls in
    `(SELECT …)` and emit `ALTER POLICY`), VIEW001
    (`ALTER VIEW … SET (security_invoker = true)`), and
    VIEW002 (`ALTER VIEW … SET (security_barrier = true)`).
    Other rules require human intent (which role to grant
    to, what column to scope by) and are not auto-fixed.

    Default mode is dry-run: prints the SQL that WOULD be applied,
    nothing is executed. Pass `--apply` to run the statements
    against the configured database.

    `--apply` semantics: all-or-nothing. Every fix runs in the
    same transaction; if any statement fails, the entire batch
    is rolled back and the database is unchanged. The failing
    fix's `(rule_id, location)` is reported in the error message.

    Output channels: SQL bodies go to stdout (so `pgrls fix >
    migration.sql` produces a usable script). Status / progress /
    error messages go to stderr.

    The Schema is captured by introspection at the start of the
    command and the generated fixes reflect that snapshot. A
    concurrent migration between introspection and `--apply` could
    cause individual statements to fail; the all-or-nothing rollback
    keeps the database consistent in that case.
    """
    try:
        config = load_config(config_path)
    except ConfigError as exc:
        raise ToolError(str(exc)) from exc

    # Validate `--rule` early — a typo silently producing zero
    # fixes is hard to debug. The "no auto-fixable" message
    # should be reserved for "DB is clean", not "you spelled the
    # rule wrong." Case-normalize to match the rest of the
    # config surfaces (`[lint].disable`, `[lint.rules.<ID>]`,
    # `--fail-on`).
    auto_fixable = {fixer.rule_id for fixer in default_fixers()}
    if rules:
        normalized_rules = {r.upper() for r in rules}
        unknown = sorted(normalized_rules - auto_fixable)
        if unknown:
            raise ToolError(
                f"unknown auto-fixable rule(s): {', '.join(unknown)}. "
                f"Available: {', '.join(sorted(auto_fixable))}."
            )
        rules = tuple(sorted(normalized_rules))

    effective = _merge_overrides(
        config,
        database_url=database_url,
        schemas_csv=schemas,
        fail_on=None,
    )

    if effective.database_url is None:
        raise ToolError(
            "No database connection: pass --database-url or set DATABASE_URL."
        )

    try:
        with psycopg.connect(effective.database_url) as conn:
            schema = introspect(conn, schemas=effective.schemas)
            try:
                fixes = generate_fixes(
                    schema,
                    rule_options=effective.rule_options,
                    rule_filter=set(rules) if rules else None,
                )
            except (TypeError, ValueError) as exc:
                raise ToolError(str(exc)) from exc

            if not fixes:
                click.echo(
                    "pgrls: no auto-fixable violations found.",
                    err=True,
                )
                return

            # SQL bodies + their `-- [rule] description` comments
            # go to stdout so `pgrls fix > migration.sql` produces
            # a clean, paste-able script.
            for f in fixes:
                click.echo(f"-- [{f.rule_id}] {f.description}")
                click.echo(f.sql)
                click.echo()

            if apply:
                with conn.cursor() as cur:
                    # Advisory lock keyed on a stable hash of
                    # 'pgrls.fix' so two concurrent `pgrls fix
                    # --apply` runs serialize. Without this, the
                    # second process would introspect a stale
                    # snapshot, regenerate fixes against pre-
                    # mutation policy text, and either undo the
                    # first process's PERF001 wrap or double-
                    # wrap it.
                    cur.execute(
                        "SELECT pg_advisory_xact_lock("
                        "hashtext('pgrls.fix'))"
                    )
                    for i, f in enumerate(fixes, start=1):
                        try:
                            cur.execute(f.sql)
                        except psycopg.Error as exc:
                            # All-or-nothing: psycopg's connection
                            # context manager rolls back on
                            # exception. Surface the failing SQL,
                            # the underlying psycopg error, AND a
                            # remediation hint so the user can act
                            # without scrolling back through
                            # stdout to find which `-- [rule]`
                            # block matched.
                            conn.rollback()
                            raise ToolError(
                                _fix_apply_failure_message(
                                    i, len(fixes), f, exc
                                )
                            ) from exc
                conn.commit()
                click.echo(
                    f"pgrls: applied {len(fixes)} "
                    f"fix{'es' if len(fixes) != 1 else ''}.",
                    err=True,
                )
            else:
                click.echo(
                    f"pgrls: {len(fixes)} "
                    f"fix{'es' if len(fixes) != 1 else ''} ready "
                    "(dry-run). Re-run with --apply to execute.",
                    err=True,
                )
    except psycopg.Error as exc:
        raise ToolError(f"Database error: {exc}") from exc
    except ValueError as exc:
        raise ToolError(str(exc)) from exc


@main.command()
@click.option(
    "--database-url",
    envvar="DATABASE_URL",
    help="Postgres connection string. Falls back to $DATABASE_URL.",
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True, dir_okay=False),
    default=None,
    help="Path to pgrls.toml. Defaults to ./pgrls.toml if present.",
)
@click.option(
    "--schemas",
    default=None,
    help="Comma-separated schemas to scan (overrides config).",
)
@click.option(
    "--output",
    "-o",
    "output_path",
    type=click.Path(dir_okay=False),
    default=None,
    help="Path to write the JSON snapshot (default: stdout).",
)
def snapshot(
    database_url: str | None,
    config_path: str | None,
    schemas: str | None,
    output_path: str | None,
) -> None:
    """Capture a JSON snapshot of the database's RLS state.

    The snapshot format is documented in CHANGELOG.md and is
    intended to be consumed by `pgrls diff` (or stored as a
    baseline in CI). Output is the same JSON shape
    `Schema.to_snapshot()` produces — top-level `version` plus a
    `tables` list, deterministic within a single Postgres
    instance.

    Without `--output`, the snapshot is written to stdout. With
    `--output PATH`, it's written to the path with a trailing
    newline (POSIX-friendly).
    """
    try:
        config = load_config(config_path)
    except ConfigError as exc:
        raise ToolError(str(exc)) from exc

    effective = _merge_overrides(
        config,
        database_url=database_url,
        schemas_csv=schemas,
        fail_on=None,
    )

    if effective.database_url is None:
        raise ToolError(
            "No database connection: pass --database-url or set DATABASE_URL."
        )

    try:
        with psycopg.connect(effective.database_url) as conn:
            schema = introspect(conn, schemas=effective.schemas)
    except psycopg.Error as exc:
        raise ToolError(f"Database error: {exc}") from exc
    except ValueError as exc:
        raise ToolError(str(exc)) from exc

    payload = json.dumps(schema.to_snapshot(), indent=2, ensure_ascii=False)
    if output_path:
        Path(output_path).write_text(payload + "\n", encoding="utf-8")
    else:
        click.echo(payload)


# ---------------------------------------------------------------------------
# diff helpers
# ---------------------------------------------------------------------------

# Map the user-facing --fail-on value (with hyphens) to the set of internal
# Classification Literal values (with underscores) that should trigger exit 1.
# Keys MUST match `DIFF_FAIL_ON_VALUES` from config.py (the [diff].fail_on
# allowlist). The import-time assertion below pins this — a future change
# that adds a value to one without the other fails at module load.
_FAIL_ON_TO_THRESHOLD: dict[str, set[str]] = {
    "safe":            {"safe", "breaking", "requires_review", "dangerous"},
    "breaking":        {"breaking", "requires_review", "dangerous"},
    "requires-review": {"requires_review", "dangerous"},
    "dangerous":       {"dangerous"},
}

# Cross-module invariant: cli.py's threshold dict keys and config.py's
# allowlist tuple must enumerate the same set of fail-on values. Failing
# this at import surfaces drift via `import pgrls` (caught in unit-test
# collection) instead of at the moment a user passes the un-aligned
# value.
if set(_FAIL_ON_TO_THRESHOLD) != set(DIFF_FAIL_ON_VALUES):
    raise RuntimeError(  # pragma: no cover — import-time invariant
        "pgrls.cli._FAIL_ON_TO_THRESHOLD keys "
        f"{sorted(_FAIL_ON_TO_THRESHOLD)!r} do not match "
        f"pgrls.config.DIFF_FAIL_ON_VALUES {sorted(DIFF_FAIL_ON_VALUES)!r}. "
        "These two surfaces must accept the same set of --fail-on values."
    )


def _classifications_at_or_above(fail_on: str) -> set[str]:
    """Return the set of Classification values that meet or exceed `fail_on`."""
    return _FAIL_ON_TO_THRESHOLD[fail_on]


def _resolve_diff_source(arg: str, *, schemas: list[str]) -> Schema:
    """Resolve a base/head argument into a Schema.

    - If arg starts with `file://` → strip the prefix, treat the rest as
      a local path (matches the URL-shaped form some tools emit).
    - Else if arg contains '://' → treat as DB URL, connect via psycopg, introspect.
    - Else if file exists → load JSON, parse via Schema.from_snapshot.
    - Else raise ToolError (exit 2) with a clear message.

    The schemas filter only applies to URL sources; snapshot files already have
    their filter baked in at capture time.
    """
    # `file://` is a URL by syntax but a path by intent. Strip the
    # prefix and fall through to the file-path branch — psycopg
    # would otherwise try to dial it as a connection string and
    # produce a confusing connection-error message.
    if arg.startswith("file://"):
        arg = arg.removeprefix("file://")
    elif "://" in arg:
        try:
            with psycopg.connect(arg) as conn:
                return introspect(conn, schemas=schemas)
        except psycopg.Error as exc:
            raise ToolError(
                f"Database error connecting to {arg!r}: {exc}"
            ) from exc
        except ValueError as exc:
            raise ToolError(str(exc)) from exc

    p = Path(arg)
    if p.is_file():
        try:
            payload = json.loads(p.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ToolError(
                f"{arg!r}: not valid JSON ({exc.msg} at line {exc.lineno}). "
                "Snapshot files are JSON; for a database URL, include "
                "'://' (e.g. postgres://...)."
            ) from exc
        try:
            return Schema.from_snapshot(payload)
        except (ValueError, KeyError, TypeError) as exc:
            raise ToolError(
                f"{arg!r}: not a valid pgrls snapshot — {exc}"
            ) from exc

    raise ToolError(
        f"{arg!r}: not a database URL (no '://') and not an existing file. "
        "Pass a URL like postgres://... or a path to a snapshot JSON file."
    )


def _apply_migration_for_diff(
    *,
    base_schema: Schema,
    migration_path: str,
    schemas: list[str],
    extensions: tuple[str, ...] = (),
    verbose: bool = False,
) -> Schema:
    """Spin up an ephemeral Postgres, restore base, apply migration, introspect.

    Used by ``pgrls diff --apply migration.sql``. The baseline schema
    is restored via ``Schema.to_sql()``; the migration SQL is applied
    on top; the resulting schema is introspected and returned as the
    diff's "head". The container is torn down at function exit
    (testcontainers context manager).

    Extensions named in the migration's ``CREATE EXTENSION``
    statements (auto-detected via ``detect_extensions``) plus any
    explicitly passed via ``extensions`` are installed before the
    baseline DDL — covers the case where the baseline schema
    assumes the extension is already present.

    Roles referenced by base policies / grants are pre-created
    idempotently in the container so the restore SQL applies. The
    migration SQL is treated as opaque — Postgres parses it. A
    migration that fails to apply surfaces the psycopg error
    verbatim and the caller raises ToolError(exit 2).

    Requires the ``pgrls[diff-apply]`` extra (testcontainers). When
    the extra isn't installed, raises ToolError with a clear
    install hint — the diff command stays usable for the
    snapshot-vs-snapshot and snapshot-vs-DB paths even without
    testcontainers.
    """
    try:
        from testcontainers.postgres import PostgresContainer
    except ImportError as exc:
        raise ToolError(
            "--apply requires the `pgrls[diff-apply]` extra "
            "(testcontainers + Docker). Install with `pip install "
            "'pgrls[diff-apply]'` and ensure Docker is running."
        ) from exc

    try:
        baseline_sql = base_schema.to_sql()
    except ValueError as exc:
        # Snapshot v3/v4 baseline — no column_details, so to_sql
        # can't fabricate the CREATE TABLE statements. Surface the
        # clear "re-capture against v0.5+" message.
        raise ToolError(str(exc)) from exc

    migration_sql = Path(migration_path).read_text(encoding="utf-8")

    # Phase 3 (v0.5.1) — auto-detect extensions named in the
    # migration's CREATE EXTENSION statements; deduplicate against
    # user-supplied --extension flags so a migration with both a
    # CREATE EXTENSION line AND a matching --extension flag doesn't
    # try to install twice (idempotent IF NOT EXISTS handles that
    # too, but the dedup keeps the loop predictable).
    from pgrls.diff._migration_extensions import detect_extensions

    extension_set: set[str] = set(extensions)
    extension_set.update(detect_extensions(migration_sql))

    # Collect the set of role names referenced by base policies
    # and grants so we can pre-create them in the ephemeral
    # container. PUBLIC is a Postgres pseudo-role and doesn't need
    # creation; everything else is created NOLOGIN, idempotent.
    role_names: set[str] = set()
    for table in base_schema.tables:
        for policy in table.policies:
            for role in policy.roles:
                if role != "PUBLIC":
                    role_names.add(role)
        for grant in table.grants:
            if grant.role != "PUBLIC":
                role_names.add(grant.role)

    # Pin to the same Postgres major as the user's CI matrix; the
    # default :latest pull is stable but a migration that depends on
    # PG version-specific syntax could surprise the user. Read from
    # PGRLS_DIFF_APPLY_PG_IMAGE for explicit override, else
    # postgres:17-alpine (the highest in the project's CI matrix).
    base_image = os.environ.get(
        "PGRLS_DIFF_APPLY_PG_IMAGE", "postgres:17-alpine"
    )

    # v0.5.2 baseline cache. Compute the cache key over inputs that
    # determine baseline state; if a cached image exists in the
    # local docker daemon, boot from it and skip the role + extension
    # + baseline-restore steps. On miss, do the setup once and commit
    # the result so the next run with the same inputs can short-
    # circuit. Disabled when PGRLS_DIFF_APPLY_NO_CACHE=1.
    from pgrls.diff import _apply_cache

    # Verbose output goes to stderr so stdout stays machine-parsable.
    # Use a tiny closure rather than a logger so the prefix is
    # consistent across pgrls subcommands and we don't fight Click's
    # echo plumbing.
    import time

    def vlog(msg: str) -> None:
        if verbose:
            click.echo(f"pgrls: {msg}", err=True)

    cache_active = not _apply_cache.cache_disabled()
    cache_key = _apply_cache.compute_cache_key(
        pg_image=base_image,
        baseline_sql=baseline_sql,
        roles=role_names,
        extensions=extension_set,
    )
    cache_tag = _apply_cache.cached_image_tag(cache_key)
    cache_hit = cache_active and _apply_cache.image_exists(cache_tag)

    # Pick the image to boot. On hit we boot the cached image
    # directly (it inherits postgres:VERSION-alpine's entrypoint
    # because it was committed from one). On miss we boot the
    # configured base image and (if caching is active) commit
    # afterwards.
    image = cache_tag if cache_hit else base_image

    if not cache_active:
        vlog(f"cache: disabled (PGRLS_DIFF_APPLY_NO_CACHE set); booting {base_image}")
    elif cache_hit:
        vlog(f"cache: hit {cache_tag}; booting cached image")
    else:
        vlog(f"cache: miss {cache_tag}; booting {base_image} and will commit after baseline restore")

    container = PostgresContainer(
        image,
        username="postgres",
        password="postgres",
        dbname="postgres",
    )
    # Override PGDATA to a path OUTSIDE the postgres image's
    # declared `VOLUME /var/lib/postgresql/data` so docker commit
    # captures the data files in the resulting image's filesystem
    # layer. Without this, the cache would always commit an empty
    # data directory and every "hit" would actually be empty.
    container.with_env("PGDATA", _apply_cache.PGDATA_PATH)

    boot_start = time.monotonic()
    with container as pg:
        vlog(f"booted in {time.monotonic() - boot_start:.2f}s")
        url = pg.get_connection_url(driver=None)
        try:
            with psycopg.connect(url, autocommit=True) as conn:
                with conn.cursor() as cur:
                    if not cache_hit:
                        baseline_start = time.monotonic()
                        # 1. Pre-create roles referenced by base.
                        for role in sorted(role_names):
                            cur.execute(
                                "DO $$ BEGIN "
                                "IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = %s) THEN "
                                "EXECUTE format('CREATE ROLE %%I NOLOGIN', %s); "
                                "END IF; END $$;",
                                (role, role),
                            )
                        if role_names:
                            vlog(f"created {len(role_names)} role(s): {sorted(role_names)}")
                        # 2. Pre-install extensions (auto-detected from
                        # the migration's CREATE EXTENSION statements
                        # + user-supplied --extension flags). IF NOT
                        # EXISTS makes this idempotent — a migration
                        # that has its own CREATE EXTENSION line still
                        # works after we've pre-installed it. Format-
                        # safe identifier interpolation via psycopg's
                        # sql.Identifier defends against unusual names.
                        if extension_set:
                            from psycopg import sql

                            for ext in sorted(extension_set):
                                cur.execute(
                                    sql.SQL(
                                        "CREATE EXTENSION IF NOT EXISTS {}"
                                    ).format(sql.Identifier(ext))
                                )
                            vlog(
                                f"pre-installed {len(extension_set)} extension(s): "
                                f"{sorted(extension_set)}"
                            )
                        # 3. Restore baseline DDL.
                        cur.execute(baseline_sql)
                        vlog(f"baseline restored in {time.monotonic() - baseline_start:.2f}s")
                        # 4. Cache commit. CHECKPOINT first so dirty
                        # buffers hit disk before the docker layer
                        # snapshot is taken; otherwise the cached
                        # image could carry torn writes that confuse
                        # crash recovery on next boot.
                        if cache_active:
                            commit_start = time.monotonic()
                            cur.execute("CHECKPOINT;")
                            wrapped = pg.get_wrapped_container()
                            if wrapped is not None:
                                _apply_cache.commit_baseline(
                                    container_id=wrapped.id,
                                    tag=cache_tag,
                                )
                                vlog(
                                    f"committed baseline cache {cache_tag} in "
                                    f"{time.monotonic() - commit_start:.2f}s"
                                )
                    # 5. Apply migration as a single multi-statement
                    # script. Any syntax / runtime error surfaces as
                    # a psycopg.Error caught below. Runs on every
                    # invocation; only baseline setup is cached.
                    migration_start = time.monotonic()
                    cur.execute(migration_sql)
                    vlog(f"migration applied in {time.monotonic() - migration_start:.2f}s")
            # 6. Introspect the resulting schema.
            introspect_start = time.monotonic()
            with psycopg.connect(url) as conn:
                result = introspect(conn, schemas=schemas)
            vlog(f"introspected in {time.monotonic() - introspect_start:.2f}s")
            return result
        except psycopg.Error as exc:
            raise ToolError(
                f"--apply: migration {migration_path!r} failed against "
                f"the restored baseline: {exc}"
            ) from exc


# ---------------------------------------------------------------------------
# diff command
# ---------------------------------------------------------------------------

_DIFF_FAIL_ON_VALUES = list(DIFF_FAIL_ON_VALUES)
_DIFF_FORMAT_VALUES = list(DIFF_SUPPORTED_FORMATS)


# Dispatch table for `pgrls diff --format <choice>`. Each entry
# pairs the user-facing choice with (renderer, click.echo nl arg).
# `text` ends without a trailing newline (the formatter emits a
# clean summary line as the final line); pass `nl=True` so the
# terminal's prompt lands on its own line. `json` and `sarif`
# delegate to the lint formatters which already emit a final
# newline; pass `nl=False` to avoid doubling. Mirrors the
# `_FORMATTERS` dispatch dict in `pgrls.formatters` — adding a
# new diff format requires only this dict + the formatter
# function + an entry in `DIFF_SUPPORTED_FORMATS`.
_DIFF_FORMATTERS: dict[str, tuple[Callable[[list[Change]], str], bool]] = {
    "text": (format_diff_text, True),
    "json": (format_diff_json, False),
    "sarif": (format_diff_sarif, False),
}


@main.command()
@click.argument("base", required=True)
@click.argument("head", required=False, default=None)
@click.option(
    "--database-url",
    envvar="DATABASE_URL",
    default=None,
    help=(
        "Postgres connection string used as the head when <head> is "
        "omitted. Falls back to $DATABASE_URL, then [database].url "
        "in pgrls.toml. Ignored when <head> is given explicitly."
    ),
)
@click.option(
    "--fail-on",
    "fail_on",
    type=click.Choice(_DIFF_FAIL_ON_VALUES, case_sensitive=False),
    default=None,
    help=(
        "Exit 1 when any change at or above this classification is present. "
        "Falls back to [diff].fail_on in pgrls.toml, then to 'dangerous' "
        "as the built-in default."
    ),
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(_DIFF_FORMAT_VALUES, case_sensitive=False),
    default="text",
    show_default=True,
    help="Output format.",
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True, dir_okay=False),
    default=None,
    help="Path to pgrls.toml. Defaults to ./pgrls.toml if present.",
)
@click.option(
    "--schemas",
    default=None,
    help="Comma-separated schemas to introspect (applied to URL sources only).",
)
@click.option(
    "--apply",
    "migration_path",
    type=click.Path(exists=True, dir_okay=False),
    default=None,
    help=(
        "Path to a SQL migration file. Diff against the post-migration "
        "schema by spinning up an ephemeral Postgres testcontainer, "
        "restoring <base> via Schema.to_sql(), applying the migration, "
        "and introspecting the result. Mutually exclusive with <head>. "
        "Requires `pip install pgrls[diff-apply]`."
    ),
)
@click.option(
    "--extension",
    "extensions",
    multiple=True,
    default=(),
    help=(
        "Extension to pre-install in the ephemeral testcontainer "
        "before applying the migration. Repeatable. Use this when the "
        "baseline schema assumes an extension is already present "
        "(e.g. `citext` columns) but the migration doesn't declare "
        "it. Extensions named in the migration's CREATE EXTENSION "
        "statements are auto-detected and don't need to be listed "
        "here. Only meaningful with --apply."
    ),
)
@click.option(
    "-v",
    "--verbose",
    "verbose",
    is_flag=True,
    default=False,
    help=(
        "Emit progress + cache + timing telemetry on stderr. With "
        "--apply, prints whether the baseline cache hit or missed, "
        "the cache image tag, and per-step timings. Output on stdout "
        "is unchanged so the diff JSON / SARIF / text payload stays "
        "machine-parsable."
    ),
)
def diff(
    base: str,
    head: str | None,
    database_url: str | None,
    fail_on: str | None,
    output_format: str,
    config_path: str | None,
    schemas: str | None,
    migration_path: str | None,
    extensions: tuple[str, ...],
    verbose: bool,
) -> None:
    """Diff two RLS schema snapshots — report semantic changes with classification."""
    try:
        config = load_config(config_path)
    except ConfigError as exc:
        raise ToolError(str(exc)) from exc

    # --apply and <head> are mutually exclusive. --apply produces
    # the head from the migration; specifying <head> too is
    # ambiguous about which one wins.
    if migration_path is not None and head is not None:
        raise ToolError(
            "--apply and <head> are mutually exclusive. Pass either a "
            "migration file (post-migration head computed via "
            "ephemeral Postgres) or a head argument (URL or snapshot), "
            "not both."
        )

    # --extension only makes sense with --apply (it controls the
    # ephemeral testcontainer's environment); warn if passed without
    # --apply rather than silently ignore.
    if extensions and migration_path is None:
        click.echo(
            "pgrls: warning: --extension is ignored without --apply "
            "(it pre-installs extensions in the testcontainer used "
            "by --apply; without --apply there's no testcontainer).",
            err=True,
        )

    # `--fail-on` fallback chain:
    #   1. CLI flag (if passed; Click resolves to lower-case via Choice).
    #   2. `[diff].fail_on` in pgrls.toml (config.diff_fail_on, default "dangerous").
    # Without this, `[diff].fail_on` is silently ignored when the
    # CLI flag default takes precedence — defeating the point of
    # configuring it in TOML.
    effective_fail_on: str = fail_on if fail_on is not None else config.diff_fail_on

    # Resolve --schemas (CSV) — only passed to URL-source resolution.
    if schemas:
        schema_list = [s.strip() for s in schemas.split(",") if s.strip()]
        if not schema_list:
            raise ToolError(
                f"--schemas {schemas!r} produced an empty list."
            )
    else:
        schema_list = config.schemas

    # Default head fallback chain (mirrors `pgrls lint` / `snapshot`):
    #   1. <head> positional arg (already-resolved before this point)
    #   2. --database-url flag (Click reads $DATABASE_URL via envvar=)
    #   3. [database].url in pgrls.toml (lives on config.database_url)
    # --apply bypasses this entirely — the head comes from applying
    # the migration to a restored copy of <base>, not from any
    # external source.
    if migration_path is None and head is None:
        head = database_url or config.database_url
        if head is None:
            raise ToolError(
                "No head: pass <head> argument, set DATABASE_URL, "
                "or configure [database].url in pgrls.toml."
            )

    # Warn early if --schemas was passed explicitly but neither side
    # is a URL — snapshot files are pre-filtered at capture time, so
    # the flag is silently ineffective on file inputs. Without this
    # warning, a user typing `pgrls diff base.json head.json --schemas
    # app` would get a misleadingly-passing run that didn't filter at
    # all. Only warn when the user passed --schemas explicitly (CLI
    # arg, not toml inheritance) AND both sources are file-shaped.
    #
    # `file://` URLs are URL-shaped by syntax but resolve as snapshot
    # files in `_resolve_diff_source` (the prefix is stripped). Treat
    # them as files for the warning gate so a `pgrls diff file://...
    # file://...` invocation doesn't silently swallow the --schemas
    # warning.
    def _is_db_url(arg: str) -> bool:
        return "://" in arg and not arg.startswith("file://")

    base_is_url = _is_db_url(base)
    head_is_url = _is_db_url(head) if head is not None else False
    if schemas and not (base_is_url or head_is_url) and migration_path is None:
        click.echo(
            "pgrls: warning: --schemas is ignored when both <base> and "
            "<head> are snapshot files (filters apply only to live DB "
            "introspection). Snapshots are already filtered at "
            "`pgrls snapshot` capture time.",
            err=True,
        )

    base_schema = _resolve_diff_source(base, schemas=schema_list)

    if migration_path is not None:
        # --apply path: spin up testcontainer, restore base via
        # Schema.to_sql(), apply migration, introspect → head.
        head_schema = _apply_migration_for_diff(
            base_schema=base_schema,
            migration_path=migration_path,
            schemas=schema_list,
            extensions=extensions,
            verbose=verbose,
        )
    else:
        assert head is not None  # guaranteed by the fallback chain above
        head_schema = _resolve_diff_source(head, schemas=schema_list)

    changes = diff_schemas(base_schema, head_schema)

    # --fail-on filter
    threshold_classifications = _classifications_at_or_above(effective_fail_on)
    failing = [c for c in changes if c.classification in threshold_classifications]

    # Format and emit. Single dispatch via _DIFF_FORMATTERS keeps
    # the format list in lockstep with DIFF_SUPPORTED_FORMATS.
    formatter, append_newline = _DIFF_FORMATTERS[output_format]
    click.echo(formatter(changes), nl=append_newline)

    if failing:
        sys.exit(1)


# ---------------------------------------------------------------------------
# pgrls cache — manage the v0.5.2 baseline cache for `diff --apply`
# ---------------------------------------------------------------------------


@main.group()
def cache() -> None:
    """Manage the baseline-image cache used by ``pgrls diff --apply``.

    The cache lives in the local Docker daemon as tagged images
    named ``pgrls-baseline:<HASH>`` with the
    ``org.pgrls.cache=baseline`` label. These commands are thin
    wrappers around ``docker images`` / ``docker image rm`` so
    you don't need to remember the label-filter incantation.
    """


def _cache_images() -> list[Any]:
    """Return the list of locally-cached baseline images.

    Filters by the ``org.pgrls.cache=baseline`` label so user-
    tagged images that happen to start with ``pgrls-baseline``
    are not picked up; only images this CLI committed are
    returned. Element type is ``docker.models.images.Image``
    but typed as ``Any`` here so we can avoid pulling the
    docker SDK into the import-time module surface — the SDK
    is only required when the diff-apply extra is installed.
    """
    try:
        import docker

        from pgrls.diff import _apply_cache
    except ImportError:
        raise ToolError(
            "`pgrls cache` requires the docker SDK. Install via "
            "`pip install 'pgrls[diff-apply]'`."
        ) from None

    try:
        client = docker.from_env()
        result: list[Any] = list(
            client.images.list(
                filters={
                    "label": (
                        f"{_apply_cache.CACHE_LABEL_KEY}="
                        f"{_apply_cache.CACHE_LABEL_VALUE}"
                    )
                }
            )
        )
        return result
    except Exception as exc:  # noqa: BLE001
        # Docker daemon down / unreachable — surface as ToolError
        # rather than an uncaught traceback.
        raise ToolError(
            f"Docker daemon error while listing cache images: {exc}"
        ) from exc


@cache.command("list")
def cache_list() -> None:
    """List baseline images currently cached locally.

    One image per line: ``<tag>  <size>``. Total image count
    and combined disk usage are summarized on the final line.
    Empty cache → "no cached baselines."
    """
    # Lazy import to keep `pgrls cache --help` fast even when the
    # diff-apply extra isn't installed.
    from pgrls.diff import _apply_cache

    images = _cache_images()
    if not images:
        click.echo("pgrls cache: no cached baselines.")
        return

    total_bytes = 0
    rows: list[tuple[str, int]] = []
    for image in images:
        # Each image may carry multiple tags; only the
        # `pgrls-baseline:*` ones are interesting here.
        size = int(image.attrs.get("Size", 0))
        total_bytes += size
        tags = [
            t for t in (image.tags or [])
            if t.startswith(f"{_apply_cache.CACHE_IMAGE_REPO}:")
        ]
        for tag in tags or [f"<untagged {image.short_id}>"]:
            rows.append((tag, size))

    # Sort by tag for stable output across runs.
    rows.sort()
    width = max(len(tag) for tag, _ in rows)
    for tag, size in rows:
        click.echo(f"{tag.ljust(width)}  {_human_bytes(size)}")
    click.echo(
        f"-- {len(rows)} image(s), {_human_bytes(total_bytes)} total"
    )


def _human_bytes(n: int) -> str:
    """Compact size string: 437MB rather than 437,234,128 bytes.

    Decimal (1000-based) rather than binary because that's how
    Docker reports image sizes — keeps the numbers consistent
    with what `docker images` shows.
    """
    units = ("B", "kB", "MB", "GB", "TB")
    size = float(n)
    for unit in units:
        if size < 1000:
            return f"{size:.0f}{unit}" if unit == "B" else f"{size:.1f}{unit}"
        size /= 1000
    return f"{size:.1f}PB"


@cache.command("prune")
@click.option(
    "--yes",
    "-y",
    "assume_yes",
    is_flag=True,
    default=False,
    help="Skip the confirmation prompt (for CI / scripts).",
)
def cache_prune(assume_yes: bool) -> None:
    """Remove every locally-cached baseline image.

    Matches images by the ``org.pgrls.cache=baseline`` label, so
    user-tagged images that happen to share the
    ``pgrls-baseline:`` prefix are NOT removed. Prompts for
    confirmation unless ``--yes`` is passed.
    """
    images = _cache_images()
    if not images:
        click.echo("pgrls cache: nothing to prune (no cached baselines).")
        return

    if not assume_yes:
        total_bytes = sum(int(i.attrs.get("Size", 0)) for i in images)
        click.echo(
            f"pgrls cache: about to remove {len(images)} cached baseline(s) "
            f"reclaiming {_human_bytes(total_bytes)}."
        )
        if not click.confirm("Proceed?"):
            click.echo("aborted.")
            return

    import docker

    client = docker.from_env()
    removed = 0
    for image in images:
        try:
            client.images.remove(image.id, force=True)
            removed += 1
        except Exception as exc:  # noqa: BLE001
            click.echo(
                f"pgrls cache: failed to remove {image.short_id}: {exc}",
                err=True,
            )
    click.echo(f"pgrls cache: removed {removed} image(s).")
