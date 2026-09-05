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

import inspect
import json
import os
import sys
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import click
import psycopg

from pgrls import __version__
from pgrls.baseline import (
    BaselineError,
    load_baseline,
    partition,
    stale_keys,
    write_baseline,
)
from pgrls.config import (
    DIFF_FAIL_ON_VALUES,
    DIFF_RENAME_CLASSIFICATION_VALUES,
    DIFF_RENAME_DETECTION_VALUES,
    Config,
    ConfigError,
    load_config,
)
from pgrls.diff import Change, diff_schemas
from pgrls.diff.formatters import (
    DIFF_SUPPORTED_FORMATS,
    format_diff_html,
    format_diff_json,
    format_diff_markdown,
    format_diff_sarif,
    format_diff_text,
)
from pgrls.fixers import (
    Fix,
    default_fixers,
    generate_fixes,
    render_fixes,
    render_migration,
)
from pgrls.formatters import SUPPORTED_FORMATS, format_violations
from pgrls.generate import GenerateOptions, GenerateResult, plan_generation
from pgrls.history import (
    HISTORY_FORMATS,
    build_rows,
    load_snapshots,
)
from pgrls.history import render as render_history
from pgrls.introspect import introspect
from pgrls.model import Schema
from pgrls.matrix import MATRIX_FORMATS, build_matrix
from pgrls.matrix import render as render_matrix
from pgrls.verify import (
    DEFAULT_AUTH_FUNCTIONS,
    VERIFY_FORMATS,
    Verification,
    build_verification,
    diff_verifications,
    render_delta_json,
    render_delta_text,
)
from pgrls.verify import render as render_verify
from pgrls.verify import render_sarif as render_verify_sarif
from pgrls.probe import run_probe
from pgrls.probe import render as render_probe
from pgrls.probe import render_sarif as render_probe_sarif
from pgrls.report import REPORT_FORMATS, build_report
from pgrls.report import render as render_report
from pgrls.coverage import COVERAGE_FORMATS, DEFAULT_ARTIFACT_PATH, CoverageData, build_coverage
from pgrls.coverage import load_artifact as load_coverage_artifact
from pgrls.coverage import render as render_coverage
from pgrls.perf import (
    DEFAULT_PERF_ARTIFACT_PATH,
    PERF_FORMATS,
    PerfThresholds,
    StatementStat,
    TableStats,
    build_perf_report,
    collect_statements,
    collect_table_stats,
    load_perf_artifact,
    top_statements_for,
    write_perf_artifact,
)
from pgrls.perf import render as render_perf
from pgrls.rules import (
    Rule,
    RuleRegistry,
    all_rules,
    default_registry,
    load_extra_rules,
)
from pgrls.violations import (
    ALL_SEVERITIES,
    Severity,
    Violation,
    coerce_severity,
    is_at_or_above,
)
from pgrls.schema_sources import (
    SchemaSource,
    SchemaSourceError,
    WarnCommand,
    inert_rule_ids,
    reparse_policy_asts,
    resolve_schema,
    schema_source_warnings,
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


# ---------------------------------------------------------------------------
# Shared option decorators
# ---------------------------------------------------------------------------
#
# The `--database-url` / `--config` / `--schemas` trio is identical across
# every command that connects to a live database, and the `--output` /
# `--format` pair recurs on the report-style commands. Declaring them once
# here (and stacking them onto each command) keeps the option metadata —
# names, envvars, defaults, types, and help — in lockstep across commands;
# previously the help strings had drifted ("schemas to lint" vs "to scan"
# vs "to report on"). The canonical `--schemas` help is the generic
# "scan" wording. Commands whose option genuinely differs (e.g. `diff`'s
# URL-source `--schemas`, `explain`'s catalog-only `--config`) keep their
# own bespoke declarations rather than forcing a mismatched shared one.


def common_db_options(func: Callable[..., Any]) -> Callable[..., Any]:
    """Stack the shared `--database-url` / `--config` / `--schemas` options.

    Applied (in this order) so the rendered `--help` lists database-url,
    then config, then schemas — matching the long-standing layout of
    every connect-to-Postgres command. Decorators apply bottom-up, so the
    options are declared here in reverse of the displayed order.
    """
    func = click.option(
        "--schemas",
        default=None,
        help="Comma-separated schemas to scan (overrides config).",
    )(func)
    func = click.option(
        "--config",
        "config_path",
        type=click.Path(exists=True, dir_okay=False),
        default=None,
        help="Path to pgrls.toml. Defaults to ./pgrls.toml if present.",
    )(func)
    func = click.option(
        "--database-url",
        envvar="DATABASE_URL",
        help="Postgres connection string. Falls back to $DATABASE_URL.",
    )(func)
    return func


def output_format_options(
    formats: list[str], *, output_help: str
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Stack the shared `--output` / `--format` pair (output shown first).

    `formats` is the `--format` choice list (each command supports a
    different set); `output_help` is the per-command help for `--output`
    (the destination wording differs — "report" vs "trend report" etc.).
    Everything else — option names, the `-o` short flag, types, defaults,
    `--format`'s "Output format." help and `text` default — is identical,
    so it lives here.
    """

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        func = click.option(
            "--format",
            "output_format",
            type=click.Choice(formats, case_sensitive=False),
            default="text",
            show_default=True,
            help="Output format.",
        )(func)
        func = click.option(
            "--output",
            "-o",
            "output_path",
            type=click.Path(dir_okay=False),
            default=None,
            help=output_help,
        )(func)
        return func

    return decorator


def migration_source_options(func: Callable[..., Any]) -> Callable[..., Any]:
    """Stack the shared `--migrations` ephemeral-build options.

    Lets a command introspect a schema built from migration files in a
    throwaway Postgres instead of connecting to a live database. Used by
    `lint`; the engine lives in `pgrls.ephemeral`. Declared bottom-up so
    `--help` lists `--migrations` first.
    """
    from pgrls.migrations_layout import LAYOUTS

    func = click.option(
        "--pg-image",
        default=None,
        help=(
            "Postgres image for the ephemeral --migrations build "
            "(default: $PGRLS_EPHEMERAL_PG_IMAGE or postgres:17-alpine)."
        ),
    )(func)
    func = click.option(
        "--create-role",
        "create_roles",
        multiple=True,
        help=(
            "Pre-create this role (NOLOGIN) in the ephemeral --migrations "
            "database before applying, so policies/grants referencing it "
            "apply. Repeat for multiple."
        ),
    )(func)
    func = click.option(
        "--supabase",
        is_flag=True,
        default=False,
        help=(
            "Shortcut for a Supabase project: build from ./supabase/migrations "
            "and provision the auth.* stubs + anon/authenticated/service_role "
            "roles. Implies --migrations when none is given."
        ),
    )(func)
    func = click.option(
        "--migrations-glob",
        default=None,
        help="Explicit ordered glob for --migrations-layout glob (e.g. 'db/*.sql').",
    )(func)
    func = click.option(
        "--migrations-layout",
        type=click.Choice(list(LAYOUTS), case_sensitive=False),
        default="auto",
        show_default=True,
        help="Migration layout for --migrations (auto-detected by default).",
    )(func)
    func = click.option(
        "--migrations",
        "migrations_path",
        type=click.Path(exists=True),
        default=None,
        help=(
            "Lint a schema built from these migration files in a throwaway "
            "Postgres (no live database needed): a directory or a .sql file. "
            "Requires Docker and the pgrls[ephemeral] extra."
        ),
    )(func)
    return func


def offline_source_options(func: Callable[..., Any]) -> Callable[..., Any]:
    """Stack the offline schema-source options --sql-file / --snapshot.

    Analyze raw DDL or a snapshot artifact with no live Postgres and no Docker.
    Mutually exclusive with --database-url / --migrations (enforced per
    command). Declared bottom-up so --help lists --sql-file first.
    """
    func = click.option(
        "--snapshot",
        "snapshot",
        type=click.Path(exists=True, dir_okay=False),
        default=None,
        help=(
            "Input artifact produced by `pgrls snapshot` (not an output flag) — "
            "analyze it offline, no live database. Mutually exclusive with "
            "--sql-file / --database-url. "
            "Add --require-full-coverage (lint) to fail a partial offline run."
        ),
    )(func)
    func = click.option(
        "--sql-file",
        "sql_file",
        type=click.Path(allow_dash=True, dir_okay=False),
        multiple=True,
        help=(
            "Analyze raw DDL from this file offline (no live database); repeat "
            "for several files (concatenated in order — declare tables before "
            "the policies/grants that reference them); '-' reads stdin. "
            "Mutually exclusive with --snapshot / --database-url. "
            "Add --require-full-coverage (lint) to fail a partial offline run."
        ),
    )(func)
    return func


@main.command()
@click.pass_context
@common_db_options
@migration_source_options
@offline_source_options
@click.option(
    "--rule",
    "rules",
    multiple=True,
    help=(
        "Only run these rules (repeat for multiple). "
        "Case-insensitive. Overrides `[lint] disable` in the config."
    ),
)
@click.option(
    "--exclude-rule",
    "exclude_rules",
    multiple=True,
    help=(
        "Skip these rules (repeat for multiple). Case-insensitive. "
        "The complement of --rule: runs everything else. Applied "
        "after --rule, so the two cannot name the same rule."
    ),
)
@click.option(
    "--min-severity",
    type=click.Choice(list(ALL_SEVERITIES), case_sensitive=False),
    default=None,
    help=(
        "Only display findings at or above this severity (error | "
        "warning | info). Affects the printed report only — the exit "
        "code still reflects every finding per --fail-on."
    ),
)
@click.option(
    "--output",
    "-o",
    "output_path",
    type=click.Path(dir_okay=False),
    default=None,
    help=(
        "Write the report to this file instead of stdout "
        "(any --format). Cannot be combined with --update-baseline."
    ),
)
@click.option(
    "--explain",
    is_flag=True,
    default=False,
    help=(
        "Append each rule's reference paragraph to its finding in "
        "the text output, for in-line rationale without a separate "
        "`pgrls explain <RULE>` lookup. Text format only."
    ),
)
@click.option(
    "--update-baseline",
    is_flag=True,
    default=False,
    help=(
        "Refresh the baseline file (named by --baseline) in place "
        "with the current findings — accept every current finding "
        "as the new baseline. Suppresses normal lint output and "
        "exits 0 on success. Requires --baseline."
    ),
)
@click.option(
    "--fail-on",
    type=click.Choice(list(ALL_SEVERITIES), case_sensitive=False),
    default=None,
    help="Severity threshold that triggers nonzero exit.",
)
@click.option(
    "--require-full-coverage",
    is_flag=True,
    default=False,
    help=(
        "Fail (exit 1) if an offline source (--sql-file / --snapshot) could "
        "not evaluate every rule — so a partial offline run cannot pass CI "
        "silently. No effect on a live-database run."
    ),
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
@click.option(
    "--coverage",
    "coverage_path",
    type=click.Path(dir_okay=False),
    default=None,
    help=(
        "Path to a coverage artifact from your pgrls.testing run "
        "(.pgrls-coverage.json). Enables HYG004 (policy has no "
        "behavioral test), which is inert without it. See `pgrls "
        "coverage` for the full report."
    ),
)
@click.option(
    "--perf",
    "perf_path",
    type=click.Path(dir_okay=False),
    default=None,
    help=(
        "Path to a runtime-stats artifact from `pgrls perf --snapshot` "
        "(.pgrls-perf.json). Enables PERF005 (RLS table observed to "
        "seq-scan), which is inert without it. See `pgrls perf` for the "
        "full report."
    ),
)
def lint(
    ctx: click.Context,
    database_url: str | None,
    config_path: str | None,
    schemas: str | None,
    rules: tuple[str, ...],
    exclude_rules: tuple[str, ...],
    min_severity: str | None,
    output_path: str | None,
    explain: bool,
    update_baseline: bool,
    fail_on: str | None,
    require_full_coverage: bool,
    output_format: str,
    baseline_path: Path | None,
    coverage_path: str | None,
    perf_path: str | None,
    migrations_path: str | None,
    migrations_layout: str,
    migrations_glob: str | None,
    supabase: bool,
    create_roles: tuple[str, ...],
    pg_image: str | None,
    sql_file: tuple[str, ...],
    snapshot: str | None,
) -> None:
    """Lint Postgres RLS policies for security and hygiene issues."""
    if update_baseline and baseline_path is None:
        raise ToolError(
            "--update-baseline requires --baseline FILE to name "
            "the file to refresh."
        )
    if update_baseline and output_path is not None:
        raise ToolError(
            "--output and --update-baseline cannot be combined: "
            "--update-baseline records findings into the baseline "
            "file and prints no report, so there is nothing for "
            "--output to write."
        )
    if update_baseline and require_full_coverage:
        raise ToolError(
            "--update-baseline records findings and exits 0; it cannot be "
            "combined with --require-full-coverage. Run them separately."
        )
    try:
        config = load_config(config_path)
    except ConfigError as exc:
        raise ToolError(str(exc)) from exc

    known = {r.id for r in _runtime_rules(config)}

    # Validate `--rule` early — a typo silently producing zero
    # findings is hard to debug. Mirrors `pgrls fix --rule`.
    rules = _validate_rule_filter(rules, known, kind="")

    # `--exclude-rule` — same typo validation, plus a contradiction
    # check against --rule (naming a rule in both is incoherent).
    exclude_ids: set[str] = set()
    if exclude_rules:
        exclude_ids = {r.upper() for r in exclude_rules}
        unknown = sorted(exclude_ids - known)
        if unknown:
            raise ToolError(
                f"unknown rule(s) in --exclude-rule: "
                f"{', '.join(unknown)}. "
                f"Available: {', '.join(sorted(known))}."
            )
        both = sorted(set(rules) & exclude_ids)
        if both:
            raise ToolError(
                f"rule(s) named in both --rule and --exclude-rule: "
                f"{', '.join(both)}. A rule cannot be selected and "
                "excluded at once."
            )
    # Capture the user-supplied exclude set BEFORE the offline code unions
    # inert rule IDs into exclude_ids.  We need it to compute gating_skipped.
    user_exclude_ids: set[str] = set(exclude_ids)

    effective = _merge_overrides(
        config,
        database_url=database_url,
        schemas_csv=schemas,
        fail_on=fail_on,
    )

    # Schema source: a live database (--database-url) or an ephemeral build
    # from migration files (--migrations / --supabase) — never both. An
    # ambient $DATABASE_URL must not block the ephemeral path (it is the
    # common CI setup), so the conflict fires only when --database-url was
    # passed explicitly on the command line.
    use_migrations = migrations_path is not None or supabase
    db_url_explicit = (
        ctx.get_parameter_source("database_url")
        is click.core.ParameterSource.COMMANDLINE
    )
    if use_migrations and db_url_explicit:
        raise ToolError(
            "choose one schema source: a live database (--database-url) or "
            "an ephemeral build (--migrations / --supabase), not both."
        )
    if not use_migrations:
        # The ephemeral-only options are meaningless without --migrations /
        # --supabase; reject them rather than silently lint the live DB.
        layout_explicit = (
            ctx.get_parameter_source("migrations_layout")
            is click.core.ParameterSource.COMMANDLINE
        )
        if (
            migrations_glob is not None
            or pg_image is not None
            or create_roles
            or layout_explicit
        ):
            raise ToolError(
                "--migrations-layout / --migrations-glob / --create-role / "
                "--pg-image apply only to an ephemeral build — pass "
                "--migrations or --supabase (or drop these options)."
            )

    # Offline schema source: raw DDL (--sql-file) or a snapshot artifact
    # (--snapshot). Mutually exclusive with live-database and ephemeral paths.
    schema_source: SchemaSource | None = None
    # Rules inert on this offline source — computed once and reused for both the
    # auto-exclude (so they don't run) and the gating-skipped notice / coverage
    # gate below, keeping the two consistent.
    schema_source_inert: frozenset[str] = frozenset()
    offline = _resolve_offline_schema(
        sql_file=sql_file, snapshot=snapshot, schemas_csv=schemas, command="lint"
    )
    if offline is not None:
        if use_migrations or db_url_explicit:
            raise ToolError(
                "choose one schema source: an offline source (--sql-file / "
                "--snapshot), a live database (--database-url), or an "
                "ephemeral build (--migrations), not more than one."
            )
        schema, schema_source, schema_source_version = offline
        schema_source_inert = inert_rule_ids(
            schema_source, snapshot_version=schema_source_version
        )
        exclude_ids |= schema_source_inert

    # Load the RLS test-coverage artifact if `--coverage` was passed. It
    # feeds HYG004 (policy has no behavioral test), inert otherwise.
    # Loaded before connecting so a bad path fails fast.
    coverage_data: CoverageData | None = None
    if coverage_path is not None:
        try:
            coverage_data = load_coverage_artifact(coverage_path)
        except FileNotFoundError as exc:
            raise ToolError(
                f"Coverage artifact {coverage_path!r} not found. Run your "
                "pgrls.testing suite first — it writes .pgrls-coverage.json "
                "on finish — or omit --coverage."
            ) from exc
        except (ValueError, OSError) as exc:
            raise ToolError(
                f"Cannot read coverage artifact {coverage_path!r}: {exc}"
            ) from exc

    # Load the runtime-stats artifact if `--perf` was passed. It feeds
    # PERF005 (RLS table observed to seq-scan), inert otherwise.
    perf_data: dict[tuple[str, str], TableStats] | None = None
    if perf_path is not None:
        try:
            perf_data = load_perf_artifact(perf_path)
        except FileNotFoundError as exc:
            raise ToolError(
                f"Perf artifact {perf_path!r} not found. Run `pgrls perf "
                "--snapshot .pgrls-perf.json` first, or omit --perf."
            ) from exc
        except (ValueError, OSError) as exc:
            raise ToolError(
                f"Cannot read perf artifact {perf_path!r}: {exc}"
            ) from exc

    if offline is None:
        if use_migrations:
            schema = _schema_from_migrations(
                migrations_path=migrations_path,
                migrations_layout=migrations_layout,
                migrations_glob=migrations_glob,
                supabase=supabase,
                create_roles=create_roles,
                pg_image=pg_image,
                schemas=effective.schemas,
            )
        else:
            if effective.database_url is None:
                # If `[database].url` was set but its env-var interpolation
                # failed, surface that specific cause (deferred from
                # load_config) instead of the generic guidance.
                raise ToolError(
                    effective.database_url_error
                    or "No database connection: pass --database-url or set DATABASE_URL."
                )
            try:
                with psycopg.connect(effective.database_url) as conn:
                    schema = introspect(conn, schemas=effective.schemas)
            except psycopg.Error as exc:
                raise ToolError(f"Database error: {exc}") from exc
            except ValueError as exc:
                raise ToolError(str(exc)) from exc

    try:
        violations = _run_rules(
            schema,
            config=effective,
            rule_filter=set(rules) if rules else None,
            exclude_filter=exclude_ids or None,
            coverage_data=coverage_data,
            perf_data=perf_data,
        )
    except (TypeError, ValueError, RuntimeError) as exc:
        raise ToolError(str(exc)) from exc

    # Offline runs skip catalog-only rules; emit a notice so operators can
    # see which rules were not evaluated.
    # Compute the GATING skipped set: inert ∩ {rules that WOULD have run
    # absent the offline auto-exclude}.  This ensures --rule SEC004 does not
    # fail --require-full-coverage (SEC004 is not inert), and --rule SEC016
    # offline is surfaced in the notice rather than being silent.
    if schema_source:
        inert = schema_source_inert
        would_run = (
            set(rules) if rules
            else (known - set(config.disable))
        ) - user_exclude_ids
        gating_skipped = sorted(inert & would_run)
    else:
        gating_skipped = []
    # `gating_skipped` drives all three consistently — the stderr notice, the
    # json `skipped_rules` field, and the `--require-full-coverage` gate — so
    # each reflects only inert rules that would have run. A scoped run like
    # `--rule SEC004` therefore neither reports nor fails on unrelated skips.
    skipped = gating_skipped
    if skipped:
        click.echo(
            f"pgrls: skipped {len(skipped)} catalog-only rule(s) not "
            f"analyzable offline: {', '.join(skipped)}.",
            err=True,
        )

    if update_baseline:
        # `--update-baseline` makes the current findings the new
        # baseline (replace, not merge) — the baseline reflects
        # current state; entries for findings that no longer fire
        # naturally drop. The lint run's job here is to record,
        # not report, so the normal format / fail-on path is
        # skipped and the exit code is 0 on success.
        assert baseline_path is not None  # guarded at the top.
        try:
            count = write_baseline(
                baseline_path, violations, tool_version=__version__
            )
        except BaselineError as exc:
            raise ToolError(str(exc)) from exc
        plural = "" if count == 1 else "s"
        click.echo(
            f"pgrls: updated baseline at {baseline_path} with "
            f"{count} finding{plural}.",
            err=True,
        )
        return

    if baseline_path is not None:
        violations = _apply_baseline(violations, baseline_path)

    # `--min-severity` filters the DISPLAYED findings only; the exit
    # code below still evaluates the full set against --fail-on, so a
    # hidden finding can never silently flip CI green. `displayed` is
    # what the report (and --explain rationale) is built from.
    displayed = violations
    if min_severity is not None:
        floor = coerce_severity(min_severity)
        displayed = [
            v for v in violations if is_at_or_above(v.severity, floor)
        ]

    rationale_map: dict[str, str] | None = None
    if explain:
        # Build a `{rule_id: rationale}` map for every rule that
        # produced a (displayed) finding, so the text formatter can
        # append the rule's reference paragraph beneath each line.
        # Other formats ignore the map; --explain is text-only.
        # Use `_runtime_rules(config)` so extras' rationale lines
        # appear too — without this an extra that fires a finding
        # would be missing its reference paragraph.
        rules_in_use = {v.rule_id for v in displayed}
        rationale_map = {
            r.id: _rule_rationale_paragraph(r)
            for r in _runtime_rules(config)
            if r.id in rules_in_use
        }

    extra_json = (
        {"schema_source": schema_source, "skipped_rules": skipped}
        if schema_source is not None and output_format == "json"
        else None
    )
    report = format_violations(
        displayed,
        format=output_format,
        rationale_map=rationale_map,
        extra_json=extra_json,
    )
    if output_path is not None:
        # Write byte-for-byte what stdout would have received, so a
        # file report is identical to a piped one. `newline=""`
        # disables universal-newline translation on write — without
        # it, the formatter's `\n` would become `\r\n` on Windows
        # while `click.echo` keeps `\n`, breaking the equivalence the
        # parser-stability tests rely on.
        try:
            Path(output_path).write_text(
                report, encoding="utf-8", newline=""
            )
        except OSError as exc:
            raise ToolError(f"Cannot write {output_path}: {exc}") from exc
    else:
        click.echo(report, nl=False)

    fail = _should_fail(violations, threshold=effective.fail_on)
    if require_full_coverage and skipped:
        click.echo(
            "pgrls: --require-full-coverage: offline run skipped "
            f"{len(skipped)} rule(s); failing.",
            err=True,
        )
        fail = True
    if fail:
        sys.exit(1)


def _parse_schemas_csv(raw: str) -> list[str]:
    """Split a `--schemas` CSV into a clean, de-whitespaced list.

    The single source of truth for parsing the `--schemas` value:
    splits on commas, trims each entry, and drops empties (so a
    trailing comma or a whitespace-only entry is ignored). Callers
    decide what to do with an empty result — `_merge_overrides` and
    `diff` raise slightly different errors — so the emptiness check is
    intentionally left to them and not done here.
    """
    return [s.strip() for s in raw.split(",") if s.strip()]


def _merge_overrides(
    config: Config,
    *,
    database_url: str | None,
    schemas_csv: str | None,
    fail_on: str | None,
) -> Config:
    if schemas_csv:
        schemas = _parse_schemas_csv(schemas_csv)
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
    effective_database_url = database_url or config.database_url
    return Config(
        database_url=effective_database_url,
        schemas=schemas,
        disable=list(config.disable),
        fail_on=effective_fail_on,
        rule_options=dict(config.rule_options),
        severity_overrides=dict(config.severity_overrides),
        diff_fail_on=config.diff_fail_on,
        # Preserve project-declared custom rules across the override
        # merge — without this they fall back to the dataclass default
        # [] and `pgrls lint` silently never runs them (they still load
        # for `explain`/validation, so the miss looks like coverage).
        extra_rules=list(config.extra_rules),
        # Carry the deferred `[database].url` interpolation error only
        # while it is still relevant: if `--database-url` supplied a
        # URL, the effective URL is non-None and the config's failed
        # interpolation no longer matters, so drop it.
        database_url_error=(
            None
            if effective_database_url is not None
            else config.database_url_error
        ),
    )


def _load_effective_config(
    *,
    config_path: str | None,
    database_url: str | None,
    schemas_csv: str | None,
    fail_on: str | None = None,
) -> Config:
    """Load the config file, merge CLI overrides, and guard the DB URL.

    The first half of nearly every connect-to-Postgres command:
    `load_config` (wrapping `ConfigError` as a `ToolError`), then
    `_merge_overrides`, then the "no database connection" guard. Returns
    the effective `Config` (with a non-None `database_url`). Kept
    separate from `_connect_and_introspect` so the two callers that hold
    the connection open afterward (`fix`, `generate`) can reuse the same
    preamble via `_connect_introspect_ctx`.
    """
    try:
        config = load_config(config_path)
    except ConfigError as exc:
        raise ToolError(str(exc)) from exc

    effective = _merge_overrides(
        config,
        database_url=database_url,
        schemas_csv=schemas_csv,
        fail_on=fail_on,
    )

    if effective.database_url is None:
        # If `[database].url` was set but its env-var interpolation
        # failed, surface that specific cause (deferred from
        # load_config) instead of the generic guidance.
        raise ToolError(
            effective.database_url_error
            or "No database connection: pass --database-url or set DATABASE_URL."
        )
    return effective


_OFFLINE_MAX_BYTES = 8 * 1024 * 1024  # reject pathological untrusted input early


def _offline_effective_config(
    *, config_path: str | None, schemas_csv: str | None
) -> Config:
    """Effective config for an offline run — like `_load_effective_config` but
    WITHOUT the live-DB-required guard (offline never connects)."""
    try:
        config = load_config(config_path)
    except ConfigError as exc:
        raise ToolError(str(exc)) from exc
    return _merge_overrides(
        config, database_url=None, schemas_csv=schemas_csv, fail_on=None
    )


def _guard_offline_exclusivity(
    ctx: click.Context, *, command: str
) -> None:
    """Reject an offline source combined with an explicit --database-url.

    Ambient $DATABASE_URL is fine (the common CI setup) — only an explicit
    command-line --database-url collides, mirroring the --migrations guard.
    """
    if (
        ctx.get_parameter_source("database_url")
        is click.core.ParameterSource.COMMANDLINE
    ):
        raise ToolError(
            "choose one schema source: an offline source (--sql-file / "
            "--snapshot) or a live database (--database-url), not both."
        )


def _reject_apply_offline(apply: bool, command: str) -> None:
    if apply:
        raise ToolError(
            f"--apply needs a live database connection and cannot be used with "
            f"an offline source (--sql-file / --snapshot). Offline {command} is "
            "emit-only: pipe stdout to a migration, or use --output."
        )


def _resolve_offline_schema(
    *,
    sql_file: tuple[str, ...],
    snapshot: str | None,
    schemas_csv: str | None,
    command: WarnCommand,
) -> tuple[Schema, SchemaSource, int | None] | None:
    """Build a Schema from --sql-file / --snapshot, or return None.

    Returns `(schema, source, snapshot_version)` — `snapshot_version` is the
    declared format version of a --snapshot source (used to scope which
    catalog-only rules it can run) and `None` for --sql-file.

    None when neither flag was given (caller keeps its live path). --sql-file is
    repeatable and concatenated in order; '-' reads stdin. Input is byte-capped;
    a pathological-depth parse (RecursionError) and any SchemaSourceError map to
    a ToolError. Prints the command-appropriate soundness caveat to stderr.
    """
    if not sql_file and snapshot is None:
        return None
    schemas = (
        tuple(s.strip() for s in schemas_csv.split(",") if s.strip())
        if schemas_csv
        else None
    )
    if snapshot is not None:
        try:
            snap_size = os.path.getsize(snapshot)
        except OSError as exc:
            raise ToolError(
                f"cannot read --snapshot {snapshot!r}: {exc}"
            ) from exc
        if snap_size > _OFFLINE_MAX_BYTES:
            raise ToolError(
                f"snapshot file {snapshot!r} is "
                f"{snap_size // (1024 * 1024)} MiB, which exceeds the "
                f"{_OFFLINE_MAX_BYTES // (1024 * 1024)} MiB limit. "
                "Use a smaller snapshot or re-capture with a scoped "
                "--schemas filter."
            )
    sql_text: str | None = None
    if sql_file:
        parts: list[str] = []
        total = 0
        for entry in sql_file:
            if entry == "-":
                chunk = sys.stdin.read()
            else:
                try:
                    with open(entry, encoding="utf-8") as fh:
                        chunk = fh.read()
                except OSError as exc:
                    raise ToolError(
                        f"cannot read --sql-file {entry!r}: {exc}"
                    ) from exc
            total += len(chunk.encode("utf-8"))
            if total > _OFFLINE_MAX_BYTES:
                raise ToolError(
                    "offline SQL input exceeds "
                    f"{_OFFLINE_MAX_BYTES // (1024 * 1024)} MiB; split it or "
                    "lint against a live database."
                )
            parts.append(chunk)
        sql_text = "\n".join(parts)
    try:
        schema, source, snapshot_version = resolve_schema(
            sql=sql_text, snapshot=snapshot, schemas=schemas
        )
    except SchemaSourceError as exc:
        where = (
            " ".join(repr(p) for p in sql_file) if sql_file else repr(snapshot)
        )
        raise ToolError(f"{exc.message} (source: {where})") from exc
    except RecursionError as exc:
        raise ToolError(
            "the provided schema has a pathologically deep policy expression "
            "and could not be parsed offline."
        ) from exc
    for line in schema_source_warnings(
        source, command=command, snapshot_version=snapshot_version
    ):
        click.echo(f"pgrls: {line}", err=True)
    return schema, source, snapshot_version


def _connect_and_introspect(
    *,
    config_path: str | None,
    database_url: str | None,
    schemas_csv: str | None,
    fail_on: str | None = None,
) -> tuple[Config, Schema]:
    """Resolve the effective config, connect, and introspect — read-only.

    The full preamble for commands that only need the introspected
    schema (lint, snapshot, report, coverage, perf): load + merge +
    guard via `_load_effective_config`, then open a short-lived psycopg
    connection and introspect. The connection is closed before
    returning. psycopg / value errors are rewrapped as `ToolError`
    with the same messages the call sites used inline. Returns
    `(effective_config, schema)`.
    """
    effective = _load_effective_config(
        config_path=config_path,
        database_url=database_url,
        schemas_csv=schemas_csv,
        fail_on=fail_on,
    )
    assert effective.database_url is not None  # guaranteed above
    try:
        with psycopg.connect(effective.database_url) as conn:
            schema = introspect(conn, schemas=effective.schemas)
    except psycopg.Error as exc:
        raise ToolError(f"Database error: {exc}") from exc
    except ValueError as exc:
        raise ToolError(str(exc)) from exc
    return effective, schema


def _schema_from_migrations(
    *,
    migrations_path: str | None,
    migrations_layout: str,
    migrations_glob: str | None,
    supabase: bool,
    create_roles: tuple[str, ...],
    pg_image: str | None,
    schemas: list[str],
) -> Schema:
    """Build a `Schema` by applying migration files in an ephemeral Postgres.

    Used by `lint --migrations`: resolve the layout to an ordered file
    list, boot a throwaway Postgres
    (`pgrls.ephemeral`), apply them, and introspect. `--supabase` defaults the
    path to ./supabase/migrations and provisions the auth.* stubs + roles.
    `LayoutError` / `EphemeralError` become `ToolError` (exit 2).
    """
    from pgrls import ephemeral
    from pgrls.migrations_layout import LayoutError, resolve_plan

    path_str = migrations_path
    layout = migrations_layout
    if supabase:
        if path_str is None:
            candidate = Path("supabase/migrations")
            path_str = str(candidate if candidate.is_dir() else Path("supabase"))
        # Default to the supabase layout only when the user hasn't asked for a
        # specific layout/glob AND the path is a directory, so --supabase can
        # pair with a custom layout or a single .sql dump (which resolves as
        # the 'sql' layout) instead of erroring "must be a directory".
        if (
            layout == "auto"
            and migrations_glob is None
            and Path(path_str).is_dir()
        ):
            layout = "supabase"
    if path_str is None:
        raise ToolError("no migration source: pass --migrations PATH (or --supabase).")

    try:
        plan = resolve_plan(
            Path(path_str), layout=layout, glob_pattern=migrations_glob
        )
    except LayoutError as exc:
        raise ToolError(str(exc)) from exc

    click.echo(
        f"pgrls: applying {len(plan.files)} migration(s) "
        "in an ephemeral Postgres…",
        err=True,
    )
    # Provision the Supabase auth.* stubs + roles whenever the layout is
    # Supabase — requested via --supabase OR auto-detected — so a Supabase
    # migration that calls auth.uid() / grants to authenticated applies.
    provision = supabase or plan.layout == "supabase"
    try:
        return ephemeral.build_schema_from_migrations(
            sql_files=plan.files,
            schemas=schemas,
            extra_roles=create_roles,
            provision_supabase=provision,
            pg_image=pg_image,
        )
    except ephemeral.EphemeralError as exc:
        raise ToolError(str(exc)) from exc


@contextmanager
def _connect_introspect_ctx(
    *,
    config_path: str | None,
    database_url: str | None,
    schemas_csv: str | None,
    fail_on: str | None = None,
) -> Iterator[tuple[Config, psycopg.Connection[Any], Schema]]:
    """Like `_connect_and_introspect`, but keeps the connection open.

    For `fix` / `generate`, which introspect, generate SQL, and then
    (under `--apply`) execute that SQL on the *same* connection. Yields
    `(effective_config, conn, schema)` inside the `psycopg.connect`
    context manager, so the connection's commit-on-success /
    rollback-on-exception semantics still apply. The psycopg / value
    error rewrapping matches the read-only variant; errors raised by the
    caller's `with` body (e.g. a fixer's `TypeError`, or a `ToolError`)
    propagate unchanged.
    """
    effective = _load_effective_config(
        config_path=config_path,
        database_url=database_url,
        schemas_csv=schemas_csv,
        fail_on=fail_on,
    )
    assert effective.database_url is not None  # guaranteed above
    try:
        with psycopg.connect(effective.database_url) as conn:
            schema = introspect(conn, schemas=effective.schemas)
            yield effective, conn, schema
    except psycopg.Error as exc:
        raise ToolError(f"Database error: {exc}") from exc
    except ValueError as exc:
        raise ToolError(str(exc)) from exc


def _emit(rendered: str, output_path: str | None) -> None:
    r"""Write a rendered report to `--output` or stdout, byte-identically.

    Ensures a single trailing newline, then either writes the text to
    `output_path` (with `newline=""` so the formatter's `\n` is not
    translated to `\r\n` on Windows — the file must match what stdout
    would have received) or echoes it with `click.echo(nl=False)`. An
    `OSError` on write becomes a `ToolError("Cannot write {path}: …")`.
    Shared by report / coverage / perf / history.
    """
    if not rendered.endswith("\n"):
        rendered += "\n"
    if output_path is not None:
        try:
            Path(output_path).write_text(
                rendered, encoding="utf-8", newline=""
            )
        except OSError as exc:
            raise ToolError(f"Cannot write {output_path}: {exc}") from exc
    else:
        click.echo(rendered, nl=False)


def _validate_rule_filter(
    rules: tuple[str, ...], known: set[str], *, kind: str
) -> tuple[str, ...]:
    """Validate and normalize a `--rule` filter against the known ids.

    Upper-cases the requested ids, rejects any not in `known` with the
    shared "unknown {kind}rule(s): … Available: …" message (a typo that
    silently produced zero findings/fixes is hard to debug), and returns
    the sorted, normalized tuple. `kind` distinguishes the two callers'
    wording: `""` for `pgrls lint` ("unknown rule(s)") and
    `"auto-fixable "` for `pgrls fix` ("unknown auto-fixable rule(s)").
    Returns the input unchanged when `rules` is empty.
    """
    if not rules:
        return rules
    normalized = {r.upper() for r in rules}
    unknown = sorted(normalized - known)
    if unknown:
        raise ToolError(
            f"unknown {kind}rule(s): {', '.join(unknown)}. "
            f"Available: {', '.join(sorted(known))}."
        )
    return tuple(sorted(normalized))


def _rule_docstring(rule: Rule) -> str:
    """Return the rule module's docstring, stripped, or '' if absent.

    Shared by `pgrls explain` (which surfaces the whole docstring)
    and `pgrls lint --explain` (which surfaces just its first
    non-title paragraph) so the two paths read the same source
    via the same lookup — no chance of one rule's docstring
    showing up in one command but not the other.
    """
    module = inspect.getmodule(type(rule))
    return ((module.__doc__ if module else None) or "").strip()


def _rule_rationale_paragraph(rule: Rule) -> str:
    """First non-title paragraph of the rule's module docstring.

    Used by `pgrls lint --explain` to append a concise reference
    blurb beneath each finding. The full module docstring is much
    longer and would bury the lint output; one paragraph hits the
    sweet spot between "more than the message already says" and
    "still readable in a CI log."

    Falls back to an empty string for any rule whose docstring is
    absent (e.g. `python -OO`) or doesn't follow the two-paragraph
    convention (title line + reference para). `pgrls lint
    --explain` then quietly degrades to the un-augmented message.
    """
    doc = _rule_docstring(rule)
    if not doc:
        return ""
    paragraphs = doc.split("\n\n")
    if len(paragraphs) < 2:
        return ""
    return paragraphs[1].strip()


def _runtime_rules(config: Config) -> list[Rule]:
    """Return the full rule set for a given config: built-ins + extras.

    Use this anywhere the catalog needs to be aware of
    `[lint].extra_rules` — `--rule` / `--exclude-rule` validation,
    `pgrls explain` catalog listing, the per-rule rationale map
    `pgrls lint --explain` builds for the text formatter.

    Returns `all_rules()` unchanged when no extras are configured
    (no extra imports, no registry rebuild — preserves the cached
    fast path the existing call sites relied on).

    ID collisions between an extra and a built-in (or between two
    extras) raise `ToolError` here, mirroring `_run_rules`'s
    `RuleRegistry.register()` rejection. Without this, the
    read-only consumers (`pgrls explain --config`, `--rule`
    validation) would silently show duplicate catalog rows for a
    shadowed built-in while `pgrls lint` would error — divergent
    behavior is the bug the iter-3 SHOULD-FIX surfaced.
    """
    if not config.extra_rules:
        return list(all_rules())
    # Python's import-module cache means repeated load_extra_rules
    # calls in the same process don't re-import; only the RULES
    # attribute read recurs (effectively free).
    builtins = list(all_rules())
    extras = load_extra_rules(config.extra_rules)
    seen_ids = {r.id for r in builtins}
    for r in extras:
        if r.id in seen_ids:
            raise ToolError(
                f"[lint].extra_rules: Rule {r.id!r} is already "
                "registered. Rule IDs must be unique across "
                "built-ins and all extra modules."
            )
        seen_ids.add(r.id)
    return [*builtins, *extras]


def _run_rules(
    schema: Schema,
    *,
    config: Config,
    rule_filter: set[str] | None = None,
    exclude_filter: set[str] | None = None,
    coverage_data: CoverageData | None = None,
    perf_data: dict[tuple[str, str], TableStats] | None = None,
) -> list[Violation]:
    # Build the per-invocation registry: built-ins + extras from
    # `[lint].extra_rules`. A fresh RuleRegistry (not the cached
    # `default_registry()`) avoids accumulating extras across
    # successive `_run_rules` calls in the same process — important
    # for the test suite, and for any future API consumer running
    # multiple lints in one Python session. The registry's
    # `register()` raises on duplicate IDs, so a collision between
    # an extra and a built-in surfaces here with a clear error
    # instead of silently shadowing.
    if config.extra_rules:
        registry = RuleRegistry()
        for r in all_rules():
            registry.register(r)
        for r in load_extra_rules(config.extra_rules):
            try:
                registry.register(r)
            except ValueError as exc:
                # ID collision — rewrap with config-locus context
                raise ToolError(
                    f"[lint].extra_rules: {exc}. Rule IDs must be "
                    "unique across built-ins and all extra modules."
                ) from exc
    else:
        registry = default_registry()
    if rule_filter is not None:
        # `--rule` is an explicit "run only these rules" — it
        # overrides `[lint] disable` so an operator investigating a
        # disabled rule can pull it back in for one run without
        # editing the config. Per-rule allowlists and severity
        # overrides still apply.
        rules = [
            r for r in registry.enabled(disabled_ids=[])
            if r.id in rule_filter
        ]
    else:
        rules = registry.enabled(disabled_ids=config.disable)
    if exclude_filter:
        # `--exclude-rule` subtracts from whatever set would run —
        # the all-enabled set, or the `--rule` selection. The
        # incoherent "same id in both" case is rejected upstream.
        rules = [r for r in rules if r.id not in exclude_filter]

    out: list[Violation] = []
    for rule in rules:
        rule_options = config.rule_options.get(rule.id, {})
        # HYG004 / PERF005 can't read their artifacts themselves (rules
        # only see the schema + options), so lint injects the parsed data
        # here under a private key each rule looks for.
        if rule.id == "HYG004" and coverage_data is not None:
            rule_options = {**rule_options, "_coverage": coverage_data}
        if rule.id == "PERF005" and perf_data is not None:
            rule_options = {**rule_options, "_perf": perf_data}
        try:
            found = rule.check(schema, rule_options)
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
) -> list[Violation]:
    """Apply a `--baseline` file to `violations`; return the findings
    the caller should report.

    First run (file absent): write the baseline, note it on
    stderr, and return an empty list — the run's job was to
    *record* the baseline, and once recorded there are no new
    findings to report. Later runs: return only the findings
    absent from the baseline, noting the suppressed count on
    stderr.

    Either way the caller still runs `format_violations` and
    `_should_fail` on the returned list, so `--baseline` composes
    with `--format` (a first run under `--format json` / `sarif`
    emits a valid empty document) and with `--fail-on`.
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
        return []

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
    stale = stale_keys(violations, baseline)
    if stale:
        click.echo(
            f"pgrls: {len(stale)} baseline entry(ies) no longer "
            "match a finding (fixed, or the policy/table renamed). "
            f"Delete {path} and re-run to regenerate a tighter "
            "baseline.",
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


def _apply_statements(
    conn: psycopg.Connection[Any],
    stmts: list[Any],  # Fix dataclasses; loose-typed to avoid circular import
    *,
    lock_key: str,
) -> None:
    """Apply generated SQL statements all-or-nothing on `conn`.

    Takes a transaction-scoped advisory lock keyed on a stable hash of
    `lock_key` (so two concurrent `pgrls fix`/`generate --apply` runs
    serialize rather than racing on a stale snapshot), then executes each
    statement in order. On the first failure the connection is rolled
    back and a `ToolError` carrying `_fix_apply_failure_message` is
    raised; on success the transaction is committed. Callers print their
    own success echo afterward.

    `lock_key` is a fixed internal constant (`pgrls.fix` /
    `pgrls.generate`), so it is embedded directly as a SQL string
    literal — keeping the executed statement byte-identical to the
    pre-refactor inline form.
    """
    with conn.cursor() as cur:
        cur.execute(
            f"SELECT pg_advisory_xact_lock(hashtext('{lock_key}'))"
        )
        for i, f in enumerate(stmts, start=1):
            try:
                cur.execute(f.sql)
            except psycopg.Error as exc:
                # All-or-nothing: surface the failing SQL, the psycopg
                # error, and a remediation hint, then roll back so the
                # database is left unchanged.
                conn.rollback()
                raise ToolError(
                    _fix_apply_failure_message(i, len(stmts), f, exc)
                ) from exc
    conn.commit()


def _plural_fixes(n: int) -> str:
    """`fix` / `fixes` agreement used throughout the `pgrls fix` output."""
    return "fix" if n == 1 else "fixes"


def _fix_check(fixes: list[Any]) -> None:
    """`pgrls fix --check`: list offending pairs, then exit 1.

    The summary count and next-step hint go to stderr; the
    `(rule_id, location)` listing goes to stdout so
    `pgrls fix --check > violations.log` captures it for CI. Always
    exits 1 (the caller only reaches here with a non-empty `fixes`).
    """
    count = len(fixes)
    plural = "" if count == 1 else "s"
    click.echo(
        f"pgrls fix --check: {count} auto-fixable "
        f"violation{plural} found.",
        err=True,
    )
    for f in fixes:
        click.echo(f"  {f.rule_id}  {f.location}")
    click.echo(
        "Run `pgrls fix --apply` to apply them, or "
        "`pgrls fix --output migration.sql` to write a "
        "migration.",
        err=True,
    )
    sys.exit(1)


def _fix_write_migration(
    fixes: list[Any], output_path: str, *, force: bool, offline: bool = False
) -> None:
    """`pgrls fix --output FILE`: write the migration script, note it.

    Deterministic (no timestamp), so regenerating against an unchanged
    schema yields a byte-identical file. Distinct error wording
    ("cannot write fixes to …") from the report-style `_emit`, so this
    stays bespoke.

    Refuses to clobber an existing file unless `force` is set — the same
    overwrite guard `pgrls generate --output` and `pgrls init` use, so a
    re-run of `pgrls fix -o migration.sql` can't silently destroy a
    hand-edited migration.

    When `offline=True`, the migration file carries an offline caveat
    header instead of the default "generated from a snapshot of the
    database" header — the offline provenance travels into the artifact.
    """
    path = Path(output_path)
    if path.exists() and not force:
        raise ToolError(
            f"{output_path} already exists. Pass --force to overwrite it."
        )
    migration = render_migration(fixes, tool_version=__version__, offline=offline)
    try:
        # newline="" so the LF render_migration emits is written
        # verbatim — without it, text mode on Windows rewrites \n to
        # \r\n, making the file diverge byte-for-byte from the stdout
        # dry-run and from `generate --output` (which already passes
        # newline=""), breaking the documented determinism guarantee.
        path.write_text(migration, encoding="utf-8", newline="")
    except OSError as exc:
        raise ToolError(
            f"cannot write fixes to {output_path}: {exc}"
        ) from exc
    click.echo(
        f"pgrls: wrote {len(fixes)} {_plural_fixes(len(fixes))} to "
        f"{output_path}.",
        err=True,
    )


def _fix_emit_and_maybe_apply(
    fixes: list[Any],
    conn: psycopg.Connection[Any] | None,
    *,
    apply: bool,
) -> None:
    """Shared dry-run / `--apply` tail of `pgrls fix`.

    Echoes the SQL bodies (with their `-- [rule]` comments) to stdout —
    so `pgrls fix > migration.sql` still produces a paste-able script —
    then either applies them all-or-nothing (`--apply`) and reports the
    applied count, or prints the dry-run hint. Both status lines go to
    stderr.
    """
    click.echo(render_fixes(fixes))
    if apply:
        # `--apply` is rejected on the offline path (the only caller that passes
        # conn=None), so a live connection is guaranteed whenever apply is set.
        assert conn is not None
        _apply_statements(conn, fixes, lock_key="pgrls.fix")
        click.echo(
            f"pgrls: applied {len(fixes)} {_plural_fixes(len(fixes))}.",
            err=True,
        )
    else:
        click.echo(
            f"pgrls: {len(fixes)} {_plural_fixes(len(fixes))} ready "
            "(dry-run). Re-run with --apply to execute.",
            err=True,
        )


_OFFLINE_SQL_HEADER = (
    "-- pgrls: generated offline from --sql-file/--snapshot; not validated "
    "against live catalog state (BYPASSRLS / SECURITY DEFINER / FK context) "
    "-- review before applying."
)


def _fix_dispatch(
    fixes: list[Fix], *, conn: psycopg.Connection[Any] | None, check: bool,
    output_path: str | None, force: bool, apply: bool, offline: bool = False,
) -> None:
    if check:
        _fix_check(fixes)
        return
    if output_path is not None:
        _fix_write_migration(fixes, output_path, force=force, offline=offline)
        return
    if offline:
        click.echo(_OFFLINE_SQL_HEADER)
    _fix_emit_and_maybe_apply(fixes, conn, apply=apply)


def _generate_dispatch(
    result: GenerateResult, stmts: list[Fix], *,
    conn: psycopg.Connection[Any] | None, output_path: str | None,
    force: bool, apply: bool, offline: bool,
) -> None:
    if output_path is not None:
        path = Path(output_path)
        if path.exists() and not force:
            raise ToolError(
                f"{output_path} already exists. Pass --force to overwrite it."
            )
        migration = render_migration(stmts, tool_version=__version__, offline=offline)
        try:
            path.write_text(migration, encoding="utf-8", newline="")
        except OSError as exc:
            raise ToolError(
                f"cannot write generated SQL to {output_path}: {exc}"
            ) from exc
        click.echo(
            f"pgrls: wrote {len(stmts)} statement(s) to {output_path}.",
            err=True,
        )
        return
    if offline:
        click.echo(_OFFLINE_SQL_HEADER + "\n" + render_fixes(stmts))
    else:
        click.echo(render_fixes(stmts))
    if apply:
        # `--apply` is rejected on the offline path (the only caller that passes
        # conn=None), so a live connection is guaranteed whenever apply is set.
        assert conn is not None
        _apply_statements(conn, stmts, lock_key="pgrls.generate")
        click.echo(
            f"pgrls: applied {len(stmts)} statement(s). Run `pgrls lint` to "
            "confirm a clean result.",
            err=True,
        )
    else:
        msg = (
            f"pgrls: {len(stmts)} statement(s) ready (offline, emit-only). "
            "Pipe to a migration or use --output FILE."
            if offline
            else f"pgrls: {len(stmts)} statement(s) ready (dry-run). Re-run "
            "with --apply to execute, or --output FILE to write a migration."
        )
        click.echo(msg, err=True)


@main.command()
@click.pass_context
@common_db_options
@offline_source_options
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
@click.option(
    "--output",
    "-o",
    "output_path",
    type=click.Path(dir_okay=False),
    default=None,
    help="Write the remediation SQL to this file (a migration-"
    "ready .sql script) instead of stdout. Cannot be combined "
    "with --apply.",
)
@click.option(
    "--force",
    is_flag=True,
    default=False,
    help="Overwrite the --output file if it already exists.",
)
@click.option(
    "--check",
    is_flag=True,
    default=False,
    help=(
        "Exit 1 if any auto-fixable violations would be emitted "
        "(CI gate / pre-commit pattern). Lists the offending "
        "(rule, location) pairs but emits no SQL and changes no "
        "database state. Cannot be combined with --apply or --output."
    ),
)
def fix(
    ctx: click.Context,
    database_url: str | None,
    config_path: str | None,
    schemas: str | None,
    sql_file: tuple[str, ...],
    snapshot: str | None,
    rules: tuple[str, ...],
    apply: bool,
    output_path: str | None,
    force: bool,
    check: bool,
) -> None:
    """Auto-remediate violations whose fix is mechanical.

    Currently fixes SEC001 (`ALTER TABLE … ENABLE ROW LEVEL
    SECURITY`), SEC002 (`ALTER TABLE … FORCE ROW LEVEL
    SECURITY`), SEC004 (`ALTER POLICY … USING (…)` stripping the
    top-level `auth_func() IS NULL` disjunct that leaks rows to anonymous
    clients; abstains when no real check survives), SEC010 (`DROP POLICY`
    for a permissive policy whose clause is the literal `false` — it admits
    no rows, so dropping it changes no access), SEC011 (`ALTER POLICY …
    USING/WITH CHECK` stripping
    an `OR true` debug bypass), SEC019 (`ALTER POLICY … USING/WITH CHECK` adding
    `, true` to one-arg `current_setting()` calls), SEC020
    (`ALTER POLICY … WITH CHECK` replacing a constant-true write
    check with USING), SEC015 (`ALTER FUNCTION ... SET search_path
    = …, pg_temp` per overload, pinning pg_temp last to block
    pg_temp shadowing), SEC017 (`ALTER FUNCTION ... NOT LEAKPROOF`
    per overload, using the per-overload signature captured in
    snapshot v12), SEC030 (`ALTER COLUMN … SET NOT NULL` for a
    nullable discriminator — runtime fails if NULLs already exist;
    the Fix description warns and supplies the backfill recipe),
    SEC031 (`DROP POLICY` for a no-op
    restrictive `USING (true)` floor), SEC032 (`ALTER TABLE …
    ENABLE ROW LEVEL SECURITY` for a dormant-policies table), SEC044
    (`ALTER DEFAULT PRIVILEGES FOR ROLE <grantor> [IN SCHEMA …] REVOKE …
    ON TABLES FROM <role>` — keyed on the grantor so the REVOKE actually
    clears the pg_default_acl entry),
    PERF001 (wrap unwrapped auth calls in
    `(SELECT …)` and emit `ALTER POLICY`), PERF003 (`CREATE
    INDEX` for an unindexed policy-predicate column), PERF004
    (`CREATE INDEX` on the function expression that wraps an
    indexed column), HYG003
    (`DROP POLICY` for a policy that exactly duplicates
    another on the same table), VIEW001
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

    `--output <file>` writes the remediation SQL to a file — a
    migration-ready `.sql` script with a header and one
    `-- [rule] description` comment per statement — instead of
    printing it to stdout. The file is deterministic (no
    timestamp), so regenerating against an unchanged schema
    produces a byte-identical result. An existing `--output`
    file is never silently clobbered: the command errors unless
    `--force` is passed (matching `pgrls generate` and `pgrls
    init`). `--output` cannot be combined with `--apply`: one
    writes a migration to run later, the other executes
    immediately.

    `--check` is a CI gate: it exits 1 if any auto-fixable
    violations would be emitted (and 0 otherwise), without
    writing SQL or changing database state. The offending
    `(rule_id, location)` pairs go to stdout (so `pgrls fix
    --check > violations.log` captures them as a CI artefact);
    the summary count and next-step hint go to stderr. Mirrors
    `ruff format --check` / `prettier --check`. Cannot be
    combined with `--apply` or `--output`.

    Output channels: SQL bodies go to stdout (so `pgrls fix >
    migration.sql` produces a usable script) unless `--output`
    redirects them to a file. Status / progress / error messages
    go to stderr.

    The Schema is captured by introspection at the start of the
    command and the generated fixes reflect that snapshot. A
    concurrent migration between introspection and `--apply` could
    cause individual statements to fail; the all-or-nothing rollback
    keeps the database consistent in that case.
    """
    if output_path is not None and apply:
        raise ToolError(
            "--output and --apply cannot be combined: --output "
            "writes a migration file to apply later, --apply "
            "executes the fixes immediately. Choose one."
        )
    if check and (apply or output_path is not None):
        raise ToolError(
            "--check is a CI gate (exit 1 if any fixes would be "
            "emitted) and cannot be combined with --apply (which "
            "applies them) or --output (which writes them to a "
            "file). Choose one."
        )

    # Parse --config up-front so a malformed config file surfaces
    # before a bad --rule (and before the db-url guard inside the
    # context manager), preserving the pre-refactor fix() error
    # precedence — config, then --rule, then db-url — for inputs that
    # trip more than one of these at once. The context manager below
    # re-reads + merges + guards + connects; this standalone parse
    # exists only to pin that ordering (the re-read is a cheap,
    # idempotent TOML parse).
    try:
        load_config(config_path)
    except ConfigError as exc:
        raise ToolError(str(exc)) from exc

    # Validate `--rule` early — a typo silently producing zero
    # fixes is hard to debug. The "no auto-fixable" message
    # should be reserved for "DB is clean", not "you spelled the
    # rule wrong." Case-normalize to match the rest of the
    # config surfaces (`[lint].disable`, `[lint.rules.<ID>]`,
    # `--fail-on`). Mirrors `pgrls lint --rule`.
    auto_fixable = {fixer.rule_id for fixer in default_fixers()}
    rules = _validate_rule_filter(rules, auto_fixable, kind="auto-fixable ")

    offline = _resolve_offline_schema(
        sql_file=sql_file, snapshot=snapshot, schemas_csv=schemas, command="fix"
    )
    if offline is not None:
        _reject_apply_offline(apply, "fix")
        _guard_offline_exclusivity(ctx, command="fix")
        schema, offline_source, offline_version = offline
        effective = _offline_effective_config(
            config_path=config_path, schemas_csv=schemas
        )
        try:
            fixes = generate_fixes(
                schema, rule_options=effective.rule_options,
                rule_filter=set(rules) if rules else None,
            )
        except (TypeError, ValueError) as exc:
            raise ToolError(str(exc)) from exc
        # Filter out any fixer whose rule is inert offline — it would emit a
        # bogus statement (e.g. a CREATE INDEX for an index it can't see via
        # DDL parsing). This preserves the under-report contract: offline fix
        # never emits a statement that isn't grounded in observed DDL.
        inert = inert_rule_ids(offline_source, snapshot_version=offline_version)
        fixes = [f for f in fixes if f.rule_id not in inert]
        if not fixes:
            click.echo("pgrls: no auto-fixable violations found.", err=True)
            return
        # Emit-only offline: dispatch with conn=None, apply=False, offline=True.
        # The offline provenance header travels into --output files (Fix 1) and
        # is prepended to stdout on the emit path (Fix 2).
        _fix_dispatch(
            fixes, conn=None, check=check, output_path=output_path, force=force,
            apply=False, offline=True,
        )
        return

    with _connect_introspect_ctx(
        config_path=config_path,
        database_url=database_url,
        schemas_csv=schemas,
    ) as (effective, conn, schema):
        try:
            fixes = generate_fixes(
                schema,
                rule_options=effective.rule_options,
                rule_filter=set(rules) if rules else None,
            )
        except (TypeError, ValueError) as exc:
            # A fixer raises TypeError on a malformed allowlist
            # — the same strict validation the rules apply — so
            # `pgrls fix` rejects bad config with a clear tool
            # error, exactly as `pgrls lint` does.
            raise ToolError(str(exc)) from exc

        if not fixes:
            click.echo(
                "pgrls: no auto-fixable violations found.",
                err=True,
            )
            return

        _fix_dispatch(fixes, conn=conn, check=check, output_path=output_path, force=force, apply=apply)

def _parse_generate_tables(
    raw: tuple[str, ...],
) -> tuple[tuple[str, str, str], ...]:
    """Parse `--table schema.table:column` entries.

    Each entry is `schema.table:column`. The schema/table split is on the
    rightmost `.` before the `:` (Postgres names can't contain `.` from
    introspection), so `app.events:org_id` → ('app','events','org_id').
    """
    out: list[tuple[str, str, str]] = []
    for entry in raw:
        if ":" not in entry:
            raise ToolError(
                f"--table {entry!r} must be 'schema.table:column' "
                "(e.g. 'public.orgs:org_id')."
            )
        ref, _, column = entry.rpartition(":")
        if "." not in ref or not column.strip():
            raise ToolError(
                f"--table {entry!r} must be 'schema.table:column' "
                "(e.g. 'public.orgs:org_id')."
            )
        schema_name, _, table_name = ref.rpartition(".")
        if not schema_name or not table_name:
            raise ToolError(
                f"--table {entry!r} must be 'schema.table:column' "
                "(e.g. 'public.orgs:org_id')."
            )
        out.append((schema_name, table_name, column.strip()))
    return tuple(out)


@main.command()
@click.pass_context
@common_db_options
@offline_source_options
@click.option(
    "--model",
    type=click.Choice(["tenant", "owner"], case_sensitive=False),
    default="tenant",
    show_default=True,
    help=(
        "What rows are scoped to: 'tenant' (per-tenant isolation) or 'owner' "
        "(per-user ownership). Sets the default column (tenant_id / user_id), "
        "the postgrest claim, and the policy names."
    ),
)
@click.option(
    "--tenant-column",
    "column",
    default=None,
    help=(
        "Discriminator column to auto-detect (default: tenant_id, or user_id "
        "with --model owner)."
    ),
)
@click.option(
    "--table",
    "tables",
    multiple=True,
    help=(
        "Generate for a specific table with an explicit discriminator "
        "column: 'schema.table:column'. Repeatable. Use for tables whose "
        "column isn't the default (e.g. 'public.orgs:org_id')."
    ),
)
@click.option(
    "--convention",
    type=click.Choice(
        ["app-guc", "postgrest", "supabase"], case_sensitive=False
    ),
    default="app-guc",
    show_default=True,
    help=(
        "Session-value source for the predicate: 'app-guc' uses "
        "current_setting('app.<col>', true); 'postgrest' uses "
        "current_setting('request.jwt.claim.<claim>', true); 'supabase' uses "
        "(SELECT auth.uid()) — owner model only."
    ),
)
@click.option(
    "--setting-name",
    default=None,
    help=(
        "Override the setting name used in current_setting() for every "
        "table (default derives from --convention and --model)."
    ),
)
@click.option(
    "--auth-function",
    default="auth.uid",
    show_default=True,
    help="Auth function for --convention supabase (compared as (SELECT fn())).",
)
@click.option(
    "--role",
    default="authenticated",
    show_default=True,
    help="Role the generated policies target (TO <role>). Must exist.",
)
@click.option(
    "--restrictive/--no-restrictive",
    default=True,
    show_default=True,
    help="Also emit a RESTRICTIVE floor (defense-in-depth).",
)
@click.option(
    "--output",
    "-o",
    "output_path",
    type=click.Path(dir_okay=False),
    default=None,
    help="Write the generated SQL to this file instead of stdout.",
)
@click.option(
    "--force",
    is_flag=True,
    default=False,
    help="Overwrite the --output file if it already exists.",
)
@click.option(
    "--strict-binding",
    is_flag=True,
    default=None,
    help=(
        "Compare against a helper that RAISES when no tenant is bound, "
        "instead of a current_setting(..., true) that silently yields NULL. "
        "An unbound query then errors instead of looking like an empty "
        "result. Also settable as `[generate].strict_binding` in pgrls.toml."
    ),
)
@click.option(
    "--apply",
    is_flag=True,
    default=False,
    help="Execute the generated SQL. Default: dry-run (print SQL only).",
)
def generate(
    ctx: click.Context,
    strict_binding: bool | None,
    database_url: str | None,
    config_path: str | None,
    schemas: str | None,
    sql_file: tuple[str, ...],
    snapshot: str | None,
    model: str,
    column: str | None,
    tables: tuple[str, ...],
    convention: str,
    setting_name: str | None,
    auth_function: str,
    role: str,
    restrictive: bool,
    output_path: str | None,
    force: bool,
    apply: bool,
) -> None:
    """Scaffold gold-standard RLS for tables that lack it.

    For every table that carries the discriminator column (default
    `tenant_id`, or `user_id` with `--model owner`, or a `--table
    schema.tbl:col` override) and has NO policies, emit the complete correct
    setup: ENABLE + FORCE row security, a permissive isolation policy, a
    RESTRICTIVE floor (`--no-restrictive` to skip), and the supporting
    index. The output is designed to lint clean — `pgrls generate --apply &&
    pgrls lint` is the intended round-trip. Tables that already have
    policies are skipped (pgrls never clobbers hand-written policy intent —
    refine those with `pgrls lint` / `fix`).

    `--model tenant` (default) scopes rows per tenant; `--model owner` scopes
    per user (e.g. `user_id = (SELECT auth.uid())` with `--convention
    supabase`).

    Default is a dry-run to stdout. `--output FILE` writes a
    migration-ready script; `--apply` runs the SQL in one all-or-nothing
    transaction against the resolved database.
    """
    if output_path is not None and apply:
        raise ToolError(
            "--output and --apply cannot be combined: --output writes a "
            "migration file, --apply executes against the database."
        )

    model_norm = model.lower()
    convention_norm = convention.lower()
    if convention_norm == "supabase" and model_norm != "owner":
        raise ToolError(
            "--convention supabase is for --model owner (it emits "
            "(SELECT auth.uid())). For tenant scoping use --convention "
            "app-guc or postgrest."
        )
    # Column default depends on the model when not given explicitly.
    resolved_column = column or ("user_id" if model_norm == "owner" else "tenant_id")

    # `--strict-binding` defaults to None (not False) so an explicit flag is
    # distinguishable from an absent one: the flag wins when given, otherwise
    # `[generate].strict_binding` decides. A False default would make the
    # config unreachable.
    try:
        _gen_cfg = load_config(config_path)
    except ConfigError:
        _gen_cfg = None  # re-raised with a clear message just below
    resolved_strict_binding = (
        strict_binding
        if strict_binding is not None
        else bool(_gen_cfg.generate_strict_binding) if _gen_cfg else False
    )

    # Validate --config unconditionally so a broken config file surfaces on
    # both offline and live generate paths (mirrors fix()'s up-front parse).
    try:
        load_config(config_path)
    except ConfigError as exc:
        raise ToolError(str(exc)) from exc

    # Resolve config (parse + merge + db-url guard) BEFORE parsing
    # --table, so a malformed --config and a missing database URL both
    # surface ahead of a bad --table value — matching the pre-refactor
    # generate() order (convention/column checks, then config-parse,
    # then db-url-missing, then --table syntax). The context manager
    # below re-resolves + connects; this up-front call exists only to
    # pin that precedence (the analogue of fix()'s up-front parse).
    # Guard: skip on the offline path — no db-url required offline, and
    # calling it would raise "No database connection" before the offline
    # branch is reached.
    if not sql_file and snapshot is None:
        _load_effective_config(
            config_path=config_path,
            database_url=database_url,
            schemas_csv=schemas,
        )

    options = GenerateOptions(
        tenant_column=resolved_column,
        model="owner" if model_norm == "owner" else "tenant",
        convention=convention_norm,  # type: ignore[arg-type]
        setting_name=setting_name,
        auth_function=auth_function,
        role=role,
        restrictive=restrictive,
        tables=_parse_generate_tables(tables),
        strict_binding=resolved_strict_binding,
    )

    offline = _resolve_offline_schema(
        sql_file=sql_file, snapshot=snapshot, schemas_csv=schemas,
        command="generate",
    )
    if offline is not None:
        _reject_apply_offline(apply, "generate")
        _guard_offline_exclusivity(ctx, command="generate")
        schema, _, _ = offline
        try:
            result = plan_generation(schema, options)
        except ValueError as exc:
            raise ToolError(str(exc)) from exc
        for note in result.notes:
            click.echo(f"pgrls: note: {note}", err=True)
        for qname, reason in result.skipped:
            click.echo(f"pgrls: skipped {qname} — {reason}", err=True)
        if not result.statements:
            click.echo(
                "pgrls: nothing to generate (no unprotected tables with the "
                "discriminator column).",
                err=True,
            )
            return
        _generate_dispatch(
            result, list(result.statements), conn=None, output_path=output_path,
            force=force, apply=False, offline=True,
        )
        return

    with _connect_introspect_ctx(
        config_path=config_path,
        database_url=database_url,
        schemas_csv=schemas,
    ) as (effective, conn, schema):
        try:
            result = plan_generation(schema, options)
        except ValueError as exc:
            # session_predicate rejects an unsafe column type before it
            # can reach a `::<type>` cast (defense-in-depth on the
            # introspected type). Surface it as a clean CLI error rather
            # than a traceback.
            raise ToolError(str(exc)) from exc

        # Advisory notes + skipped tables → stderr (never pollutes the
        # SQL on stdout / in the migration file).
        for note in result.notes:
            click.echo(f"pgrls: note: {note}", err=True)
        for qname, reason in result.skipped:
            click.echo(f"pgrls: skipped {qname} — {reason}", err=True)

        if not result.statements:
            click.echo(
                "pgrls: nothing to generate (no unprotected tables with "
                "the discriminator column).",
                err=True,
            )
            return

        _generate_dispatch(result, list(result.statements), conn=conn, output_path=output_path, force=force, apply=apply, offline=False)


def _offline_migration_options(func: Callable[..., Any]) -> Callable[..., Any]:
    """The static subset of ``migration_source_options`` — resolve a migration
    directory to its layout-ordered file list and read it OFFLINE (no ephemeral
    Postgres). `snapshot` uses it for a DB-free, layout-aware source. Declared
    bottom-up so `--help` lists `--migrations` first."""
    from pgrls.migrations_layout import LAYOUTS

    func = click.option(
        "--migrations-glob",
        default=None,
        help="Explicit ordered glob for --migrations-layout glob (e.g. 'db/*.sql').",
    )(func)
    func = click.option(
        "--migrations-layout",
        type=click.Choice(list(LAYOUTS), case_sensitive=False),
        default="auto",
        show_default=True,
        help="Migration layout for --migrations (auto-detected by default).",
    )(func)
    func = click.option(
        "--migrations",
        "migrations_path",
        type=click.Path(exists=True),
        default=None,
        help=(
            "Build the snapshot OFFLINE from a migration directory (or a single "
            ".sql file): its layout-ordered files are concatenated and parsed — "
            "no database, no Docker (unlike `lint --migrations`, which "
            "provisions an ephemeral Postgres). Mutually exclusive with "
            "--sql-file / --snapshot / --database-url."
        ),
    )(func)
    return func


@main.command()
@click.pass_context
@common_db_options
@offline_source_options
@_offline_migration_options
@click.option(
    "--output",
    "-o",
    "output_path",
    type=click.Path(dir_okay=False),
    default=None,
    help="Path to write the JSON snapshot (default: stdout).",
)
def snapshot(
    ctx: click.Context,
    database_url: str | None,
    config_path: str | None,
    schemas: str | None,
    sql_file: tuple[str, ...],
    snapshot: str | None,
    migrations_path: str | None,
    migrations_layout: str,
    migrations_glob: str | None,
    output_path: str | None,
) -> None:
    """Capture a JSON snapshot of a schema's RLS state.

    The snapshot format is documented in CHANGELOG.md and is
    intended to be consumed by `pgrls diff` (or stored as a
    baseline in CI). Output is the same JSON shape
    `Schema.to_snapshot()` produces — top-level `version` plus a
    `tables` list, deterministic within a single Postgres
    instance.

    The default source is a live database (`--database-url` /
    `$DATABASE_URL`). Pass `--sql-file` to build the snapshot from raw
    DDL **offline** — no database and no Docker — so two migration
    revisions can be captured and `pgrls diff`'d in CI with the target
    database never touched (an offline snapshot carries only what DDL
    expresses; see the caveat on stderr). `--snapshot IN` re-emits an
    existing artifact, upgrading it to the current format version.

    Without `--output`, the snapshot is written to stdout. With
    `--output PATH`, it's written to the path with a trailing
    newline (POSIX-friendly).
    """
    try:
        config = load_config(config_path)
    except ConfigError as exc:
        raise ToolError(str(exc)) from exc

    if migrations_path is not None:
        # Static/offline migration-directory read: resolve the layout to an
        # ordered file list and build the schema from their concatenated DDL —
        # no database, no Docker (distinct from `lint --migrations`, which
        # provisions an ephemeral Postgres). Feed the ordered files through the
        # same offline `--sql-file` path below.
        if sql_file or snapshot is not None:
            raise ToolError(
                "choose one offline source: --migrations, --sql-file, or "
                "--snapshot."
            )
        from pgrls.migrations_layout import LayoutError, resolve_plan

        try:
            plan = resolve_plan(
                Path(migrations_path),
                layout=migrations_layout,
                glob_pattern=migrations_glob,
            )
        except LayoutError as exc:
            raise ToolError(str(exc)) from exc
        sql_file = tuple(str(f) for f in plan.files)

    if sql_file or snapshot is not None:
        # Offline source (raw DDL / an existing snapshot) — reject a
        # colliding explicit --database-url before doing any work.
        _guard_offline_exclusivity(ctx, command="snapshot")
        offline = _resolve_offline_schema(
            sql_file=sql_file,
            snapshot=snapshot,
            schemas_csv=schemas,
            command="snapshot",
        )
        assert offline is not None  # a source was given
        schema = offline[0]
        # Provenance: raw DDL (`--sql-file`), or a re-emitted offline snapshot
        # that `resolve_schema` resolved back to `sql`. Stamped below so
        # `pgrls pr` / `lint --snapshot` treat catalog-dependent rules as inert
        # instead of reading their silent no-op (empty indexes/roles/FKs) as
        # coverage. A live-DB re-emit stays `snapshot` → no marker.
        offline_from_ddl = offline[1] == "sql"
    else:
        offline_from_ddl = False
        effective = _merge_overrides(
            config,
            database_url=database_url,
            schemas_csv=schemas,
            fail_on=None,
        )
        if effective.database_url is None:
            # If `[database].url` was set but its env-var interpolation
            # failed, surface that specific cause (deferred from
            # load_config) instead of the generic guidance.
            raise ToolError(
                effective.database_url_error
                or "No schema source: pass --database-url / set DATABASE_URL, "
                "or build a snapshot offline with --sql-file / --snapshot."
            )
        try:
            with psycopg.connect(effective.database_url) as conn:
                schema = introspect(conn, schemas=effective.schemas)
        except psycopg.Error as exc:
            raise ToolError(f"Database error: {exc}") from exc
        except ValueError as exc:
            raise ToolError(str(exc)) from exc

    snap = schema.to_snapshot()
    if offline_from_ddl:
        snap["source"] = "sql"
    payload = json.dumps(snap, indent=2, ensure_ascii=False)
    if output_path:
        try:
            Path(output_path).write_text(payload + "\n", encoding="utf-8")
        except OSError as exc:
            raise ToolError(f"Cannot write {output_path}: {exc}") from exc
    else:
        click.echo(payload)


# The starter config `pgrls init` writes, assembled from three parts: a
# shared head (schema directive + [database] connection comment), a
# per-preset middle (the `schemas` key plus the stack's RLS conventions,
# including the exact `pgrls generate` command that scaffolds matching
# policies), and a shared [lint]/[diff] tail. Every active key is a no-op
# default — the file parses and `pgrls lint` runs unchanged regardless of
# preset; the only thing a preset changes is the documented convention and
# generate command, never a rule's behaviour. `[database].url` is left
# commented so a fresh file doesn't fail with an env-var error before the
# user has wired up DATABASE_URL.
_INIT_HEAD = """\
#:schema https://raw.githubusercontent.com/pgrls/pgrls/main/pgrls.schema.json
# pgrls configuration. Rule reference:
# https://github.com/pgrls/pgrls/blob/main/docs/RULES.md
# Every key is optional; this file documents the common knobs.

[database]
# Connection string. Prefer leaving this unset and passing
# --database-url (or $DATABASE_URL) at runtime so secrets stay out of
# version control. When set, $VAR / ${VAR} are interpolated from the
# environment, e.g. url = "$DATABASE_URL".
# url = "postgres://user:pass@localhost:5432/app"
"""

_INIT_SCHEMAS = """\
# Schemas to lint. Defaults to ["public"].
schemas = ["public"]
"""

_INIT_TAIL = """\
[lint]
# Severity that makes `pgrls lint` exit non-zero: error | warning | info.
# CI gates on this. Default: "warning".
fail_on = "warning"

# Turn rules off entirely, by id (case-insensitive):
# disable = ["SEC022", "PERF002"]

# Per-rule settings live under [lint.rules.<ID>].
# `allowlist` exempts specific objects from a rule:
# [lint.rules.SEC001]
# allowlist = ["public.countries"]   # reference data, intentionally public

# `severity` remaps a rule's level without disabling it — promote an
# info nudge to a CI-blocking error, or demote a noisy warning:
# [lint.rules.SEC030]
# severity = "error"

[diff]
# Threshold that makes `pgrls diff` exit non-zero:
# safe | breaking | requires-review | dangerous. Default: "dangerous".
fail_on = "dangerous"

[generate]
# `pgrls generate --strict-binding` as a standing default: generated tenant
# policies compare against a helper that RAISES when no tenant is bound,
# instead of a current_setting(..., true) that silently returns NULL.
strict_binding = false
"""

# Per-preset RLS conventions block. Each names the stack's tenancy model and
# the exact `pgrls generate` invocation that scaffolds matching, lint-clean
# policies — using only flags `pgrls generate` actually accepts. The
# predicate examples are illustrative (the real cast is derived from the
# discriminator column's type). These are comments only: the generated config
# parses identically and leaves every rule at its default for all presets.
_INIT_CONV_GENERIC = """\
# --- RLS conventions: per-tenant isolation via a session GUC ---
# Scaffold gold-standard RLS for any table that has a `tenant_id` column
# but no policies, then confirm the result lints clean:
#
#     pgrls generate --apply && pgrls lint
#
# Generated predicate (index-friendly; NULL when the GUC is unset = deny):
#     tenant_id = (SELECT current_setting('app.tenant_id', true)::uuid)
# Set the GUC per transaction:  SET app.tenant_id = '<id>';"""

_INIT_CONV_SUPABASE = """\
# --- Supabase RLS conventions: per-user ownership via auth.uid() ---
# Supabase manages the `auth` and `storage` schemas; lint only your own
# schema (`public`, above). Scaffold gold-standard per-user RLS for any
# table that has a `user_id` column but no policies:
#
#     pgrls generate --model owner --convention supabase --apply && pgrls lint
#
# Generated predicate — the initplan-cached form Supabase recommends over
# bare auth.uid() (re-evaluated per row):
#     user_id = (SELECT auth.uid())"""

_INIT_CONV_POSTGREST = """\
# --- PostgREST RLS conventions: per-tenant isolation via a JWT claim ---
# PostgREST sets request.jwt.claim.* GUCs from the verified JWT. Scaffold
# gold-standard per-tenant RLS for any table that has a `tenant_id` column
# but no policies:
#
#     pgrls generate --convention postgrest --apply && pgrls lint
#
# Generated predicate:
#     tenant_id = (SELECT current_setting('request.jwt.claim.tenant_id', true)::uuid)"""

_INIT_CONV_NEON = """\
# --- Neon Authorize RLS conventions: per-user ownership via auth.user_id() ---
# Neon Authorize exposes the JWT subject through auth.user_id() (text).
# Scaffold gold-standard per-user RLS for any table that has a `user_id`
# column but no policies:
#
#     pgrls generate --model owner --convention supabase --auth-function auth.user_id --apply
#
# Generated predicate:
#     user_id = (SELECT auth.user_id())"""

# Insertion order is the order shown in --help and tested by the CLI suite.
_INIT_CONVENTIONS: dict[str, str] = {
    "generic": _INIT_CONV_GENERIC,
    "supabase": _INIT_CONV_SUPABASE,
    "postgrest": _INIT_CONV_POSTGREST,
    "neon": _INIT_CONV_NEON,
}
_INIT_PRESETS = tuple(_INIT_CONVENTIONS)


def _render_init_config(preset: str) -> str:
    """Assemble the starter pgrls.toml for the given stack preset.

    Blocks are joined with a blank line between them and a single trailing
    newline, independent of each constant's own trailing whitespace.
    """
    parts = [
        _INIT_HEAD,
        _INIT_SCHEMAS,
        _INIT_CONVENTIONS[preset],
        _INIT_TAIL,
    ]
    return "\n\n".join(part.rstrip("\n") for part in parts) + "\n"


@main.command()
@click.option(
    "--output",
    "-o",
    "output_path",
    type=click.Path(dir_okay=False),
    default="pgrls.toml",
    show_default=True,
    help="Path to write the config.",
)
@click.option(
    "--preset",
    type=click.Choice(_INIT_PRESETS, case_sensitive=False),
    default="generic",
    show_default=True,
    help=(
        "Tailor the starter config to a stack: 'generic' (per-tenant via an "
        "app GUC), 'supabase' / 'neon' (per-user via auth.uid() / "
        "auth.user_id()), or 'postgrest' (per-tenant via a JWT claim). Each "
        "documents the matching `pgrls generate` command; rules stay at "
        "their defaults."
    ),
)
@click.option(
    "--force",
    is_flag=True,
    help="Overwrite the file if it already exists.",
)
def init(output_path: str, preset: str, force: bool) -> None:
    """Write a starter pgrls.toml with the common options documented.

    The generated file parses as-is and leaves every rule at its
    default — `pgrls lint` runs unchanged against it. Connection
    string, disable list, and per-rule allowlist / severity overrides
    are included as commented examples to edit. Refuses to clobber an
    existing file unless `--force` is given.

    `--preset` tailors the documented tenancy convention and the exact
    `pgrls generate` command to a stack (supabase / postgrest / neon /
    generic) without changing any rule's behaviour.
    """
    preset = preset.lower()
    path = Path(output_path)
    if path.exists() and not force:
        raise ToolError(
            f"{path} already exists. Pass --force to overwrite it."
        )
    try:
        path.write_text(_render_init_config(preset), encoding="utf-8")
    except OSError as exc:
        raise ToolError(f"Cannot write {path}: {exc}") from exc
    click.echo(
        f"Wrote {path} ({preset} preset). Set [database].url (or pass "
        "--database-url / $DATABASE_URL), then run `pgrls lint`. To scaffold "
        "RLS, run the `pgrls generate` command noted in the file."
    )


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
            # Do NOT interpolate `arg` — it is a DSN that may embed a
            # password (`postgres://user:pw@host/db`), and this message
            # lands in CI logs. Mirror the redacted form every other
            # command uses.
            raise ToolError(f"Database error connecting to the database: {exc}") from exc
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
                        from psycopg import sql

                        baseline_start = time.monotonic()
                        # 1. Pre-create roles referenced by base. Compose the
                        # role name client-side via sql.Literal / sql.Identifier:
                        # a server-side %s parameter referenced inside a DO block
                        # body has no inferable type, so the old `... rolname =
                        # %s ... format(..., %s)` form raised IndeterminateDatatype
                        # the moment a baseline referenced a non-PUBLIC role
                        # (e.g. `authenticated`). Mirrors ephemeral.py.
                        for role in sorted(role_names):
                            cur.execute(
                                sql.SQL(
                                    "DO $$ BEGIN "
                                    "IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = {name}) "
                                    "THEN CREATE ROLE {ident} NOLOGIN; END IF; END $$;"
                                ).format(name=sql.Literal(role), ident=sql.Identifier(role))
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
# Pre-computed lists for click.Choice — mirrors _DIFF_FAIL_ON_VALUES
# and stays in sync with the config constants automatically.
_DIFF_RENAME_DETECTION_VALUES = list(DIFF_RENAME_DETECTION_VALUES)
_DIFF_RENAME_CLASSIFICATION_VALUES = list(DIFF_RENAME_CLASSIFICATION_VALUES)


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
    # markdown emits an H2 + pipe table + trailing summary that's
    # paste-ready for a PR review comment or a Markdown runbook.
    # The empty-changes case returns "pgrls diff: no changes.\n"
    # (matches text); pass nl=False so click doesn't double-newline.
    "markdown": (format_diff_markdown, False),
    # html emits a standalone audit page mirroring report/history
    # HTML — embedded CSS, no external assets. nl=False because the
    # renderer already ends in a trailing newline.
    "html": (format_diff_html, False),
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
@click.option(
    "--explain",
    is_flag=True,
    default=False,
    help=(
        "Append a one-paragraph rationale to each Change in the "
        "text output, explaining why the kind carries the "
        "classification it does (e.g. why dropping a PERMISSIVE "
        "policy is BREAKING rather than DANGEROUS). Text format "
        "only — JSON / SARIF already carry the classification tag."
    ),
)
@click.option(
    "--rename-detection",
    type=click.Choice(list(DIFF_RENAME_DETECTION_VALUES), case_sensitive=False),
    default=None,
    help=(
        "Policy-rename detection mode. 'strict' (default) reports a "
        "name-only rename as one change (SAFE by default; see "
        "--rename-classification) and leaves a rename+edit as drop+add; "
        "'relaxed' also collapses a rename+edit into one POLICY_RENAMED "
        "graded by predicate direction; 'off' restores the prior "
        "drop+add behavior. Overrides [diff].rename_detection."
    ),
)
@click.option(
    "--rename-classification",
    type=click.Choice(list(DIFF_RENAME_CLASSIFICATION_VALUES), case_sensitive=False),
    default=None,
    help=(
        "Classification for a name-only policy rename. 'safe' (default) "
        "since row access is unchanged; 'requires-review' if a policy "
        "name is part of your external contract. Overrides "
        "[diff].rename_classification."
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
    explain: bool,
    rename_detection: str | None,
    rename_classification: str | None,
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

    # `--rename-detection` / `--rename-classification` fallback chains
    # mirror `--fail-on`: CLI flag wins, else the [diff] config value,
    # else the built-in default. Click lower-cases Choice values; the
    # classification's hyphen normalizes to the internal underscore form.
    effective_rename_detection: str = (
        rename_detection
        if rename_detection is not None
        else config.diff_rename_detection
    )
    effective_rename_classification: str = (
        rename_classification.replace("-", "_")
        if rename_classification is not None
        else config.diff_rename_classification
    )

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
            # A configured `[database].url` whose env-var interpolation
            # failed lands here (deferred from load_config). Surface the
            # specific cause rather than the generic "No head" guidance —
            # the user did configure a head source, it just couldn't
            # resolve.
            raise ToolError(
                config.database_url_error
                or "No head: pass <head> argument, set DATABASE_URL, "
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

    changes = diff_schemas(
        base_schema,
        head_schema,
        rename_detection=effective_rename_detection,
        rename_classification=effective_rename_classification,
    )

    # --fail-on filter
    threshold_classifications = _classifications_at_or_above(effective_fail_on)
    failing = [c for c in changes if c.classification in threshold_classifications]

    # Format and emit. Single dispatch via _DIFF_FORMATTERS keeps
    # the format list in lockstep with DIFF_SUPPORTED_FORMATS.
    # `--explain` only meaningfully applies to the text format —
    # JSON / SARIF already carry the classification tag, and the
    # diff rationale is human-prose rather than a structured field.
    # Mirrors `pgrls lint --explain`'s text-only behavior.
    formatter, append_newline = _DIFF_FORMATTERS[output_format]
    if output_format == "text":
        rendered = format_diff_text(changes, explain=explain)
    else:
        rendered = formatter(changes)
    click.echo(rendered, nl=append_newline)

    if failing:
        sys.exit(1)


def _snapshot_meta(arg: str) -> tuple[str | None, int | None]:
    """The `(source, version)` of a `pgrls snapshot` artifact at `arg`.

    `source` is the provenance marker — `"sql"` for a `snapshot --sql-file`
    offline capture (catalog-dependent rules can't be trusted → skip them like
    `lint --sql-file` does), else None. `version` is the declared format version
    (which scopes which catalog-only rules a live-DB snapshot is new enough to
    run). Both None when `arg` isn't a readable snapshot file (e.g. a database
    URL).

    A single `file://` normalization, matching `_resolve_diff_source`, is the
    whole point of reading `(source, version)` here in one place: `pr` accepts a
    `file://`-prefixed snapshot path, and if these helpers read the raw
    `file://…` string (which `Path.read_text` can't open) they'd fall through to
    "no marker / no version" and silently drop the offline / version-skew
    coverage gating on that head — a false clear the schema-load path
    (`_resolve_diff_source`, which strips the prefix) would never show."""
    arg = arg.removeprefix("file://")
    try:
        data = json.loads(Path(arg).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None, None
    if not isinstance(data, dict):
        return None, None
    source = data.get("source")
    version = data.get("version")
    return (
        source if isinstance(source, str) else None,
        version if isinstance(version, int) else None,
    )


def _render_pr_report(
    changes: list[Change],
    lint_violations: list[Violation],
    *,
    output_format: str,
    diff_failing: int,
    lint_failing: int,
    skipped: frozenset[str] = frozenset(),
    offline_head: bool = False,
) -> str:
    """Render the combined base→head PR verdict — a regressions section (diff)
    plus a new-findings section (lint) plus a one-line pass/fail verdict.

    `skipped` is the catalog-dependent rules that could not run on this head. It
    is surfaced as a coverage caveat so a clean report is never mistaken for
    full coverage — the lint pass proves nothing about the rules it never ran.
    `offline_head` distinguishes the two reasons a rule is skipped so the caveat
    stays truthful: a DDL-built head (`snapshot --sql-file`) whose catalog state
    can't be expressed at all, versus a live-DB snapshot captured by an older
    pgrls that predates those rules' inputs — different causes, different fixes."""
    from pgrls.formatters.markdown import format_markdown

    failed = bool(diff_failing or lint_failing)
    n_skipped = len(skipped)
    # One truthful reason + remedy, reused by both output formats.
    if offline_head:
        skip_why = (
            "it was captured offline from DDL, which can't express indexes, "
            "roles, function bodies, or foreign keys"
        )
        skip_remedy = "Re-run against a live database for full coverage."
    else:
        skip_why = "it was captured by an older pgrls that predates those rules"
        skip_remedy = (
            "Re-capture the snapshot with a current pgrls (or run against a "
            "live database) for full coverage."
        )
    if output_format == "markdown":
        diff_body = (
            format_diff_markdown(changes)
            if changes
            else "_No RLS policy changes._"
        )
        lint_body = (
            format_markdown(lint_violations)
            if lint_violations
            else "_No findings in the changed schema._"
        )
        caveat = (
            f"\n> _{n_skipped} catalog-dependent rule(s) not evaluated on this "
            f"head — {skip_why}. {skip_remedy}_\n"
            if n_skipped
            else ""
        )
        verdict = (
            f"**pgrls PR check: FAILED** — {diff_failing} blocking policy "
            f"change(s), {lint_failing} finding(s) at or above the threshold."
            if failed
            else "**pgrls PR check: PASSED** — no blocking RLS regressions or "
            "findings."
        )
        return (
            "## pgrls PR check\n\n"
            "### RLS policy changes (base → head)\n\n"
            f"{diff_body}\n\n"
            "### Findings in the changed schema\n\n"
            f"{lint_body}\n"
            f"{caveat}\n"
            f"{verdict}\n"
        )
    diff_body = format_diff_text(changes) if changes else "No RLS policy changes."
    lint_body = (
        format_violations(lint_violations, format="text")
        if lint_violations
        else "No findings in the changed schema."
    )
    caveat = (
        f"\nNote: {n_skipped} catalog-dependent rule(s) not evaluated on this "
        f"head — {skip_why}. {skip_remedy}\n"
        if n_skipped
        else ""
    )
    verdict = (
        f"pgrls PR check: FAILED ({diff_failing} blocking change(s), "
        f"{lint_failing} finding(s))"
        if failed
        else "pgrls PR check: PASSED"
    )
    return (
        "RLS policy changes (base -> head):\n"
        f"{diff_body}\n\n"
        "Findings in the changed schema:\n"
        f"{lint_body}\n"
        f"{caveat}\n"
        f"{verdict}"
    )


@main.command(name="pr")
@click.argument("base")
@click.argument("head")
@click.option(
    "--fail-on",
    type=click.Choice(
        ["safe", "breaking", "requires-review", "dangerous"],
        case_sensitive=False,
    ),
    default=None,
    help="Diff classification at or above which the check fails. "
    "Falls back to [diff].fail_on, then 'dangerous'.",
)
@click.option(
    "--lint-fail-on",
    type=click.Choice(["error", "warning", "info"], case_sensitive=False),
    default=None,
    help="Lint severity (on the head schema) at or above which the check "
    "fails. Falls back to [lint].fail_on, then 'warning'.",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["markdown", "text"], case_sensitive=False),
    default="markdown",
    show_default=True,
    help="Report format — markdown is PR-comment ready.",
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(dir_okay=False),
    default=None,
    help="Path to pgrls.toml. Defaults to ./pgrls.toml if present.",
)
@click.option(
    "--schemas",
    default=None,
    help="Comma-separated schemas to introspect (URL sources only).",
)
def pr(
    base: str,
    head: str,
    fail_on: str | None,
    lint_fail_on: str | None,
    output_format: str,
    config_path: str | None,
    schemas: str | None,
) -> None:
    """One PR verdict: lint the head schema AND diff base->head, in one gate.

    BASE and HEAD are `pgrls snapshot` artifacts (or database URLs). This
    combines the regression check (`pgrls diff` — did this PR loosen an existing
    policy?) and the new-issue check (`pgrls lint` — does the changed schema
    have RLS problems?) into a single Markdown report and a single exit code —
    the payload a CI PR check posts. Build BASE / HEAD offline
    (`pgrls snapshot --sql-file` / `--migrations`) and this never touches the
    target database. Exits 1 when either the diff or the lint crosses its
    threshold.
    """
    try:
        config = load_config(config_path)
    except ConfigError as exc:
        raise ToolError(str(exc)) from exc

    schema_list = (
        [s.strip() for s in schemas.split(",") if s.strip()]
        if schemas
        else config.schemas
    )
    base_schema = _resolve_diff_source(base, schemas=schema_list)
    # `from_snapshot` leaves policy USING / WITH CHECK ASTs unpopulated; reparse
    # them so the lint pass sees predicates (matching `lint --snapshot`) —
    # otherwise every predicate rule (SEC004, SEC038, PERF001, …) silently
    # no-ops and a real leak in the head would false-PASS. No-op for a URL head.
    head_schema = reparse_policy_asts(_resolve_diff_source(head, schemas=schema_list))

    # Lint the head. A head built offline from DDL (`snapshot --sql-file`)
    # can't be trusted for catalog-dependent rules — their inputs (indexes,
    # roles, function bodies, FKs) aren't expressed in DDL — so skip them like
    # `lint --sql-file` does rather than read a silent no-op as coverage. A
    # versioned live-DB snapshot skips only rules newer than its captured
    # version; a live-URL head sees the full catalog, so nothing is skipped.
    head_source, head_version = _snapshot_meta(head)
    offline_head = head_source == "sql"
    if offline_head:
        inert = inert_rule_ids("sql")
    elif head_version is not None:
        inert = inert_rule_ids("snapshot", snapshot_version=head_version)
    else:
        inert = frozenset()
    try:
        lint_violations = _run_rules(
            head_schema,
            config=config,
            exclude_filter=set(inert) if inert else None,
        )
    except (TypeError, ValueError, RuntimeError) as exc:
        raise ToolError(str(exc)) from exc
    lint_floor: Severity = lint_fail_on or config.fail_on  # type: ignore[assignment]
    lint_failing = [
        v for v in lint_violations if is_at_or_above(v.severity, lint_floor)
    ]

    changes = diff_schemas(
        base_schema,
        head_schema,
        rename_detection=config.diff_rename_detection,
        rename_classification=config.diff_rename_classification,
    )
    diff_floor = fail_on if fail_on is not None else config.diff_fail_on
    diff_failing = [
        c
        for c in changes
        if c.classification in _classifications_at_or_above(diff_floor)
    ]

    click.echo(
        _render_pr_report(
            changes,
            lint_violations,
            output_format=output_format,
            diff_failing=len(diff_failing),
            lint_failing=len(lint_failing),
            skipped=inert,
            offline_head=offline_head,
        )
    )
    if diff_failing or lint_failing:
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


def _rule_docstring_body(rule: Rule) -> str:
    """Module docstring with the leading "<ID> — <title>." line
    stripped, so the surrounding renderer can place its own header
    without restating the title. Returns "" when the rule has no
    docstring (graceful degrade for both `text` and `markdown`).
    """
    doc = _rule_docstring(rule)
    if not doc:
        return ""
    lines = doc.splitlines()
    # The trailing space pins the match to the whole ID token.
    if lines and lines[0].lstrip().startswith(rule.id + " "):
        lines = lines[1:]
        while lines and not lines[0].strip():
            lines.pop(0)
    return "\n".join(lines).strip()


def _render_rule_markdown(rule: Rule) -> str:
    """A single rule rendered as Markdown for embedding in user docs.

    `## <ID> — <title>` heading, a `**Severity:**` line, then the
    rule's reference body (docstring minus its title line). Rule
    docstrings already use Markdown-friendly conventions —
    fenced ``` blocks, `**bold**`, `*` bullets — so they render
    cleanly without further transformation.
    """
    parts = [
        f"## {rule.id} — {rule.title}",
        "",
        f"**Severity:** {rule.severity}",
    ]
    body = _rule_docstring_body(rule)
    if body:
        parts.append("")
        parts.append(body)
    return "\n".join(parts) + "\n"


def _render_catalog_markdown(rules: list[Rule]) -> str:
    """The rule catalog rendered as a Markdown table."""
    header = (
        f"`pgrls {__version__}` ships {len(rules)} rules. Run "
        "`pgrls explain <RULE>` for any rule's full reference."
    )
    lines = [
        "# pgrls rule catalog",
        "",
        header,
        "",
        "| ID | Severity | Title |",
        "|---|---|---|",
    ]
    for r in rules:
        # Defensive: a `|` in a title would break the table row.
        # No rule title carries one today, but the escape costs
        # nothing and pins the contract.
        title = r.title.replace("|", "\\|")
        lines.append(f"| {r.id} | {r.severity} | {title} |")
    return "\n".join(lines) + "\n"


def _fixable_rule_ids() -> set[str]:
    """Rule ids that `pgrls fix` can auto-remediate.

    Surfaced as the `fixable` flag in the JSON catalog so tooling
    (IDE integrations, dashboards) can show a "fix available" badge
    without hard-coding the list.
    """
    return {fixer.rule_id for fixer in default_fixers()}


def _render_rule_json(rule: Rule, *, fixable_ids: set[str]) -> str:
    """A single rule as a machine-readable JSON object.

    Includes the full reference body (the rule's docstring minus its
    title line) so a consumer gets everything `--format text` shows.
    """
    payload = {
        "id": rule.id,
        "severity": rule.severity,
        "title": rule.title,
        "fixable": rule.id in fixable_ids,
        "reference": _rule_docstring_body(rule),
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def _render_catalog_json(rules: list[Rule], *, fixable_ids: set[str]) -> str:
    """The rule catalog as a JSON document.

    Compact per-rule entries (id / severity / title / fixable) to
    mirror the text and Markdown catalogs; call `pgrls explain <RULE>
    --format json` for a single rule's full reference body.
    """
    payload = {
        "pgrls_version": __version__,
        "count": len(rules),
        "rules": [
            {
                "id": r.id,
                "severity": r.severity,
                "title": r.title,
                "fixable": r.id in fixable_ids,
            }
            for r in rules
        ],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# HTML rendering for `pgrls explain` (v0.6.21)
# ---------------------------------------------------------------------------

import html as _html_module  # noqa: E402  (kept local to the explain block)

# Severity → CSS color, matching the diff HTML and report HTML palettes.
_EXPLAIN_SEVERITY_COLOR: dict[str, str] = {
    "error": "#cf222e",    # red
    "warning": "#9a6700",  # amber
    "info": "#0969da",     # blue
}


def _explain_html_css() -> str:
    """Shared CSS preamble for `pgrls explain` HTML renderings.

    Same palette and dark-mode handling as `pgrls report --format
    html`, `pgrls history --format html`, and `pgrls diff --format
    html`. Returned as a single string so the per-rule and
    catalog renderers don't drift.
    """
    return """
  :root { color-scheme: light dark; }
  body { font: 14px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI",
         Roboto, "Helvetica Neue", Arial, sans-serif;
         margin: 2rem auto; max-width: 72rem; padding: 0 1rem;
         color: #1f2328; background: #ffffff; }
  @media (prefers-color-scheme: dark) {
    body { color: #e6edf3; background: #0d1117; }
    table { border-color: #30363d; }
    th { background: #161b22; }
    tr td { background: #0d1117; }
    tr:nth-child(even) td { background: #161b22; }
    code { background: #161b22; }
    pre { background: #161b22; }
  }
  header { margin-bottom: 1.5rem; }
  h1 { font-size: 1.5rem; margin: 0 0 .25rem 0; }
  h2 { font-size: 1.25rem; margin: 1.5rem 0 .5rem 0;
       padding-top: .5rem; border-top: 1px solid #d0d7de; }
  .meta { color: #57606a; font-size: .85rem; }
  .pill { display: inline-block; padding: .15rem .55rem;
          border-radius: 999px; font-size: .85rem;
          border: 1px solid currentColor; }
  .sev-error   { color: #cf222e; }
  .sev-warning { color: #9a6700; }
  .sev-info    { color: #0969da; }
  .fixable { display: inline-block; padding: .15rem .55rem;
             border-radius: 999px; font-size: .85rem;
             color: #1a7f37; border: 1px solid currentColor;
             margin-left: .25rem; }
  table { width: 100%; border-collapse: collapse;
          border: 1px solid #d0d7de; }
  thead th { text-align: left; padding: .5rem .75rem;
             background: #f6f8fa; border-bottom: 1px solid #d0d7de;
             font-weight: 600; }
  tbody td { padding: .5rem .75rem; border-bottom: 1px solid #d0d7de;
             vertical-align: top; }
  tbody tr:last-child td { border-bottom: 0; }
  code { background: #f6f8fa; padding: .1rem .35rem;
         border-radius: 4px;
         font: .9em ui-monospace, Menlo, monospace; }
  pre { background: #f6f8fa; padding: .75rem 1rem;
        border-radius: 6px; overflow-x: auto;
        font: .9em ui-monospace, Menlo, monospace;
        white-space: pre-wrap; word-break: break-word; }
  .reference { line-height: 1.6; }
  .reference p { margin: 0 0 .75rem 0; }
  footer { margin-top: 2rem; color: #57606a; font-size: .8rem; }
""".strip("\n")


def _render_rule_html(rule: Rule, *, fixable_ids: set[str]) -> str:
    """A single rule rendered as a standalone HTML page.

    Mirrors the design of `pgrls report --format html`: embedded
    CSS, no external assets, light/dark via `prefers-color-scheme`.
    Designed for sharing a single rule reference with someone who
    doesn't run pgrls — paste-into-Slack, print-to-PDF for a
    runbook attachment, embed in an internal wiki.

    The rule's docstring body is rendered as preformatted text
    (`<pre>`) so the rule-author's intended whitespace, code
    fences, and bullet alignment all survive. Future enhancement
    could attempt full Markdown→HTML conversion, but the current
    shape is robust to any docstring content.
    """
    fixable = rule.id in fixable_ids
    body = _rule_docstring_body(rule)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>pgrls explain — {_html_module.escape(rule.id)}</title>
<style>
{_explain_html_css()}
</style>
</head>
<body>
  <header>
    <h1>{_html_module.escape(rule.id)} — {_html_module.escape(rule.title)}</h1>
    <p class="meta">
      <span class="pill sev-{rule.severity}">{_html_module.escape(rule.severity)}</span>
      {'<span class="fixable">✦ auto-fixable</span>' if fixable else ''}
      &nbsp;·&nbsp; <code>pgrls explain {_html_module.escape(rule.id)}</code>
    </p>
  </header>
  <section class="reference">
    <pre>{_html_module.escape(body) if body else "(no extended reference for this rule)"}</pre>
  </section>
  <footer>pgrls {_html_module.escape(__version__)} — Postgres Row-Level Security linter · <a href="https://github.com/pgrls/pgrls">github.com/pgrls/pgrls</a></footer>
</body>
</html>
"""


def _render_catalog_html(rules: list[Rule], *, fixable_ids: set[str]) -> str:
    """The whole rule catalog as a standalone HTML page.

    Three things in one document: a header naming the pgrls version
    and rule count; a per-rule table (ID / Severity / Fixable /
    Title) so a reviewer can scan the catalog visually; and a
    severity-grouped index for jumping to per-rule sections of the
    docs site. Each rule row's ID links to the canonical
    `docs/RULES.md#rule-<id>` anchor on GitHub — same convention
    SARIF helpUri and the Markdown / pr-comment rule-link helpers
    use. Auto-fixable rules carry a green badge so a reader scanning
    "what's automatable" can see at a glance.
    """
    fixable_count = sum(1 for r in rules if r.id in fixable_ids)

    rows: list[str] = []
    for r in rules:
        fixable_badge = (
            '<span class="fixable">✦ fix</span>' if r.id in fixable_ids else ''
        )
        rule_id_e = _html_module.escape(r.id)
        title_e = _html_module.escape(r.title)
        sev_e = _html_module.escape(r.severity)
        # Rule-link convention: DIFF_* go to AGENTS.md#diff-rules;
        # lint rules to docs/RULES.md#rule-<lower>. Pgrls.explain
        # only walks the lint registry today (no DIFF_* in
        # all_rules()) so we use the lint convention unconditionally.
        link = (
            f"https://github.com/pgrls/pgrls/blob/main/docs/"
            f"RULES.md#rule-{rule_id_e.lower()}"
        )
        rows.append(
            f"      <tr>"
            f'<td><a href="{link}"><code>{rule_id_e}</code></a></td>'
            f'<td><span class="pill sev-{sev_e}">{sev_e}</span></td>'
            f"<td>{fixable_badge}</td>"
            f"<td>{title_e}</td>"
            "</tr>"
        )
    rows_html = "\n".join(rows)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>pgrls rule catalog</title>
<style>
{_explain_html_css()}
</style>
</head>
<body>
  <header>
    <h1>pgrls rule catalog</h1>
    <p class="meta">
      <code>pgrls {_html_module.escape(__version__)}</code>
      &nbsp;·&nbsp; <strong>{len(rules)}</strong> rules
      &nbsp;·&nbsp; <strong class="sev-info">{fixable_count}</strong> mechanically auto-fixable
    </p>
  </header>
  <table>
    <thead>
      <tr>
        <th>ID</th>
        <th>Severity</th>
        <th>Fixable</th>
        <th>Title</th>
      </tr>
    </thead>
    <tbody>
{rows_html}
    </tbody>
  </table>
  <footer>pgrls — Postgres Row-Level Security linter · <a href="https://github.com/pgrls/pgrls">github.com/pgrls/pgrls</a></footer>
</body>
</html>
"""


@main.command()
@click.argument("rule_id", metavar="RULE", required=False, default=None)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["text", "markdown", "json", "html"], case_sensitive=False),
    default="text",
    show_default=True,
    help=(
        "Output format. `text` (default, human-readable), "
        "`markdown` (embeddable in runbooks, wikis, or generated "
        "docs), `json` (machine-readable rule metadata for "
        "tooling / IDE integrations), or `html` (standalone page "
        "with embedded CSS — shareable rule reference, no external "
        "deps)."
    ),
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(dir_okay=False),
    default=None,
    help=(
        "Path to a pgrls.toml. When supplied, `[lint].extra_rules` "
        "are loaded so `pgrls explain` lists / documents project-"
        "specific rules alongside the built-ins. Without it, only "
        "built-ins are shown — explain works anywhere with no "
        "database, no config."
    ),
)
def explain(
    rule_id: str | None,
    output_format: str,
    config_path: str | None,
) -> None:
    """Print a lint rule's reference, or list the rule catalog.

    With no argument, `pgrls explain` prints the catalog — one
    line per rule (ID, severity, title) — so you can scan the
    shipping rule set at a glance.

    With a RULE argument (case-insensitive — `pgrls explain
    SEC023`, `pgrls explain perf001`), prints the rule's own
    reference documentation: what it flags, why that is a
    problem, how detection works, what is deliberately out of
    scope, and how to allowlist an intentional case. Exits 2 if
    RULE is not a known rule.

    Reads pgrls's built-in rule catalog by default — no database
    connection required. Pass `--config pgrls.toml` to also load
    project-specific rules declared in `[lint].extra_rules`.

    `--format markdown` emits the same content as a Markdown
    document (`##` heading + `**Severity:**` line + the rule's
    reference body, or a Markdown table for the catalog) so the
    output is paste-ready for a project runbook or wiki. `--format
    json` emits machine-readable rule metadata (id, severity, title,
    `fixable` flag, and — for a single rule — the full reference
    body) for IDE / tooling integrations.
    """
    if config_path is not None:
        try:
            config = load_config(config_path)
        except ConfigError as exc:
            raise ToolError(str(exc)) from exc
        rules = _runtime_rules(config)
    else:
        rules = list(all_rules())
    if rule_id is None:
        # Catalog mode.
        if output_format == "json":
            click.echo(
                _render_catalog_json(rules, fixable_ids=_fixable_rule_ids())
            )
            return
        if output_format == "markdown":
            click.echo(_render_catalog_markdown(rules), nl=False)
            return
        if output_format == "html":
            click.echo(
                _render_catalog_html(
                    rules, fixable_ids=_fixable_rule_ids()
                ),
                nl=False,
            )
            return
        # Text catalog — one line per rule, padded so IDs and
        # titles line up across the rows.
        for r in rules:
            sev = f"[{r.severity}]"
            click.echo(f"{r.id:<8} {sev:<9} {r.title}")
        click.echo()
        click.echo(
            "Run `pgrls explain <RULE>` for the full reference of any rule."
        )
        return
    normalized = rule_id.strip().upper()
    rule = next((r for r in rules if r.id == normalized), None)
    if rule is None:
        known = ", ".join(r.id for r in rules)
        raise ToolError(f"Unknown rule {rule_id!r}. Known rules: {known}.")

    if output_format == "json":
        click.echo(
            _render_rule_json(rule, fixable_ids=_fixable_rule_ids())
        )
        return

    if output_format == "markdown":
        click.echo(_render_rule_markdown(rule), nl=False)
        return

    if output_format == "html":
        click.echo(
            _render_rule_html(rule, fixable_ids=_fixable_rule_ids()),
            nl=False,
        )
        return

    click.echo(f"{rule.id}  [{rule.severity}]  {rule.title}")
    # The explanation is the rule module's docstring (minus its
    # title line, which the header just printed). `_rule_docstring_body`
    # centralises the strip so `--format markdown` and the default
    # text path stay in sync.
    body = _rule_docstring_body(rule)
    if body:
        click.echo()
        click.echo(body)


@main.command()
@common_db_options
@output_format_options(
    list(REPORT_FORMATS),
    output_help="Write the report to this file instead of stdout (any --format).",
)
def report(
    database_url: str | None,
    config_path: str | None,
    schemas: str | None,
    output_path: str | None,
    output_format: str,
) -> None:
    """Summarize the RLS posture of every table — no rules, no findings.

    A factual snapshot for audits and onboarding: per-table RLS
    enabled / FORCE'd / policy counts plus a coarse status
    (`protected` / `not-forced` / `no-policies` / `covered-by-parent`
    / `rls-off`) and an aggregate summary. Reads a live database and
    runs NO lint rules — use `pgrls lint` for findings. `--format
    json` / `markdown` emit machine-readable / paste-ready output;
    `--format html` emits a standalone HTML audit page (embedded CSS,
    no external dependencies — opens offline, prints/PDF cleanly).
    `--output FILE` writes it to a file (e.g. an audit doc) instead of
    stdout.
    """
    _, schema = _connect_and_introspect(
        config_path=config_path,
        database_url=database_url,
        schemas_csv=schemas,
    )

    rendered = render_report(build_report(schema), output_format)
    _emit(rendered, output_path)


@main.command()
@common_db_options
@click.option(
    "--roles",
    "roles_csv",
    default=None,
    help=(
        "Comma-separated roles to show as columns (overrides auto-discovery). "
        "Default: PUBLIC, anon, authenticated plus every non-system role named "
        "by a grant or policy, or carrying BYPASSRLS."
    ),
)
@click.option(
    "--include-system-roles",
    "include_system",
    is_flag=True,
    default=False,
    help="Also show pg_* system roles (hidden by default).",
)
@output_format_options(
    list(MATRIX_FORMATS),
    output_help="Write the matrix to this file instead of stdout (any --format).",
)
def matrix(
    database_url: str | None,
    config_path: str | None,
    schemas: str | None,
    roles_csv: str | None,
    include_system: bool,
    output_path: str | None,
    output_format: str,
) -> None:
    """Show who can access what — a role x table x command access matrix.

    The audit companion to `pgrls report`: instead of each table's posture,
    it collapses table GRANTs, the RLS enabled/forced flags, and the
    permissive(OR) / restrictive(AND) policy set into one verdict per cell —
    `OPEN` (every row reachable), `DENIED` (no privilege, or RLS on with no
    applicable permissive policy), or `COND` (gated by a row predicate, shown
    in `--format json`/`html`). Per command it uses the clause Postgres
    applies: `WITH CHECK` for INSERT, `USING` for SELECT/UPDATE/DELETE.
    Reads a live database and runs NO lint rules. `--roles a,b` overrides the
    columns; `--include-system-roles` adds `pg_*`. Note: a table *owner*
    bypasses RLS unless the table is `FORCE`d, and a superuser bypasses
    everything — neither is modeled per-cell.
    """
    # Validate --roles before connecting so a malformed flag fails fast
    # (no database round-trip needed to reject it).
    roles: tuple[str, ...] | None = None
    if roles_csv is not None:
        roles = tuple(
            dict.fromkeys(r.strip() for r in roles_csv.split(",") if r.strip())
        )
        if not roles:
            raise ToolError("--roles listed no role names.")

    _, schema = _connect_and_introspect(
        config_path=config_path,
        database_url=database_url,
        schemas_csv=schemas,
    )

    built = build_matrix(schema, roles=roles, include_system=include_system)
    rendered = render_matrix(built, output_format)
    _emit(rendered, output_path)


def _verify_anon_roles(mode: str, rule_options: dict[str, Any]) -> set[str] | None:
    """The anon-role set the verifier should honor for `mode`, reusing the lint
    rule's own `anon_roles` convention so lint and verify never disagree.

    * ``anon`` gates every permissive policy to those an anonymous session can
      invoke — honors ``[lint.rules.SEC004].anon_roles`` (the rule that WARNs vs
      ERRORs on the very same inverted-auth shape).
    * ``escalation`` proves the SEC042 anon-callable-SECDEF case — honors
      ``[lint.rules.SEC042].anon_roles``.
    * ``reachability`` asks which roles can ``SELECT`` the bypassing view, and
      joins the answer against the table's ``anon`` verdict — so it must use
      the same *anonymous* set that mode does (SEC004's). Deliberately NOT
      SEC052's ``grantees``, whose default includes ``authenticated``: that set
      answers "reachable over the API", a broader question. Treating an
      authenticated role as anonymous is precisely the bug that made the probe
      grant itself ``authenticated`` and then contradict a correct proof.

    Other modes (``cross-tenant`` / ``write``) don't role-gate → ``None``.
    """
    try:
        if mode in ("anon", "reachability"):
            from pgrls.rules.sec004 import _parse_anon_roles

            return _parse_anon_roles(rule_options.get("SEC004", {}))
        if mode == "escalation":
            from pgrls.rules.sec042 import _parse_anon_roles

            return _parse_anon_roles(rule_options.get("SEC042", {}))
    except TypeError as exc:
        raise click.UsageError(str(exc)) from exc
    return None


def _identity_columns_from_config(config_path: str | None) -> frozenset[str] | None:
    """`[lint.rules.SEC021].identity_columns`, for the cross-tenant axis gate.

    The cross-tenant / write provers only accept an identity-named column as
    the tenant axis (a `status = <session value>` equality proves nothing
    about tenants). SEC021's option is the one place a project already names
    its discriminator columns, so honour it here too; None → the default set.
    """
    try:
        cfg = load_config(config_path)
    except ConfigError as exc:
        raise ToolError(str(exc)) from exc
    cols = cfg.rule_options.get("SEC021", {}).get("identity_columns")
    if not cols:
        return None
    return frozenset(str(c).lower() for c in cols)



@main.command()
@common_db_options
@click.option(
    "--mode",
    "mode",
    type=click.Choice(
        ["anon", "cross-tenant", "write", "escalation", "reachability"]
    ),
    default="anon",
    show_default=True,
    help=(
        "Threat model to prove. 'anon': no row is readable by an "
        "anonymous session — JWT-less (every auth function NULL) or Supabase "
        "anon-key (auth.role() = 'anon', auth.jwt() non-null, auth.uid() "
        "NULL); a leak under either is a leak. 'cross-tenant': no row of one tenant is "
        "readable by a session authenticated as a different tenant (verifies "
        "the `<column> = <session identity>` scoping equality). 'write': no "
        "such session can WRITE (INSERT/UPDATE/DELETE) a row of another tenant "
        "— proven over BOTH gates of each write policy: the new-row gate (WITH "
        "CHECK, or the USING that FOR UPDATE/ALL reuses) and the old-row gate "
        "(USING, for UPDATE/DELETE/ALL); SEC006/SEC020/SEC028/SEC040 are the "
        "linter fallback. 'escalation': prove the SEC048 finding — a low-trust "
        "role that reaches a table's owner (not superuser/BYPASSRLS) bypasses "
        "the RLS on that owner's enabled-but-not-FORCE'd tables; LEAK when the "
        "table's RLS provably isolates tenants (so the bypass defeats real "
        "isolation), PROVEN when it does not. 'reachability': prove no "
        "anon-selectable VIEW hands back the rows a table's own policies "
        "withhold — a `security_invoker = false` view executes as its owner "
        "(the nearest such view on a view→view→table path sets the effective "
        "user), so a path whose effective owner is RLS-exempt — "
        "superuser/BYPASSRLS, or the table owner or an INHERIT member of it "
        "when the table is not FORCE'd — returns every row to anon while "
        "'anon' mode correctly reports the table itself isolated; UNVERIFIED "
        "when the role-membership graph is unavailable."
    ),
)
@click.option(
    "--auth-function",
    "auth_functions",
    multiple=True,
    help=(
        "Treat this function as an auth-context value, in addition to the "
        "defaults (auth.uid/role/jwt, current_setting): NULL under 'anon', a "
        "session identity under 'cross-tenant'. Repeatable — pass a project's "
        "custom auth helper, e.g. --auth-function auth.user_id."
    ),
)
@click.option(
    "--strict",
    "strict",
    is_flag=True,
    default=False,
    help="Also exit non-zero when any table is UNVERIFIED (not just on a leak).",
)
@click.option(
    "--against",
    "against",
    metavar="BASE",
    default=None,
    help=(
        "Compare against a baseline schema (a snapshot JSON or a DB URL) and "
        "report only the leaks this change *introduced*: a table PROVEN "
        "in BASE (or absent from it) that the live schema now proves LEAK. Exits "
        "non-zero only on a NEW leak — pre-existing leaks don't fail the gate — "
        "so it's the 'no new provable leak' PR check (pair a committed `pgrls "
        "snapshot` of main as BASE with the PR branch's live DB). A BASE table "
        "that was UNVERIFIED is never counted as newly-leaking (soundness). "
        "--format text/json/sarif; SARIF carries only the new leaks."
    ),
)
@click.option(
    "--emit-repro",
    "emit_repro_dir",
    type=click.Path(file_okay=False),
    default=None,
    help=(
        "For each LEAK, write a runnable reproduction (a .sql script and a "
        "pytest) to this directory — recreating the table + policy and "
        "demonstrating the leak per --mode: reading the counterexample row back "
        "as an anonymous (anon) or different-tenant (cross-tenant) session, or "
        "(write) INSERTing a row stamped for another tenant and observing it "
        "admitted. Not supported with --mode escalation (use --probe) or "
        "--mode reachability (the leak is a view path; the DETAIL column names "
        "the view to query)."
    ),
)
@click.option(
    "--force",
    "force",
    is_flag=True,
    default=False,
    help=(
        "Overwrite existing reproduction files in the --emit-repro directory "
        "(otherwise an existing file is left untouched and the run errors)."
    ),
)
@click.option(
    "--probe",
    "probe",
    is_flag=True,
    default=False,
    help=(
        "Confirm the static proof against the LIVE database: connect as the "
        "threat-model session, seed a throwaway row, run the real query, and "
        "diff observed behavior against the Z3 verdict — all inside a "
        "rolled-back transaction (nothing is committed). Reports AGREE / "
        "MISMATCH / LEAK CONFIRMED per table; upgrades an UNVERIFIED policy that "
        "leaks live to a reproduced leak. Exits non-zero on any mismatch or "
        "live-confirmed leak. Requires a live --database-url and a connection "
        "that can create a role (CREATEROLE / superuser); abstains cleanly "
        "otherwise. Not supported with --emit-repro (run them separately) or with --mode reachability (rejected; that mode reports the static verdict only)."
    ),
)
@click.option(
    "--probe-role",
    "probe_role",
    default="pgrls_probe_runner",
    show_default=True,
    help=(
        "Name of the unprivileged (NOLOGIN/NOSUPERUSER/NOBYPASSRLS) role the "
        "--probe creates and runs each probe query as. It is created and "
        "dropped inside the rolled-back probe transaction; pass a name not "
        "already taken in the database."
    ),
)
@output_format_options(
    list(VERIFY_FORMATS),
    output_help="Write the proof report to this file instead of stdout.",
)
def verify(
    database_url: str | None,
    config_path: str | None,
    schemas: str | None,
    mode: str,
    auth_functions: tuple[str, ...],
    strict: bool,
    against: str | None,
    emit_repro_dir: str | None,
    force: bool,
    probe: bool,
    probe_role: str,
    output_path: str | None,
    output_format: str,
) -> None:
    """Prove tenant isolation with Z3 — and show a leaking row when it fails.

    For every RLS-enabled table, `pgrls verify` *proves* a read-isolation
    property. `--mode anon` (default): can an **anonymous** session (every auth
    function NULL — the JWT-less connection — *or* the Supabase anon-key
    caller: `auth.role()` = 'anon', `auth.jwt()` non-null, `auth.uid()` NULL)
    read any row? A leak under either session is a leak. `--mode cross-tenant`: can a session authenticated as one
    tenant read a **different** tenant's row (against the policy's
    `<column> = <session identity>` scoping equality)? `--mode write`: can such
    a session **write** (INSERT/UPDATE/DELETE) a row of another tenant — proven
    over BOTH gates of each write policy: the new-row gate (`WITH CHECK`, or the
    `USING` that `FOR UPDATE`/`FOR ALL` reuses) and the old-row gate (`USING`,
    for `UPDATE`/`DELETE`/`ALL`)? Three honest verdicts:
    `PROVEN` (the property is unsatisfiable under the threat model), `LEAK` (it
    *is* violated — with a concrete counterexample), or `UNVERIFIED` (Z3
    unavailable, the predicate is outside the decidable fragment, it timed out,
    or — cross-tenant/write — there is no single scoping equality to verify;
    here the verifier degrades to the linter, run `pgrls lint` — for write, the
    SEC006/SEC020/SEC028/SEC040 write-check rules).

    The `anon` and `cross-tenant` modes are complementary: the inverted `auth.uid() IS NULL OR …`
    policy is an anon LEAK but cross-tenant PROVEN. Unlike `pgrls lint`
    (heuristic findings) this is a soundness proof: it never reports a leak it
    cannot exhibit, and never reports isolated unless Z3 proves it. Exits
    non-zero on any leak — drop it in CI as a hard tenant-isolation gate.
    `--strict` also fails on UNVERIFIED. `--format json` emits the
    per-table/per-policy verdicts and counterexamples; `--format sarif` emits a
    SARIF v2.1.0 document for GitHub Code Scanning (each LEAK an error result;
    UNVERIFIED surfaces only under `--strict`), sharing lint's SARIF schema and
    driver block. `--emit-repro DIR`
    writes, for each leak, a runnable `.sql` script and a pytest that recreate
    the table + policy and demonstrate the leak per `--mode`: reading the
    counterexample row back as an anonymous (`anon`) or different-tenant
    (`cross-tenant`) session, or — `--mode write` — as tenant A INSERTing a row
    stamped for tenant B and observing it admitted (rejected once the WITH CHECK
    is fixed). The proof, made reproducible (re-running won't clobber a
    hand-edited reproduction unless `--force`). Not supported with `--mode
    escalation` (use `--probe`) or `--mode reachability` (the leak is a view
    path — the DETAIL names the view to query). See the README for scope.

    `--probe` keeps the static proof honest by confirming it against the LIVE
    database: it connects as the threat-model session, seeds a throwaway row,
    runs the real query, and diffs the observed behavior against the Z3 verdict
    — all inside a transaction that is rolled back, so nothing is committed. It
    reports AGREE / MISMATCH / LEAK CONFIRMED per table and, crucially, upgrades
    an UNVERIFIED policy that turns out to leak live into a reproduced leak.
    With `--probe`, `pgrls verify` exits non-zero on any proof↔reality mismatch
    or live-confirmed leak. `--probe` only ever ADDS evidence, so it is never
    weaker than plain `verify`: under `--strict` it still fails on any table
    the verifier could not decide, whether the probe abstained or ran without
    seeing a leak — one sampled row is not a proof. It needs a
    connection that can create a role; anything it cannot reproduce live it
    abstains on cleanly. `--probe` supports `--format text` / `json` / `sarif`
    (probe MISMATCH / LEAK CONFIRMED → SARIF `error` results for GitHub Code
    Scanning); it is not supported with `--emit-repro` — run those separately.
    """
    if probe and emit_repro_dir is not None:
        raise click.UsageError("run --probe and --emit-repro separately")
    identity_columns = _identity_columns_from_config(config_path)
    if mode == "escalation" and emit_repro_dir is not None:
        # The escalation bypass is a SET-ROLE role-reachability chain, not a
        # single policy predicate the emitter can template; --probe live-confirms
        # it instead. Fail fast rather than emit a wrong repro.
        raise click.UsageError(
            "--emit-repro is not supported with --mode escalation "
            "(the SET ROLE chain has no static reproduction template — use "
            "--probe, which live-confirms the escalation bypass)."
        )
    if mode == "reachability" and emit_repro_dir is not None:
        # A reachability leak is a VIEW path, and its proof names the view,
        # not a policy — the emitter would silently write zero files.
        raise click.UsageError(
            "--emit-repro is not supported with --mode reachability (the leak "
            "is a view path, not a policy predicate; the DETAIL column names "
            "the view to query)."
        )
    if mode == "reachability" and probe:
        raise click.UsageError(
            "--probe is not supported with --mode reachability yet; the mode "
            "reports the static verdict only."
        )
    if against is not None and probe:
        raise click.UsageError(
            "--against and --probe cannot be combined: --against compares two "
            "static schemas, --probe live-confirms one database."
        )
    if against is not None and emit_repro_dir is not None:
        raise click.UsageError(
            "--against and --emit-repro cannot be combined (emit a reproduction "
            "for the head schema in a separate run)."
        )
    auth = (
        set(DEFAULT_AUTH_FUNCTIONS) | {a.strip() for a in auth_functions if a.strip()}
        if auth_functions
        else None
    )

    if probe:
        # The probe needs the SAME connection still open after introspection (to
        # seed + query + roll back), so use the open-connection context manager
        # rather than the read-only `_connect_and_introspect` that closes it.
        with _connect_introspect_ctx(
            config_path=config_path,
            database_url=database_url,
            schemas_csv=schemas,
        ) as (_cfg, conn, schema):
            probe_anon_roles = _verify_anon_roles(mode, _cfg.rule_options)
            verification = build_verification(schema, auth_functions=auth, mode=mode, anon_roles=probe_anon_roles, identity_columns=identity_columns)  # type: ignore[arg-type]
            probe_result = run_probe(
                conn, schema, verification,
                mode=mode,  # type: ignore[arg-type]
                auth_functions=auth, probe_role=probe_role,
                anon_roles=probe_anon_roles,
            )
        # Text shows the static proof and the live probe section stacked; JSON is
        # the self-contained probe document (it carries each table's
        # static_verdict, so the static JSON would be redundant).
        if output_format == "json":
            _emit(render_probe(probe_result, "json"), output_path)
        elif output_format == "sarif":
            # SARIF threads --strict (abstains become `note` results), so call
            # the probe SARIF renderer directly (mirrors verify's SARIF path).
            _emit(render_probe_sarif(probe_result, strict=strict), output_path)
        else:
            static_text = render_verify(verification, "text")
            probe_text = render_probe(probe_result, "text")
            _emit(f"{static_text}\n\n{probe_text}", output_path)
        # --probe must never be *less* strict than plain verify: a soundly
        # proven static leak still fails the gate even when the live probe could
        # not reproduce it (e.g. it abstained on an un-seedable NOT NULL column).
        if (
            verification.has_leak
            or probe_result.has_mismatch
            or probe_result.has_confirmed_leak
        ):
            sys.exit(1)
        # ...and that extends to --strict. The plain path fails on any table
        # the verifier could not decide; the probe must fail on those too. A
        # probe that saw no leak on a statically UNVERIFIED table is agreement
        # `skipped`, whose own detail says "not a proof" — it is one sampled
        # row, not a proof of isolation, so it cannot satisfy a gate that means
        # "fail unless proven". Checking `verification.tables` rather than only
        # the probe's own rows also covers a table the probe never reached.
        if strict and (
            any(t.verdict == "unverified" for t in verification.tables)
            or any(r.agreement == "abstained" for r in probe_result.results)
        ):
            sys.exit(1)
        return

    cfg, schema = _connect_and_introspect(
        config_path=config_path,
        database_url=database_url,
        schemas_csv=schemas,
    )

    # Both role-gated modes honor the anon-role set of the lint rule they prove,
    # so `verify` and `lint` never disagree on which roles count as anonymous
    # (`anon`→SEC004, `escalation`→SEC042; default {anon, PUBLIC}).
    anon_roles = _verify_anon_roles(mode, cfg.rule_options)

    verification = build_verification(schema, auth_functions=auth, mode=mode, anon_roles=anon_roles, identity_columns=identity_columns)  # type: ignore[arg-type]

    if against is not None:
        # Compose the head verdicts with a baseline schema and report only the
        # leaks THIS change introduced — the "no new provable leak" PR gate.
        schema_list = (
            [s.strip() for s in schemas.split(",") if s.strip()]
            if schemas
            else cfg.schemas
        )
        # A snapshot base serializes only policy SQL, not the parsed AST that
        # the verifier walks; reparse it (a no-op for a live-URL base, whose
        # ASTs introspection already populated).
        base_schema = reparse_policy_asts(
            _resolve_diff_source(against, schemas=schema_list)
        )
        base_verification = build_verification(base_schema, auth_functions=auth, mode=mode, anon_roles=anon_roles, identity_columns=identity_columns)  # type: ignore[arg-type]
        delta = diff_verifications(base_verification, verification)
        if output_format == "sarif":
            # The gate is "no NEW leak", so introduced leaks become SARIF error
            # results (pre-existing leaks are the baseline, not this change's
            # regressions). Under --strict a newly-unverified table also fails
            # the gate (exit 1 below), so include those too — as note results —
            # otherwise a red check would carry zero alerts.
            projected = list(delta.new_leaks)
            if strict:
                projected += list(delta.new_unverified)
            rendered = render_verify_sarif(
                Verification(tuple(projected), verification.mode), strict=strict
            )
        elif output_format == "json":
            rendered = render_delta_json(delta)
        else:
            rendered = render_delta_text(delta)
        _emit(rendered, output_path)
        if delta.new_leaks:
            sys.exit(1)
        if strict and delta.new_unverified:
            sys.exit(1)
        return

    # SARIF is the one format whose result-set depends on --strict (UNVERIFIED
    # is omitted by default, a `note` under --strict), so it can't go through
    # the 1-arg render() dispatcher — call render_sarif directly to thread the
    # flag. text/json are strict-independent and dispatch normally.
    if output_format == "sarif":
        rendered = render_verify_sarif(verification, strict=strict)
    else:
        rendered = render_verify(verification, output_format)
    _emit(rendered, output_path)

    if emit_repro_dir is not None:
        from pathlib import Path

        from pgrls.repro import emit_repros

        out_dir = Path(emit_repro_dir)
        artifacts = emit_repros(schema, verification, auth_functions=auth, mode=mode)
        if not force:
            # Refuse to clobber a hand-edited reproduction (the artifacts tell
            # the developer to edit the INSERT for conditional/cross-table
            # leaks) — the same --force guard generate/fix/init use. All-or-
            # nothing: bail before writing anything if any target exists.
            clash = next(
                (
                    out_dir / name
                    for art in artifacts
                    for name in (art.sql_filename, art.pytest_filename)
                    if (out_dir / name).exists()
                ),
                None,
            )
            if clash is not None:
                raise ToolError(
                    f"{clash} already exists. Pass --force to overwrite "
                    "reproduction files."
                )
        try:
            out_dir.mkdir(parents=True, exist_ok=True)
            for art in artifacts:
                (out_dir / art.sql_filename).write_text(
                    art.sql, encoding="utf-8", newline="\n"
                )
                (out_dir / art.pytest_filename).write_text(
                    art.pytest, encoding="utf-8", newline="\n"
                )
        except OSError as exc:
            raise ToolError(
                f"Cannot write reproduction files to {emit_repro_dir}: {exc}"
            ) from exc
        click.echo(
            f"pgrls: wrote {len(artifacts)} reproduction(s) to {emit_repro_dir}",
            err=True,
        )

    if verification.has_leak:
        sys.exit(1)
    if strict and any(t.verdict == "unverified" for t in verification.tables):
        sys.exit(1)


@main.command()
@common_db_options
@click.option(
    "--probe-role",
    "probe_role",
    default=None,
    help=(
        "Role to probe as — the low-trust role your API runs retrieval under "
        "(e.g. `authenticated`). Defaults to the first concrete role holding "
        "EXECUTE on the retrieval function."
    ),
)
@click.option(
    "--set",
    "settings",
    multiple=True,
    metavar="GUC=VALUE",
    help=(
        "Session setting to stamp before probing, e.g. "
        "--set request.jwt.claim.sub=<a-user-id>. Repeatable. This is the "
        "identity your policies read; without it an identity-less session sees "
        "no rows, so the comparison cannot discriminate and abstains."
    ),
)
@output_format_options(
    ["text", "json"], output_help="Write the retrieval-path audit here."
)
def vector(
    config_path: str | None,
    database_url: str | None,
    schemas: str | None,
    probe_role: str | None,
    settings: tuple[str, ...],
    output_format: str,
    output_path: str | None,
) -> None:
    """Detect an RLS bypass on the RAG (pgvector) retrieval path.

    Audits the Supabase *RAG with Permissions* shape: embeddings in a
    `document_sections`-style table gated by RLS, retrieved through a
    `match_documents()` similarity-search function. The bypass this catches is
    invisible to table-level checks — RLS is on, `FORCE`'d, the policy is right,
    and a direct SELECT as another tenant returns zero rows — because the leak
    lives in the *composed path*: a `SECURITY DEFINER` retrieval function runs
    with the owner's privileges and hands back rows the caller's RLS denies.

    For each (embeddings table -> SECDEF retrieval function) pair it compares,
    as a low-trust role inside a rolled-back transaction, the primary keys the
    function surfaces against the keys a direct SELECT allows. The table's RLS
    defines what that role may see, so a surfaced-but-denied key is a proven
    bypass and the row is printed as evidence. This is a leak DETECTOR, not an
    isolation prover: "no leak" means only that this spot-check came up clean,
    never that the path is safe for every argument — which is why the clean
    verdict is NO LEAK, not PROVEN.

    Pass `--probe-role` for the low-trust role your API uses; without it every
    concrete EXECUTE grantee is probed. `--set guc=value` stamps the session
    identity the policies read (e.g. `--set request.jwt.claim.sub=<uuid>`).

    It issues only SELECTs and always rolls back, but it *executes* the
    retrieval function with the definer's privileges — a function that commits a
    side effect outside the transaction (dblink, an FDW write) is not contained.
    Exits 1 when any retrieval path leaks.
    """
    from pgrls.vector import render_json, render_text, run_vector_audit

    parsed: dict[str, str] = {}
    for item in settings:
        key, sep, value = item.partition("=")
        if not sep or not key.strip():
            raise click.UsageError(
                f"--set expects GUC=VALUE, got {item!r}"
            )
        parsed[key.strip()] = value

    with _connect_introspect_ctx(
        config_path=config_path,
        database_url=database_url,
        schemas_csv=schemas,
    ) as (_cfg, conn, schema):
        audit = run_vector_audit(
            conn, schema, probe_role=probe_role, settings=parsed
        )

    rendered = render_json(audit) if output_format == "json" else render_text(audit)
    _emit(rendered, output_path)
    if audit.has_leak:
        sys.exit(1)


@main.command()
def mcp() -> None:
    """Run the pgrls MCP server (stdio) for AI coding agents. Requires pgrls[mcp].

    Starts a Model Context Protocol server over stdio that exposes pgrls's
    static analysis — `lint`, `verify`, `explain_rule`, `list_rules` — as MCP
    tools. The headline is OFFLINE analysis of raw DDL: an agent passes the
    `CREATE TABLE` / `CREATE POLICY` SQL it just wrote and pgrls lints +
    Z3-verifies it with no database. The server is read-only / diagnostic-only
    — it never mutates a database and never auto-applies SQL.

    Point an MCP client at it with:
    `{"mcpServers": {"pgrls": {"command": "pgrls", "args": ["mcp"]}}}`.
    """
    # Import the server LAZILY (it imports the optional `fastmcp` extra). The
    # normal CLI path must never import FastMCP — this mirrors the
    # `pgrls[diff-apply]` extra's import-guard pattern above.
    try:
        from pgrls.mcp.server import run_stdio
    except ImportError as exc:
        raise ToolError(
            "the MCP server requires the `pgrls[mcp]` extra. "
            "Install with `pip install 'pgrls[mcp]'`."
        ) from exc
    run_stdio()


@main.command()
def lsp() -> None:
    """Run the pgrls Language Server (stdio) for real-time editor diagnostics.
    Requires pgrls[lsp].

    Starts an LSP server over stdio that lints the `.sql` buffer you are editing
    as you type — in any LSP client (VS Code, Neovim, Helix, JetBrains). It runs
    the OFFLINE `schema_from_sql` engine (the same one `pgrls lint --sql-file`
    uses) on each change and publishes findings as diagnostics pinned to the
    exact `CREATE TABLE` / `CREATE POLICY` line. It never connects to a database
    and never mutates anything — diagnostic-only.

    Rules that need live catalog state (BYPASSRLS roles, SECURITY DEFINER
    owners, triggers, indexes, …) cannot be analyzed from a buffer and are
    skipped, exactly as in the `--sql-file` path — so an absence of diagnostics
    is not a proof of safety; run `pgrls lint` against a live database for full
    coverage.

    Point an editor's LSP client at `pgrls lsp` for `sql` filetypes. Example
    (Neovim): `vim.lsp.start({ name = 'pgrls', cmd = { 'pgrls', 'lsp' } })`.
    """
    # Import the server LAZILY (it imports the optional `pygls` extra). The
    # normal CLI path must never import pygls — mirrors the `pgrls[mcp]`
    # lazy-import contract above.
    try:
        from pgrls.lsp.server import run_stdio
    except ImportError as exc:
        raise ToolError(
            "the Language Server requires the `pgrls[lsp]` extra. "
            "Install with `pip install 'pgrls[lsp]'`."
        ) from exc
    run_stdio()


@main.command()
@common_db_options
@click.option(
    "--coverage",
    "coverage_path",
    type=click.Path(dir_okay=False),
    default=DEFAULT_ARTIFACT_PATH,
    show_default=True,
    help="Coverage artifact written by your pgrls.testing run.",
)
@click.option(
    "--fail-under",
    "fail_under",
    type=click.FloatRange(0, 100),
    default=None,
    help="Exit 1 if coverage %% is below this threshold (CI gate).",
)
@output_format_options(
    list(COVERAGE_FORMATS),
    output_help="Write the report to this file instead of stdout (any --format).",
)
def coverage(
    database_url: str | None,
    config_path: str | None,
    schemas: str | None,
    coverage_path: str,
    fail_under: float | None,
    output_path: str | None,
    output_format: str,
) -> None:
    """Report which RLS policies your test suite exercised.

    Cross-references the coverage artifact (`.pgrls-coverage.json`,
    written automatically when your `pgrls.testing` suite runs) against
    the live schema. A policy is *covered* when a test queried its table,
    under a role the policy targets (or PUBLIC), with a matching command;
    everything else is *uncovered* — the cross-tenant DELETE nobody
    tested. `--format json` / `markdown` / `html` emit machine-readable /
    paste-ready / standalone-page output. `--fail-under N` exits 1 when
    coverage falls below N% — drop it in CI next to `pgrls lint`.
    """
    # Resolve config + guard the DB URL first, then load the coverage
    # artifact *before* connecting so a bad artifact path fails fast
    # (preserving the original error precedence: artifact errors surface
    # before any database connection is attempted).
    effective = _load_effective_config(
        config_path=config_path,
        database_url=database_url,
        schemas_csv=schemas,
    )

    try:
        data = load_coverage_artifact(coverage_path)
    except FileNotFoundError as exc:
        raise ToolError(
            f"Coverage artifact {coverage_path!r} not found. Run your "
            "pgrls.testing suite first — it writes .pgrls-coverage.json on "
            "finish — or pass --coverage PATH."
        ) from exc
    except (ValueError, OSError) as exc:
        raise ToolError(
            f"Cannot read coverage artifact {coverage_path!r}: {exc}"
        ) from exc

    assert effective.database_url is not None  # guaranteed above
    try:
        with psycopg.connect(effective.database_url) as conn:
            schema = introspect(conn, schemas=effective.schemas)
    except psycopg.Error as exc:
        raise ToolError(f"Database error: {exc}") from exc
    except ValueError as exc:
        raise ToolError(str(exc)) from exc

    report = build_coverage(schema, data)
    rendered = render_coverage(report, output_format)
    _emit(rendered, output_path)

    # Gate on the RAW fraction, not the 1-dp display value: 9999/10000 =
    # 99.99% rounds to 100.0 and would slip past --fail-under 100 even
    # though a policy is uncovered.
    summary = report.summary
    total_policies = summary["policies"]
    covered = summary["covered"]
    raw_pct = 100.0 if total_policies == 0 else 100.0 * covered / total_policies
    if fail_under is not None and raw_pct < fail_under:
        click.echo(
            f"pgrls: coverage {covered}/{total_policies} policies "
            f"({raw_pct:.2f}%) is below --fail-under {fail_under}%.",
            err=True,
        )
        sys.exit(1)


def _perf003_flagged_tables(schema: Schema) -> set[tuple[str, str]]:
    """The ``(schema, table)`` set PERF003 statically flags.

    A table is flagged when PERF003 reports any of its policies as having
    a predicate column without a usable leading-column index. Run with
    empty options — this is an internal classification signal for
    ``pgrls perf`` (confirmed-missing-index vs index-unused), deliberately
    independent of the user's PERF003 lint config (disable / allowlist /
    severity). PERF003's violation ``location`` is the policy id
    ``schema.table.policy``; we match against each table's known policy
    ids rather than parse the string, so quoted identifiers can't trip it.
    """
    perf003 = next((r for r in all_rules() if r.id == "PERF003"), None)
    if perf003 is None:  # pragma: no cover - PERF003 is always registered
        return set()
    flagged_locations = {v.location for v in perf003.check(schema, {})}
    out: set[tuple[str, str]] = set()
    for table in schema.tables:
        for policy in table.policies:
            if f"{table.schema}.{table.name}.{policy.name}" in flagged_locations:
                out.add((table.schema, table.name))
    return out


@main.command()
@common_db_options
@click.option(
    "--min-rows",
    "min_rows",
    type=click.IntRange(min=0),
    default=PerfThresholds.min_live_tup,
    show_default=True,
    help=(
        "Ignore tables with fewer than this many estimated live rows — "
        "a sequential scan of a small table is cheap and usually correct."
    ),
)
@click.option(
    "--min-seq-scans",
    "min_seq_scans",
    type=click.IntRange(min=0),
    default=PerfThresholds.min_seq_scans,
    show_default=True,
    help=(
        "Ignore tables sequentially scanned fewer than this many times "
        "(a handful of scans is noise, not a steady-state cost)."
    ),
)
@click.option(
    "--min-seq-pct",
    "min_seq_pct",
    type=click.FloatRange(0, 100),
    default=PerfThresholds.min_seq_pct,
    show_default=True,
    help=(
        "Ignore tables that do less than this %% of their scanning "
        "sequentially (a mostly-index-scanned table is healthy)."
    ),
)
@click.option(
    "--fail-on-findings",
    is_flag=True,
    default=False,
    help="Exit 1 if any RLS table is under seq-scan pressure (CI gate).",
)
@click.option(
    "--statements",
    is_flag=True,
    default=False,
    help=(
        "Attribute seq-scan cost to specific queries via pg_stat_statements "
        "(extension required; degrades gracefully if absent)."
    ),
)
@click.option(
    "--output",
    "-o",
    "output_path",
    type=click.Path(dir_okay=False),
    default=None,
    help="Write the report to this file instead of stdout (any --format).",
)
@click.option(
    "--snapshot",
    "snapshot_path",
    type=click.Path(dir_okay=False),
    default=None,
    is_flag=False,
    flag_value=DEFAULT_PERF_ARTIFACT_PATH,
    help=(
        "Also write a raw runtime-stats artifact for `pgrls lint --perf` "
        f"(PERF005). Bare --snapshot writes {DEFAULT_PERF_ARTIFACT_PATH}."
    ),
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(list(PERF_FORMATS), case_sensitive=False),
    default="text",
    show_default=True,
    help="Output format.",
)
def perf(
    database_url: str | None,
    config_path: str | None,
    schemas: str | None,
    min_rows: int,
    min_seq_scans: int,
    min_seq_pct: float,
    fail_on_findings: bool,
    statements: bool,
    output_path: str | None,
    snapshot_path: str | None,
    output_format: str,
) -> None:
    """Surface RLS-protected tables observed to seq-scan in production.

    PERF003 predicts a missing index *statically*; this reads what the
    database actually did. It pulls Postgres's cumulative table statistics
    (`pg_stat_user_tables`) and ranks RLS-enabled tables by rows read
    sequentially, cross-referencing each against PERF003: a table PERF003
    flagged that *also* seq-scans is a **confirmed** missing-index
    candidate; a table PERF003 thought was indexed that still seq-scans
    means the index **isn't being used** (poor selectivity, stale stats).

    Table-level counters include *every* sequential scan, not only those an
    RLS predicate drove — so this prioritises where to look. `--statements`
    narrows that down: it attributes the cost to specific queries via
    `pg_stat_statements` (when the extension is installed), listing the
    costliest statements that touch a pressured table. `--min-rows` /
    `--min-seq-scans` / `--min-seq-pct` tune the thresholds;
    `--fail-on-findings` gates CI; `--snapshot` writes the artifact for
    `pgrls lint --perf` (PERF005). Warm the planner's statistics first
    (exercise the workload, then ANALYZE).
    """
    effective = _load_effective_config(
        config_path=config_path,
        database_url=database_url,
        schemas_csv=schemas,
    )

    thresholds = PerfThresholds(
        min_live_tup=min_rows,
        min_seq_scans=min_seq_scans,
        min_seq_pct=min_seq_pct,
    )

    assert effective.database_url is not None  # guaranteed above
    stmt_rows: list[StatementStat] | None = None
    try:
        with psycopg.connect(effective.database_url) as conn:
            schema = introspect(conn, schemas=effective.schemas)
            stats = collect_table_stats(conn, effective.schemas)
            if statements:
                stmt_rows = collect_statements(conn)
    except psycopg.Error as exc:
        raise ToolError(f"Database error: {exc}") from exc
    except ValueError as exc:
        raise ToolError(str(exc)) from exc

    report = build_perf_report(
        schema,
        stats,
        statically_flagged=_perf003_flagged_tables(schema),
        thresholds=thresholds,
    )
    if statements:
        if stmt_rows is None:
            click.echo(
                "pgrls: --statements: pg_stat_statements is unavailable "
                "(extension not installed, or registered but unreadable); "
                "reporting table-level stats only.",
                err=True,
            )
        elif report.findings:
            # Only attach when there's a pressured table to attribute to —
            # with no findings the section is vacuous, and leaving
            # `statements=None` keeps every output format consistent (none
            # shows the block) rather than text alone omitting it.
            report = replace(
                report, statements=top_statements_for(report, stmt_rows)
            )

    # `--snapshot` persists the raw counters for `pgrls lint --perf`
    # (PERF005). Written before any --fail-on-findings exit so a gated run
    # still produces the artifact.
    if snapshot_path is not None:
        try:
            write_perf_artifact(
                snapshot_path, stats, generated_at=datetime.now(timezone.utc)
            )
        except OSError as exc:
            raise ToolError(
                f"Cannot write perf artifact {snapshot_path}: {exc}"
            ) from exc
        click.echo(f"pgrls: wrote runtime-stats artifact {snapshot_path}.", err=True)

    rendered = render_perf(report, output_format)
    _emit(rendered, output_path)

    if fail_on_findings and report.findings:
        n = len(report.findings)
        noun = "table" if n == 1 else "tables"
        click.echo(
            f"pgrls: {n} RLS {noun} under seq-scan pressure "
            "(--fail-on-findings).",
            err=True,
        )
        sys.exit(1)


@main.command()
@click.argument(
    "directory",
    type=click.Path(exists=True, file_okay=False, dir_okay=True),
)
@output_format_options(
    list(HISTORY_FORMATS),
    output_help=(
        "Write the trend report to this file instead of stdout (any --format)."
    ),
)
def history(
    directory: str,
    output_path: str | None,
    output_format: str,
) -> None:
    """Show the trend across a directory of `pgrls lint --format json` snapshots.

    Each `*.json` file in DIRECTORY is parsed as a lint snapshot; the
    file's mtime is its timestamp. Snapshots are ordered chronologically
    and the per-snapshot delta — which findings are NEW vs FIXED relative
    to the prior snapshot — is computed against `(rule_id, location)`
    identity. The output is a per-snapshot row table plus a summary line
    naming the net change over the full series.

    Use it to answer "are we gaining ground over time?" — pair with a
    cron job that runs `pgrls lint --format json -o snapshots/$(date
    -u +%FT%H%M%SZ).json` daily and check `pgrls history snapshots/`
    weekly. `--format json` / `markdown` emit machine-readable / paste-
    ready output (the markdown form drops cleanly into a PR or weekly
    update); `--format html` emits a standalone trend page (embedded
    CSS, no external assets) suitable for archiving as a quarterly
    review artefact or printing to PDF. `--output FILE` writes to a
    file instead of stdout.

    Files that don't parse as the pgrls JSON shape are skipped with a
    stderr warning; the report still renders for the readable ones.
    """
    try:
        snapshots = load_snapshots(Path(directory))
    except (FileNotFoundError, NotADirectoryError) as exc:
        raise ToolError(str(exc)) from exc

    rows = build_rows(snapshots)
    rendered = render_history(rows, output_format)
    _emit(rendered, output_path)
