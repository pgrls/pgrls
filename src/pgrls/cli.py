"""Click entry point for the `pgrls` console script."""
from __future__ import annotations

import sys
from typing import cast

import click
import psycopg

from pgrls import __version__
from pgrls.config import Config, ConfigError, load_config
from pgrls.fixers import default_fixers, generate_fixes
from pgrls.formatters import SUPPORTED_FORMATS, format_violations
from pgrls.introspect import introspect
from pgrls.model import Schema
from pgrls.rules import default_registry
from pgrls.violations import Severity, Violation, is_at_or_above


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
    type=click.Choice(["error", "warning", "info"], case_sensitive=False),
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
def lint(
    database_url: str | None,
    config_path: str | None,
    schemas: str | None,
    fail_on: str | None,
    output_format: str,
) -> None:
    """Lint Postgres RLS policies for security and hygiene issues."""
    try:
        config = load_config(config_path)
    except ConfigError as exc:
        raise click.ClickException(str(exc))

    effective = _merge_overrides(
        config,
        database_url=database_url,
        schemas_csv=schemas,
        fail_on=fail_on,
    )

    if effective.database_url is None:
        raise click.ClickException(
            "No database connection: pass --database-url or set DATABASE_URL."
        )

    try:
        with psycopg.connect(effective.database_url) as conn:
            schema = introspect(conn, schemas=effective.schemas)
    except psycopg.Error as exc:
        raise click.ClickException(f"Database error: {exc}")
    except ValueError as exc:
        raise click.ClickException(str(exc))

    try:
        violations = _run_rules(schema, config=effective)
    except (TypeError, ValueError) as exc:
        raise click.ClickException(str(exc))

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
            raise click.ClickException(
                f"--schemas {schemas_csv!r} produced an empty schema list. "
                "Check for trailing commas or whitespace-only values."
            )
    else:
        schemas = config.schemas
    effective_fail_on: Severity = (
        cast(Severity, fail_on) if fail_on is not None else config.fail_on
    )
    return Config(
        database_url=database_url or config.database_url,
        schemas=schemas,
        disable=list(config.disable),
        fail_on=effective_fail_on,
        rule_options=dict(config.rule_options),
    )


def _run_rules(schema: Schema, *, config: Config) -> list[Violation]:
    registry = default_registry()
    rules = registry.enabled(disabled_ids=config.disable)
    out: list[Violation] = []
    for rule in rules:
        out.extend(rule.check(schema, config.rule_options.get(rule.id, {})))
    return out


def _should_fail(violations: list[Violation], *, threshold: Severity) -> bool:
    return any(is_at_or_above(v.severity, threshold) for v in violations)


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

    Currently fixes SEC002 (`ALTER TABLE … FORCE ROW LEVEL
    SECURITY`) and PERF001 (wrap unwrapped auth calls in
    `(SELECT …)` and emit `ALTER POLICY`). Other rules require
    human intent (which role to grant to, what column to scope
    by) and are not auto-fixed.

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
        raise click.ClickException(str(exc))

    # Validate `--rule` early — a typo silently producing zero
    # fixes is hard to debug. The "no auto-fixable" message
    # should be reserved for "DB is clean", not "you spelled the
    # rule wrong."
    auto_fixable = {fixer.rule_id for fixer in default_fixers()}
    if rules:
        unknown = sorted(set(rules) - auto_fixable)
        if unknown:
            raise click.ClickException(
                f"unknown auto-fixable rule(s): {', '.join(unknown)}. "
                f"Available: {', '.join(sorted(auto_fixable))}."
            )

    effective = _merge_overrides(
        config,
        database_url=database_url,
        schemas_csv=schemas,
        fail_on=None,
    )

    if effective.database_url is None:
        raise click.ClickException(
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
                raise click.ClickException(str(exc))

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
                            # exception. Tell the user which fix
                            # broke so they can investigate
                            # without re-running the lint.
                            conn.rollback()
                            raise click.ClickException(
                                f"fix {i}/{len(fixes)} failed "
                                f"({f.rule_id} on {f.location}): "
                                f"{exc}. No fixes were applied."
                            )
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
        raise click.ClickException(f"Database error: {exc}")
    except ValueError as exc:
        raise click.ClickException(str(exc))
