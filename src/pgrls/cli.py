"""Click entry point for the `pgrls` console script."""
from __future__ import annotations

import sys
from typing import cast

import click
import psycopg

from pgrls import __version__
from pgrls.config import Config, ConfigError, load_config
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
# When --config is omitted, load_config() in Task 3 auto-discovers ./pgrls.toml.
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

    violations = _run_rules(schema, config=effective)

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
