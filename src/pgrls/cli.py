"""Click entry point for the `pgrls` console script."""
from __future__ import annotations

import click

from pgrls import __version__


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
def lint(
    database_url: str | None,
    config_path: str | None,
    schemas: str | None,
    fail_on: str | None,
) -> None:
    """Lint Postgres RLS policies for security and hygiene issues."""
    raise click.ClickException("not implemented yet")
