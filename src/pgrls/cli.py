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

import sys

import click
import psycopg

from pgrls import __version__
from pgrls.config import Config, ConfigError, load_config
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
    )


def _run_rules(schema: Schema, *, config: Config) -> list[Violation]:
    registry = default_registry()
    rules = registry.enabled(disabled_ids=config.disable)
    out: list[Violation] = []
    for rule in rules:
        try:
            out.extend(
                rule.check(schema, config.rule_options.get(rule.id, {}))
            )
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
    return out


def _should_fail(violations: list[Violation], *, threshold: Severity) -> bool:
    return any(is_at_or_above(v.severity, threshold) for v in violations)


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
        raise ToolError(str(exc)) from exc

    # Validate `--rule` early — a typo silently producing zero
    # fixes is hard to debug. The "no auto-fixable" message
    # should be reserved for "DB is clean", not "you spelled the
    # rule wrong."
    auto_fixable = {fixer.rule_id for fixer in default_fixers()}
    if rules:
        unknown = sorted(set(rules) - auto_fixable)
        if unknown:
            raise ToolError(
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
        raise ToolError(f"Database error: {exc}") from exc
    except ValueError as exc:
        raise ToolError(str(exc)) from exc
