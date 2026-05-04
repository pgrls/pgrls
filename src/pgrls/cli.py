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
import sys
from collections.abc import Callable
from pathlib import Path

import click
import psycopg

from pgrls import __version__
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
        diff_fail_on=config.diff_fail_on,
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
def diff(
    base: str,
    head: str | None,
    database_url: str | None,
    fail_on: str | None,
    output_format: str,
    config_path: str | None,
    schemas: str | None,
) -> None:
    """Diff two RLS schema snapshots — report semantic changes with classification."""
    try:
        config = load_config(config_path)
    except ConfigError as exc:
        raise ToolError(str(exc)) from exc

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
    # All three are documented in CHANGELOG.md and AGENTS.md;
    # the implementation here was previously honoring only #3,
    # which broke the common "DATABASE_URL is set, no toml file
    # exists" CI workflow.
    if head is None:
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
    head_is_url = _is_db_url(head)
    if schemas and not (base_is_url or head_is_url):
        click.echo(
            "pgrls: warning: --schemas is ignored when both <base> and "
            "<head> are snapshot files (filters apply only to live DB "
            "introspection). Snapshots are already filtered at "
            "`pgrls snapshot` capture time.",
            err=True,
        )

    base_schema = _resolve_diff_source(base, schemas=schema_list)
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
