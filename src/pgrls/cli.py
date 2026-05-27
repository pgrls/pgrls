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
    stale_keys,
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
    format_diff_html,
    format_diff_json,
    format_diff_markdown,
    format_diff_sarif,
    format_diff_text,
)
from pgrls.fixers import (
    default_fixers,
    generate_fixes,
    render_fixes,
    render_migration,
)
from pgrls.formatters import SUPPORTED_FORMATS, format_violations
from pgrls.history import (
    HISTORY_FORMATS,
    build_rows,
    load_snapshots,
)
from pgrls.history import render as render_history
from pgrls.introspect import introspect
from pgrls.model import Schema
from pgrls.report import REPORT_FORMATS, build_report
from pgrls.report import render as render_report
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
    rules: tuple[str, ...],
    exclude_rules: tuple[str, ...],
    min_severity: str | None,
    output_path: str | None,
    explain: bool,
    update_baseline: bool,
    fail_on: str | None,
    output_format: str,
    baseline_path: Path | None,
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
    try:
        config = load_config(config_path)
    except ConfigError as exc:
        raise ToolError(str(exc)) from exc

    known = {r.id for r in _runtime_rules(config)}

    # Validate `--rule` early — a typo silently producing zero
    # findings is hard to debug. Mirrors `pgrls fix --rule`.
    if rules:
        normalized_rules = {r.upper() for r in rules}
        unknown = sorted(normalized_rules - known)
        if unknown:
            raise ToolError(
                f"unknown rule(s): {', '.join(unknown)}. "
                f"Available: {', '.join(sorted(known))}."
            )
        rules = tuple(sorted(normalized_rules))

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
        violations = _run_rules(
            schema,
            config=effective,
            rule_filter=set(rules) if rules else None,
            exclude_filter=exclude_ids or None,
        )
    except (TypeError, ValueError, RuntimeError) as exc:
        raise ToolError(str(exc)) from exc

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

    report = format_violations(
        displayed,
        format=output_format,
        rationale_map=rationale_map,
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
    database_url: str | None,
    config_path: str | None,
    schemas: str | None,
    rules: tuple[str, ...],
    apply: bool,
    output_path: str | None,
    check: bool,
) -> None:
    """Auto-remediate violations whose fix is mechanical.

    Currently fixes SEC001 (`ALTER TABLE … ENABLE ROW LEVEL
    SECURITY`), SEC002 (`ALTER TABLE … FORCE ROW LEVEL
    SECURITY`), SEC006 (`ALTER POLICY … WITH CHECK` mirroring
    USING), SEC011 (`ALTER POLICY … USING/WITH CHECK` stripping
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
    ENABLE ROW LEVEL SECURITY` for a dormant-policies table),
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
    produces a byte-identical result. `--output` cannot be
    combined with `--apply`: one writes a migration to run later,
    the other executes immediately.

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

            # `--check` is a CI gate — list the offending
            # (rule, location) pairs and exit 1 without emitting
            # SQL. The actionable next step is named so a
            # pre-commit-style hook output is self-documenting.
            #
            # Output split: the violation listing goes to *stdout*
            # so `pgrls fix --check > violations.log` captures it
            # for CI artefacts; the summary and next-step hint go
            # to stderr so they don't pollute parseable output.
            # Matches `pgrls lint` (findings on stdout, status on
            # stderr) and `ruff --check`.
            if check:
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

            # `--output` writes the migration file and stops here.
            # `--apply` is already rejected alongside `--output`, so
            # reaching this branch means a pure dry-run-to-file.
            if output_path is not None:
                migration = render_migration(
                    fixes, tool_version=__version__
                )
                try:
                    Path(output_path).write_text(
                        migration, encoding="utf-8"
                    )
                except OSError as exc:
                    raise ToolError(
                        f"cannot write fixes to {output_path}: {exc}"
                    ) from exc
                click.echo(
                    f"pgrls: wrote {len(fixes)} "
                    f"fix{'es' if len(fixes) != 1 else ''} to "
                    f"{output_path}.",
                    err=True,
                )
                return

            # Otherwise the SQL bodies + their `-- [rule]
            # description` comments go to stdout so `pgrls fix >
            # migration.sql` still produces a clean, paste-able
            # script.
            click.echo(render_fixes(fixes))

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


# The starter config `pgrls init` writes. Every active key is a no-op
# default (so the file parses and `pgrls lint` runs unchanged); the
# illustrative knobs — connection string, disable list, per-rule
# allowlist / severity override — are commented examples. `[database].url`
# is deliberately left commented so a fresh file doesn't fail with an
# env-var error before the user has wired up DATABASE_URL.
_INIT_TEMPLATE = """\
#:schema https://raw.githubusercontent.com/pgrls/pgrls/main/pgrls.schema.json
# pgrls configuration. Rule reference:
# https://github.com/pgrls/pgrls/blob/main/AGENTS.md
# Every key is optional; this file documents the common knobs.

[database]
# Connection string. Prefer leaving this unset and passing
# --database-url (or $DATABASE_URL) at runtime so secrets stay out of
# version control. When set, $VAR / ${VAR} are interpolated from the
# environment, e.g. url = "$DATABASE_URL".
# url = "postgres://user:pass@localhost:5432/app"

# Schemas to lint. Defaults to ["public"].
schemas = ["public"]

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
"""


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
    "--force",
    is_flag=True,
    help="Overwrite the file if it already exists.",
)
def init(output_path: str, force: bool) -> None:
    """Write a starter pgrls.toml with the common options documented.

    The generated file parses as-is and leaves every rule at its
    default — `pgrls lint` runs unchanged against it. Connection
    string, disable list, and per-rule allowlist / severity overrides
    are included as commented examples to edit. Refuses to clobber an
    existing file unless `--force` is given.
    """
    path = Path(output_path)
    if path.exists() and not force:
        raise ToolError(
            f"{path} already exists. Pass --force to overwrite it."
        )
    try:
        path.write_text(_INIT_TEMPLATE, encoding="utf-8")
    except OSError as exc:
        raise ToolError(f"Cannot write {path}: {exc}") from exc
    click.echo(
        f"Wrote {path}. Set [database].url (or pass --database-url / "
        "$DATABASE_URL), then run `pgrls lint`."
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
    type=click.Choice(["text", "markdown", "json", "html"]),
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
@click.option(
    "--database-url",
    envvar="DATABASE_URL",
    default=None,
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
    help="Comma-separated schemas to report on (overrides config).",
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
    "--format",
    "output_format",
    type=click.Choice(list(REPORT_FORMATS), case_sensitive=False),
    default="text",
    show_default=True,
    help="Output format.",
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

    rendered = render_report(build_report(schema), output_format)
    # Normalize a single trailing newline so file and stdout output are
    # byte-identical (text/json renderers don't add one; markdown does).
    if not rendered.endswith("\n"):
        rendered += "\n"
    if output_path is not None:
        # `newline=""` disables universal-newline translation so the
        # file matches stdout byte-for-byte (no `\n`→`\r\n` on Windows).
        try:
            Path(output_path).write_text(
                rendered, encoding="utf-8", newline=""
            )
        except OSError as exc:
            raise ToolError(f"Cannot write {output_path}: {exc}") from exc
    else:
        click.echo(rendered, nl=False)


@main.command()
@click.argument(
    "directory",
    type=click.Path(exists=True, file_okay=False, dir_okay=True),
)
@click.option(
    "--output",
    "-o",
    "output_path",
    type=click.Path(dir_okay=False),
    default=None,
    help="Write the trend report to this file instead of stdout (any --format).",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(list(HISTORY_FORMATS), case_sensitive=False),
    default="text",
    show_default=True,
    help="Output format.",
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
    rendered = render_history(rows, output_format)  # type: ignore[arg-type]
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
