"""Load `pgrls.toml`, interpolate environment variables, return a typed Config."""
from __future__ import annotations

import os
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pgrls.violations import ALL_SEVERITIES, Severity, coerce_severity

_ENV_PATTERN = re.compile(r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))")

# Guard rail for the `extends` chain depth. Real chains are 1-3 deep
# (project → team → org); anything past this is a misconfiguration,
# and capping it keeps a runaway from hitting the raw recursion limit.
_MAX_EXTENDS_DEPTH = 32


class ConfigError(Exception):
    """Raised when the user's config file is invalid or references missing env vars."""


# User-facing values for `[diff].fail_on` — match the CLI's
# `pgrls diff --fail-on` choices exactly. The hyphen in
# `requires-review` is intentional (mirrors `_BUCKET_LABEL` in
# `pgrls.diff.formatters`); internal Classification values use
# underscores. Kept here as a tuple, not duplicated, so the CLI
# imports it for `click.Choice` validation.
DIFF_FAIL_ON_VALUES: tuple[str, ...] = (
    "safe",
    "breaking",
    "requires-review",
    "dangerous",
)


@dataclass(frozen=True)
class Config:
    """Loaded configuration.

    `frozen=True` prevents field reassignment but does NOT freeze the list and
    dict fields. Callers must treat `schemas`, `disable`, `rule_options`, and
    `severity_overrides` as read-only — do not mutate them in place.
    """

    database_url: str | None = None
    schemas: list[str] = field(default_factory=lambda: ["public"])
    disable: list[str] = field(default_factory=list)
    fail_on: Severity = "warning"
    rule_options: dict[str, dict[str, Any]] = field(default_factory=dict)
    # Per-rule severity overrides — `{rule_id: Severity}` parsed from
    # the `severity` key of each `[lint.rules.<ID>]` table. A rule
    # whose id is present here has every violation it emits remapped
    # to the override severity before exit-code and output handling,
    # letting an operator promote a warning to error (or demote one)
    # without disabling the rule. Empty when no override is set.
    severity_overrides: dict[str, Severity] = field(default_factory=dict)
    # `[diff].fail_on` default — the threshold below which `pgrls
    # diff` exits 0 even when changes are detected. CLI flag takes
    # precedence when supplied. Defaults to "dangerous" (only
    # security regressions block CI).
    diff_fail_on: str = "dangerous"
    # `[lint].extra_rules` — dotted Python module paths that expose
    # additional Rule-protocol objects via a `RULES` attribute.
    # See `pgrls.rules.load_extra_rules` for the loader contract
    # and `docs/RULE_AUTHORING.md` for the per-rule shape. Empty
    # list means "no extras"; built-ins always run regardless.
    extra_rules: list[str] = field(default_factory=list)


def load_config(path: Path | str | None) -> Config:
    """Load config from `path`, or `./pgrls.toml` if `path` is None and the file exists.

    Returns a default Config when no file is found.

    A config may pull in a shared base with a top-level `extends`
    (a path string, or a list of them) — see `_read_raw` for the
    merge semantics.
    """
    resolved = _resolve_path(path)
    if resolved is None:
        return Config()

    raw = _read_raw(resolved, _stack=[])
    return _build_config(raw)


def _deep_merge(
    base: dict[str, Any], override: dict[str, Any]
) -> dict[str, Any]:
    """Merge `override` onto `base`, recursing into nested tables.

    Tables (dicts) merge key-by-key, so a child can set one key of a
    `[lint.rules.SEC001]` table while inheriting the rest from the
    base. Every non-table value — scalars AND arrays — is replaced
    wholesale by the override: a child `disable`/`allowlist` list
    *replaces* the base's, it does not append. Replace-not-append is
    the predictable rule (no surprise accumulation); a child that
    wants the base's entries plus more re-lists them.
    """
    out = dict(base)
    for key, value in override.items():
        existing = out.get(key)
        if isinstance(existing, dict) and isinstance(value, dict):
            out[key] = _deep_merge(existing, value)
        else:
            out[key] = value
    return out


def _read_raw(path: Path, *, _stack: list[Path]) -> dict[str, Any]:
    """Read a TOML config, resolving any top-level `extends` chain.

    `extends` is a path (or list of paths) to base configs the current
    file layers on top of. Bases are resolved relative to the file
    that declares `extends`. For a list, later entries override
    earlier ones, and the declaring file's own keys override every
    base (`merge(merge(base1, base2), self)`).

    `_stack` holds the configs currently being resolved (an ancestry
    chain) so an `extends` cycle raises instead of recursing forever.
    It is *not* a global visited set — a base reached twice through
    different paths (a diamond) is allowed and merged each time.
    """
    resolved = path.resolve()
    if resolved in _stack:
        chain = " -> ".join(str(p) for p in [*_stack, resolved])
        raise ConfigError(f"extends cycle detected: {chain}")
    # A non-cyclic but pathologically deep chain would otherwise blow
    # the Python recursion limit with a raw traceback. Surface a clean
    # ConfigError instead — mirrors how the lint path converts a
    # too-deep policy AST's RecursionError into a tidy message. No real
    # `extends` chain is anywhere near this deep.
    if len(_stack) > _MAX_EXTENDS_DEPTH:
        raise ConfigError(
            f"extends chain too deep (more than {_MAX_EXTENDS_DEPTH} "
            f"levels) at {path} — likely a misconfiguration."
        )

    raw = _read_toml(path)
    extends = raw.pop("extends", None)
    if extends is None:
        return raw

    if isinstance(extends, str):
        bases = [extends]
    elif isinstance(extends, list) and all(
        isinstance(s, str) for s in extends
    ):
        bases = extends
    else:
        raise ConfigError(
            "`extends` must be a config path string or a list of "
            f"path strings, got {type(extends).__name__}"
        )

    merged: dict[str, Any] = {}
    for base in bases:
        base_path = Path(base)
        if not base_path.is_absolute():
            base_path = path.parent / base_path
        if not base_path.is_file():
            raise ConfigError(
                f"`extends` target not found: {base!r} "
                f"(resolved to {base_path}, referenced from {path})"
            )
        base_raw = _read_raw(base_path, _stack=[*_stack, resolved])
        merged = _deep_merge(merged, base_raw)
    # The declaring file's own keys win over every extended base.
    return _deep_merge(merged, raw)


def _resolve_path(path: Path | str | None) -> Path | None:
    if path is not None:
        p = Path(path)
        if not p.is_file():
            raise ConfigError(f"Config file not found: {p}")
        return p
    default = Path.cwd() / "pgrls.toml"
    return default if default.is_file() else None


def _read_toml(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as fh:
            return tomllib.load(fh)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"Invalid TOML in {path}: {exc}") from exc
    except OSError as exc:
        raise ConfigError(f"Cannot read config {path}: {exc}") from exc


def _build_config(raw: dict[str, Any]) -> Config:
    database = raw.get("database", {})
    if not isinstance(database, dict):
        raise ConfigError("[database] must be a table")
    lint = raw.get("lint", {})
    if not isinstance(lint, dict):
        raise ConfigError("[lint] must be a table")

    url_raw = database.get("url")
    if url_raw is None:
        database_url = None
    elif isinstance(url_raw, str):
        database_url = _interpolate_env(url_raw)
        if not database_url:
            raise ConfigError(
                "[database].url is empty after env-var interpolation. "
                "This usually means a referenced env var is set to "
                "the empty string. Set the variable to a real "
                "connection string or remove the [database].url key."
            )
    else:
        raise ConfigError(
            f"[database].url must be a string, got {type(url_raw).__name__}"
        )

    schemas = database.get("schemas", ["public"])
    if not isinstance(schemas, list) or not all(isinstance(s, str) for s in schemas):
        raise ConfigError("[database].schemas must be a list of strings")

    disable = lint.get("disable", [])
    if not isinstance(disable, list) or not all(isinstance(s, str) for s in disable):
        raise ConfigError("[lint].disable must be a list of rule-id strings")
    # Validate disable entries against the rule catalog so a typo
    # (`SEC0001`, `sec01`) surfaces as a config error instead of
    # silently leaving the rule enabled. Same UX motivation as the
    # `--rule` validation in `pgrls fix`. Lazy import — keeps
    # `load_config()` from pulling in all 15 rule modules for
    # callers that only want to read e.g. `Config.database_url`.
    from pgrls.rules import all_rules

    known_rule_ids = {rule.id for rule in all_rules()}
    # Case-normalize so `[lint].disable = ["sec001"]` matches the
    # canonical uppercase rule id; mirrors the `[lint.rules.<ID>]`
    # case treatment below.
    normalized_disable = [s.upper() for s in disable]
    unknown_disable = sorted(set(normalized_disable) - known_rule_ids)
    if unknown_disable:
        known_sorted = ", ".join(sorted(known_rule_ids))
        raise ConfigError(
            f"[lint].disable references unknown rule id(s): "
            f"{', '.join(unknown_disable)}. Known rules: {known_sorted}."
        )
    # Reject case-collisions (`["SEC001", "sec001"]`) loud, parallel
    # to the `[lint.rules.<ID>]` collision check below. Lowercased
    # comparison surfaces the original strings so the user sees both
    # sides of the duplicate in the error message.
    seen: dict[str, str] = {}
    for original, normalized in zip(disable, normalized_disable, strict=True):
        if normalized in seen and seen[normalized] != original:
            raise ConfigError(
                f"[lint].disable lists {seen[normalized]!r} and "
                f"{original!r} which both normalize to "
                f"{normalized!r} (rule ids are case-insensitive)"
            )
        seen.setdefault(normalized, original)
    # Deduplicate identical entries (`["SEC001", "SEC001"]`) — the
    # registry-side `enabled()` already deduplicates via `set()`,
    # so this is purely Config-shape hygiene.
    disable = list(dict.fromkeys(normalized_disable))

    fail_on_raw = lint.get("fail_on", "warning")
    if not isinstance(fail_on_raw, str):
        raise ConfigError(
            f"[lint].fail_on must be a string, got {type(fail_on_raw).__name__}"
        )
    # Route through `coerce_severity` so the TOML path matches the
    # CLI's case-insensitive contract (Click's `--fail-on ERROR`
    # accepts uppercase). Without this, `pgrls lint --fail-on
    # WARNING` is accepted but `[lint].fail_on = "WARNING"` in
    # the same project's pgrls.toml errors out — exactly the
    # surprise a user copy-pasting between CLI and config will
    # hit.
    try:
        fail_on: Severity = coerce_severity(fail_on_raw)
    except ValueError as exc:
        raise ConfigError(
            f"[lint].fail_on must be one of {ALL_SEVERITIES}, "
            f"got {fail_on_raw!r}"
        ) from exc

    rules_raw = lint.get("rules", {})
    if not isinstance(rules_raw, dict):
        raise ConfigError("[lint.rules] must be a table")
    rule_options: dict[str, dict[str, Any]] = {}
    severity_overrides: dict[str, Severity] = {}
    for rule_id, opts in rules_raw.items():
        if not isinstance(opts, dict):
            raise ConfigError(f"[lint.rules.{rule_id}] must be a table")
        # Case-normalize the rule id key so `[lint.rules.sec001]`
        # works the same as `[lint.rules.SEC001]`. Without this,
        # a lowercase TOML key would silently miss the lookup at
        # `config.rule_options.get(rule.id, {})` (rule.id is
        # always uppercase). Same case-insensitive contract as
        # `--fail-on`, `[lint].fail_on`, and `[diff].fail_on`.
        normalized_id = rule_id.upper()
        # Validate against the rule catalog so a typo'd section
        # (`[lint.rules.SEC0001]`) fails loud instead of silently
        # parking options the rule will never read. Mirrors the
        # `[lint].disable` validation above.
        if normalized_id not in known_rule_ids:
            known_sorted = ", ".join(sorted(known_rule_ids))
            raise ConfigError(
                f"[lint.rules.{rule_id}] references unknown rule id. "
                f"Known rules: {known_sorted}."
            )
        if normalized_id in rule_options:
            raise ConfigError(
                f"[lint.rules.{rule_id}] duplicates "
                f"[lint.rules.{normalized_id}] (rule ids are "
                "case-insensitive)"
            )
        # `severity` is a reserved key inside a `[lint.rules.<ID>]`
        # table — a meta-directive that remaps the rule's emitted
        # severity, NOT an option passed to the rule's `check()`.
        # Extract it into `severity_overrides` and keep `rule_options`
        # for genuine rule options (allowlist, auth_functions, ...).
        opts_remaining = dict(opts)
        severity_raw = opts_remaining.pop("severity", None)
        if severity_raw is not None:
            if not isinstance(severity_raw, str):
                raise ConfigError(
                    f"[lint.rules.{rule_id}].severity must be a string, "
                    f"got {type(severity_raw).__name__}"
                )
            try:
                severity_overrides[normalized_id] = coerce_severity(
                    severity_raw
                )
            except ValueError as exc:
                raise ConfigError(
                    f"[lint.rules.{rule_id}].severity must be one of "
                    f"{ALL_SEVERITIES}, got {severity_raw!r}"
                ) from exc
        rule_options[normalized_id] = opts_remaining

    # [lint].extra_rules — module dotted-paths that ship project-
    # specific rules via a `RULES` attribute. Validate the shape
    # of the field here (must be list[str]); defer the actual
    # import/discovery to `pgrls.rules.load_extra_rules` at lint
    # time (config-load shouldn't trigger arbitrary user code).
    extra_rules_raw = lint.get("extra_rules", [])
    if not isinstance(extra_rules_raw, list) or not all(
        isinstance(s, str) for s in extra_rules_raw
    ):
        raise ConfigError(
            "[lint].extra_rules must be a list of dotted Python "
            'module paths, e.g. ["mycompany.pgrls_rules"]'
        )
    extra_rules = [
        p.strip() for p in extra_rules_raw if p.strip()
    ]
    if any(not p for p in extra_rules_raw):
        raise ConfigError(
            "[lint].extra_rules entries must be non-empty strings"
        )

    diff = raw.get("diff", {})
    if not isinstance(diff, dict):
        raise ConfigError("[diff] must be a table")
    diff_fail_on_raw = diff.get("fail_on", "dangerous")
    if not isinstance(diff_fail_on_raw, str):
        raise ConfigError(
            f"[diff].fail_on must be a string, got "
            f"{type(diff_fail_on_raw).__name__}"
        )
    # Match the CLI's case-insensitive contract. `pgrls diff
    # --fail-on REQUIRES-REVIEW` works; `[diff].fail_on =
    # "REQUIRES-REVIEW"` should too.
    diff_fail_on = diff_fail_on_raw.lower()
    if diff_fail_on not in DIFF_FAIL_ON_VALUES:
        raise ConfigError(
            f"[diff].fail_on must be one of {DIFF_FAIL_ON_VALUES}, "
            f"got {diff_fail_on_raw!r}"
        )

    return Config(
        database_url=database_url,
        schemas=list(schemas),
        disable=list(disable),
        fail_on=fail_on,
        rule_options=rule_options,
        severity_overrides=severity_overrides,
        diff_fail_on=diff_fail_on,
        extra_rules=extra_rules,
    )


def _interpolate_env(value: str) -> str:
    """Replace `$VAR` and `${VAR}` with environment values.

    Missing vars raise. Use `$$` to insert a literal `$` (necessary
    when a Postgres password legitimately contains `$` next to a
    letter, e.g. `pa$$word`).
    """
    # First step: protect literal-$ escapes by substituting a
    # placeholder that the env-var pattern can't match.
    _PLACEHOLDER = "\x00DOLLAR\x00"
    value = value.replace("$$", _PLACEHOLDER)

    def replace(match: re.Match[str]) -> str:
        name = match.group(1) or match.group(2)
        if name not in os.environ:
            raise ConfigError(f"Environment variable {name!r} is not set")
        return os.environ[name]

    out = _ENV_PATTERN.sub(replace, value)
    return out.replace(_PLACEHOLDER, "$")
