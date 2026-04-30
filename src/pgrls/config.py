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
    dict fields. Callers must treat `schemas`, `disable`, and `rule_options` as
    read-only — do not mutate them in place.
    """

    database_url: str | None = None
    schemas: list[str] = field(default_factory=lambda: ["public"])
    disable: list[str] = field(default_factory=list)
    fail_on: Severity = "warning"
    rule_options: dict[str, dict[str, Any]] = field(default_factory=dict)
    # `[diff].fail_on` default — the threshold below which `pgrls
    # diff` exits 0 even when changes are detected. CLI flag takes
    # precedence when supplied. Defaults to "dangerous" (only
    # security regressions block CI).
    diff_fail_on: str = "dangerous"


def load_config(path: Path | str | None) -> Config:
    """Load config from `path`, or `./pgrls.toml` if `path` is None and the file exists.

    Returns a default Config when no file is found.
    """
    resolved = _resolve_path(path)
    if resolved is None:
        return Config()

    raw = _read_toml(resolved)
    return _build_config(raw)


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
    for rule_id, opts in rules_raw.items():
        if not isinstance(opts, dict):
            raise ConfigError(f"[lint.rules.{rule_id}] must be a table")
        rule_options[rule_id] = dict(opts)

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
        diff_fail_on=diff_fail_on,
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
