"""Load `pgrls.toml`, interpolate environment variables, return a typed Config."""
from __future__ import annotations

import os
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

Severity = Literal["error", "warning", "info"]
_VALID_FAIL_ON: tuple[Severity, ...] = ("error", "warning", "info")
_ENV_PATTERN = re.compile(r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))")


class ConfigError(Exception):
    """Raised when the user's config file is invalid or references missing env vars."""


@dataclass(frozen=True)
class Config:
    database_url: str | None = None
    schemas: list[str] = field(default_factory=lambda: ["public"])
    disable: list[str] = field(default_factory=list)
    fail_on: Severity = "warning"
    rule_options: dict[str, dict[str, Any]] = field(default_factory=dict)


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


def _build_config(raw: dict[str, Any]) -> Config:
    database = raw.get("database", {})
    lint = raw.get("lint", {})

    url_raw = database.get("url")
    database_url = _interpolate_env(url_raw) if isinstance(url_raw, str) else None

    schemas = database.get("schemas", ["public"])
    if not isinstance(schemas, list) or not all(isinstance(s, str) for s in schemas):
        raise ConfigError("[database].schemas must be a list of strings")

    disable = lint.get("disable", [])
    if not isinstance(disable, list) or not all(isinstance(s, str) for s in disable):
        raise ConfigError("[lint].disable must be a list of rule-id strings")

    fail_on = lint.get("fail_on", "warning")
    if fail_on not in _VALID_FAIL_ON:
        raise ConfigError(
            f"[lint].fail_on must be one of {_VALID_FAIL_ON}, got {fail_on!r}"
        )

    rule_options: dict[str, dict[str, Any]] = {}
    for rule_id, opts in lint.get("rules", {}).items():
        if not isinstance(opts, dict):
            raise ConfigError(f"[lint.rules.{rule_id}] must be a table")
        rule_options[rule_id] = dict(opts)

    return Config(
        database_url=database_url,
        schemas=list(schemas),
        disable=list(disable),
        fail_on=fail_on,
        rule_options=rule_options,
    )


def _interpolate_env(value: str) -> str:
    """Replace `$VAR` and `${VAR}` with environment values. Missing vars raise."""

    def replace(match: re.Match[str]) -> str:
        name = match.group(1) or match.group(2)
        if name not in os.environ:
            raise ConfigError(f"Environment variable {name!r} is not set")
        return os.environ[name]

    return _ENV_PATTERN.sub(replace, value)
