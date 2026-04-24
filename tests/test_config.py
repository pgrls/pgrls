from __future__ import annotations

from pathlib import Path

import pytest

from pgrls.config import Config, ConfigError, load_config


def test_default_config_when_no_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    cfg = load_config(path=None)
    assert isinstance(cfg, Config)
    assert cfg.database_url is None
    assert cfg.schemas == ["public"]
    assert cfg.disable == []
    assert cfg.fail_on == "warning"
    assert cfg.rule_options == {}


def test_loads_explicit_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DATABASE_URL", raising=False)
    cfg_file = tmp_path / "pgrls.toml"
    cfg_file.write_text(
        """
[database]
url = "postgres://localhost/test"
schemas = ["public", "tenant"]

[lint]
disable = ["PERF001"]
fail_on = "error"

[lint.rules.SEC001]
allowlist = ["countries"]
"""
    )
    cfg = load_config(path=cfg_file)
    assert cfg.database_url == "postgres://localhost/test"
    assert cfg.schemas == ["public", "tenant"]
    assert cfg.disable == ["PERF001"]
    assert cfg.fail_on == "error"
    assert cfg.rule_options["SEC001"] == {"allowlist": ["countries"]}


def test_env_interpolation_dollar_var(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DATABASE_URL", "postgres://from-env/db")
    cfg_file = tmp_path / "pgrls.toml"
    cfg_file.write_text('[database]\nurl = "$DATABASE_URL"\n')
    cfg = load_config(path=cfg_file)
    assert cfg.database_url == "postgres://from-env/db"


def test_env_interpolation_braces(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MY_DB", "postgres://from-env/db2")
    cfg_file = tmp_path / "pgrls.toml"
    cfg_file.write_text('[database]\nurl = "${MY_DB}"\n')
    cfg = load_config(path=cfg_file)
    assert cfg.database_url == "postgres://from-env/db2"


def test_env_interpolation_missing_var_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MISSING_VAR", raising=False)
    cfg_file = tmp_path / "pgrls.toml"
    cfg_file.write_text('[database]\nurl = "${MISSING_VAR}"\n')
    with pytest.raises(ConfigError, match="MISSING_VAR"):
        load_config(path=cfg_file)


def test_invalid_fail_on_raises(tmp_path: Path) -> None:
    cfg_file = tmp_path / "pgrls.toml"
    cfg_file.write_text('[lint]\nfail_on = "nope"\n')
    with pytest.raises(ConfigError, match="fail_on"):
        load_config(path=cfg_file)


def test_auto_discovers_pgrls_toml_in_cwd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "pgrls.toml").write_text('[database]\nurl = "postgres://auto/db"\n')
    cfg = load_config(path=None)
    assert cfg.database_url == "postgres://auto/db"


def test_explicit_path_does_not_exist_raises(tmp_path: Path) -> None:
    missing = tmp_path / "does_not_exist.toml"
    with pytest.raises(ConfigError, match="not found"):
        load_config(path=missing)


def test_database_section_must_be_a_table(tmp_path: Path) -> None:
    cfg_file = tmp_path / "pgrls.toml"
    cfg_file.write_text('database = "not-a-table"\n')
    with pytest.raises(ConfigError, match=r"\[database\]"):
        load_config(path=cfg_file)


def test_url_must_be_a_string(tmp_path: Path) -> None:
    cfg_file = tmp_path / "pgrls.toml"
    cfg_file.write_text("[database]\nurl = 42\n")
    with pytest.raises(ConfigError, match="url"):
        load_config(path=cfg_file)


def test_env_interpolation_does_not_apply_to_disable_list(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SHOULD_NOT_EXPAND", "expanded-value")
    cfg_file = tmp_path / "pgrls.toml"
    cfg_file.write_text(
        """
[lint]
disable = ["$SHOULD_NOT_EXPAND"]
"""
    )
    cfg = load_config(path=cfg_file)
    assert cfg.disable == ["$SHOULD_NOT_EXPAND"]
