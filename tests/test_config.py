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


def test_fail_on_normalizes_case(tmp_path: Path) -> None:
    # Click's `--fail-on ERROR` is accepted via case_sensitive=False;
    # the TOML path should match the same contract. Without the
    # `coerce_severity` route, a user copy-pasting `--fail-on
    # WARNING` into `[lint].fail_on = "WARNING"` would hit a
    # surprise ConfigError.
    cfg_file = tmp_path / "pgrls.toml"
    cfg_file.write_text('[lint]\nfail_on = "ERROR"\n')
    cfg = load_config(path=cfg_file)
    assert cfg.fail_on == "error"


def test_fail_on_rejects_non_string(tmp_path: Path) -> None:
    cfg_file = tmp_path / "pgrls.toml"
    cfg_file.write_text("[lint]\nfail_on = 1\n")
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


def test_disable_must_be_a_list(tmp_path: Path) -> None:
    cfg_file = tmp_path / "pgrls.toml"
    cfg_file.write_text('[lint]\ndisable = "SEC001"\n')
    with pytest.raises(ConfigError, match="disable"):
        load_config(path=cfg_file)


def test_disable_items_must_be_strings(tmp_path: Path) -> None:
    cfg_file = tmp_path / "pgrls.toml"
    cfg_file.write_text("[lint]\ndisable = [42]\n")
    with pytest.raises(ConfigError, match="disable"):
        load_config(path=cfg_file)


def test_schemas_must_be_a_list(tmp_path: Path) -> None:
    cfg_file = tmp_path / "pgrls.toml"
    cfg_file.write_text('[database]\nschemas = "public"\n')
    with pytest.raises(ConfigError, match="schemas"):
        load_config(path=cfg_file)


def test_schemas_items_must_be_strings(tmp_path: Path) -> None:
    cfg_file = tmp_path / "pgrls.toml"
    cfg_file.write_text("[database]\nschemas = [42]\n")
    with pytest.raises(ConfigError, match="schemas"):
        load_config(path=cfg_file)


def test_lint_section_must_be_a_table(tmp_path: Path) -> None:
    cfg_file = tmp_path / "pgrls.toml"
    cfg_file.write_text('lint = "not-a-table"\n')
    with pytest.raises(ConfigError, match=r"\[lint\]"):
        load_config(path=cfg_file)


def test_lint_rules_section_must_be_a_table(tmp_path: Path) -> None:
    cfg_file = tmp_path / "pgrls.toml"
    cfg_file.write_text('[lint]\nrules = "nope"\n')
    with pytest.raises(ConfigError, match=r"\[lint\.rules\]"):
        load_config(path=cfg_file)


def test_per_rule_options_must_be_a_table(tmp_path: Path) -> None:
    cfg_file = tmp_path / "pgrls.toml"
    cfg_file.write_text(
        """
[lint.rules]
SEC001 = "not-a-table"
"""
    )
    with pytest.raises(ConfigError, match=r"\[lint\.rules\.SEC001\]"):
        load_config(path=cfg_file)


def test_invalid_toml_syntax_raises_config_error(tmp_path: Path) -> None:
    cfg_file = tmp_path / "pgrls.toml"
    cfg_file.write_text("[unclosed section\n")
    with pytest.raises(ConfigError, match="Invalid TOML"):
        load_config(path=cfg_file)


def test_empty_toml_yields_defaults(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DATABASE_URL", raising=False)
    cfg_file = tmp_path / "pgrls.toml"
    cfg_file.write_text("")
    cfg = load_config(path=cfg_file)
    assert cfg.database_url is None
    assert cfg.schemas == ["public"]
    assert cfg.disable == []
    assert cfg.fail_on == "warning"
    assert cfg.rule_options == {}


def test_unknown_top_level_keys_silently_ignored(tmp_path: Path) -> None:
    # Unknown sections must not error — config is forward-compatible.
    cfg_file = tmp_path / "pgrls.toml"
    cfg_file.write_text(
        """
[database]
url = "postgres://localhost/x"

[future_feature]
something = "ignored"
"""
    )
    cfg = load_config(path=cfg_file)
    assert cfg.database_url == "postgres://localhost/x"


def test_rule_options_passed_through_unmodified(tmp_path: Path) -> None:
    cfg_file = tmp_path / "pgrls.toml"
    cfg_file.write_text(
        """
[lint.rules.SEC004]
auth_functions = ["auth.uid", "my.custom"]

[lint.rules.SEC001]
allowlist = ["countries", "currencies"]
"""
    )
    cfg = load_config(path=cfg_file)
    assert cfg.rule_options["SEC004"] == {
        "auth_functions": ["auth.uid", "my.custom"]
    }
    assert cfg.rule_options["SEC001"] == {
        "allowlist": ["countries", "currencies"]
    }


def test_env_interpolation_with_multiple_vars_in_one_string(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PG_USER", "alice")
    monkeypatch.setenv("PG_HOST", "db.local")
    cfg_file = tmp_path / "pgrls.toml"
    cfg_file.write_text(
        '[database]\nurl = "postgres://${PG_USER}@${PG_HOST}/db"\n'
    )
    cfg = load_config(path=cfg_file)
    assert cfg.database_url == "postgres://alice@db.local/db"


def test_invalid_fail_on_error_mentions_valid_choices(
    tmp_path: Path,
) -> None:
    cfg_file = tmp_path / "pgrls.toml"
    cfg_file.write_text('[lint]\nfail_on = "fatal"\n')
    with pytest.raises(ConfigError) as exc_info:
        load_config(path=cfg_file)
    msg = str(exc_info.value)
    # The error must surface the valid options so the user can act on it.
    assert "error" in msg
    assert "warning" in msg
    assert "info" in msg


def test_dollar_dollar_escapes_to_literal_dollar(monkeypatch) -> None:
    # A Postgres password like `pa$$word` contains a literal `$`
    # next to a letter — pgrls must not treat that as `${VAR}`.
    # `$$` escapes to a single `$`.
    from pgrls.config import _interpolate_env
    out = _interpolate_env("postgres://user:pa$$word@host/db")
    assert out == "postgres://user:pa$word@host/db"


def test_dollar_dollar_escape_does_not_interfere_with_real_var(
    monkeypatch,
) -> None:
    from pgrls.config import _interpolate_env
    monkeypatch.setenv("PGUSER", "alice")
    out = _interpolate_env("$PGUSER says $$$$")
    # Two `$$` pairs → two literal dollars after the env-resolved name.
    assert out == "alice says $$"


def test_empty_env_var_value_raises_clear_error(
    monkeypatch, tmp_path,
) -> None:
    from pgrls.config import ConfigError, load_config
    monkeypatch.setenv("EMPTY_DB", "")
    cfg = tmp_path / "pgrls.toml"
    cfg.write_text('[database]\nurl = "${EMPTY_DB}"\n')
    import pytest
    with pytest.raises(ConfigError, match="empty after env-var interpolation"):
        load_config(cfg)
