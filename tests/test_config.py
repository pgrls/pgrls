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
    # Env interpolation runs on `[database].url` only, not on the
    # disable list. The validator therefore sees the literal
    # `$SHOULD_NOT_EXPAND` (not the env value) — confirming this
    # by asserting the rule-id-validation error reports the literal
    # token, never the expanded value.
    monkeypatch.setenv("SHOULD_NOT_EXPAND", "expanded-value")
    cfg_file = tmp_path / "pgrls.toml"
    cfg_file.write_text(
        """
[lint]
disable = ["$SHOULD_NOT_EXPAND"]
"""
    )
    with pytest.raises(ConfigError) as excinfo:
        load_config(path=cfg_file)
    assert "$SHOULD_NOT_EXPAND" in str(excinfo.value)
    assert "expanded-value" not in str(excinfo.value)


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


def test_disable_rejects_unknown_rule_id(tmp_path: Path) -> None:
    # A typo in `[lint].disable` should fail loud, not silently
    # leave the rule enabled. The error mentions both the unknown
    # token and the catalog so the user can spot the typo.
    cfg_file = tmp_path / "pgrls.toml"
    cfg_file.write_text('[lint]\ndisable = ["SEC0001"]\n')
    with pytest.raises(ConfigError) as excinfo:
        load_config(path=cfg_file)
    msg = str(excinfo.value)
    assert "SEC0001" in msg
    assert "SEC001" in msg


def test_disable_normalizes_rule_id_case(tmp_path: Path) -> None:
    # `[lint].disable = ["sec001"]` is the same as ["SEC001"] —
    # mirrors the case-insensitive contract on `--fail-on`,
    # `[lint].fail_on`, `[diff].fail_on`, and `[lint.rules.<ID>]`.
    cfg_file = tmp_path / "pgrls.toml"
    cfg_file.write_text('[lint]\ndisable = ["sec001", "Hyg002"]\n')
    cfg = load_config(path=cfg_file)
    assert cfg.disable == ["SEC001", "HYG002"]


def test_disable_rejects_case_collision(tmp_path: Path) -> None:
    # Two entries that differ only in case both normalize to
    # SEC001 — surface as a config error, parallel to the
    # `[lint.rules.<ID>]` collision check.
    cfg_file = tmp_path / "pgrls.toml"
    cfg_file.write_text('[lint]\ndisable = ["SEC001", "sec001"]\n')
    with pytest.raises(ConfigError, match="case-insensitive"):
        load_config(path=cfg_file)


def test_disable_dedupes_identical_entries(tmp_path: Path) -> None:
    # `["SEC001", "SEC001"]` is harmless (same id twice) — keep
    # the first, drop the second so the resulting Config is clean.
    cfg_file = tmp_path / "pgrls.toml"
    cfg_file.write_text('[lint]\ndisable = ["SEC001", "SEC001"]\n')
    cfg = load_config(path=cfg_file)
    assert cfg.disable == ["SEC001"]


def test_disable_accepts_full_rule_catalog(tmp_path: Path) -> None:
    # Disabling every shipping rule simultaneously is a degenerate
    # but valid config — pins that the validator's known-id set is
    # derived from the same `all_rules()` source as the runtime
    # registry. A drift between the two (e.g. validator hand-codes
    # rule ids that fall behind a new SEC012) would surface here.
    from pgrls.rules import all_rules

    catalog = sorted(rule.id for rule in all_rules())
    cfg_file = tmp_path / "pgrls.toml"
    quoted = ", ".join(f'"{rid}"' for rid in catalog)
    cfg_file.write_text(f"[lint]\ndisable = [{quoted}]\n")
    cfg = load_config(path=cfg_file)
    assert sorted(cfg.disable) == catalog


def test_rule_options_normalizes_section_id_case(tmp_path: Path) -> None:
    # `[lint.rules.sec004]` should reach SEC004's check via the
    # canonical uppercase rule id.
    cfg_file = tmp_path / "pgrls.toml"
    cfg_file.write_text(
        """
[lint.rules.sec004]
auth_functions = ["auth.custom"]
"""
    )
    cfg = load_config(path=cfg_file)
    assert cfg.rule_options == {
        "SEC004": {"auth_functions": ["auth.custom"]}
    }


def test_rule_options_rejects_unknown_rule_id(tmp_path: Path) -> None:
    # `[lint.rules.SEC0001]` is shape-valid (table-of-table) but
    # references a nonexistent rule. Without validation, the
    # options would be silently parked and the user would think
    # they'd configured an allowlist that the rule never sees.
    # Mirror the `[lint].disable` validation hint with the catalog.
    cfg_file = tmp_path / "pgrls.toml"
    cfg_file.write_text(
        '[lint.rules.SEC0001]\nallowlist = ["countries"]\n'
    )
    with pytest.raises(ConfigError) as excinfo:
        load_config(path=cfg_file)
    msg = str(excinfo.value)
    assert "SEC0001" in msg
    assert "SEC001" in msg


def test_rule_options_rejects_case_collision(tmp_path: Path) -> None:
    # Two TOML sections that differ only in case both normalize to
    # the same id — should fail loud rather than silently keep one.
    cfg_file = tmp_path / "pgrls.toml"
    cfg_file.write_text(
        """
[lint.rules.SEC001]
allowlist = ["countries"]

[lint.rules.sec001]
allowlist = ["currencies"]
"""
    )
    with pytest.raises(ConfigError, match="case-insensitive"):
        load_config(path=cfg_file)


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


# ---------------------------------------------------------------------------
# [diff] section (v0.2.1+)
# ---------------------------------------------------------------------------


def test_diff_fail_on_default_when_section_absent(tmp_path: Path) -> None:
    # No `[diff]` section at all → `diff_fail_on` falls back to the
    # built-in "dangerous" default.
    cfg = tmp_path / "pgrls.toml"
    cfg.write_text('[database]\nurl = "postgres://x/"\n')
    config = load_config(cfg)
    assert config.diff_fail_on == "dangerous"


def test_diff_fail_on_reads_from_section(tmp_path: Path) -> None:
    cfg = tmp_path / "pgrls.toml"
    cfg.write_text(
        '[database]\nurl = "postgres://x/"\n'
        '[diff]\nfail_on = "requires-review"\n'
    )
    config = load_config(cfg)
    assert config.diff_fail_on == "requires-review"


def test_diff_fail_on_normalizes_case(tmp_path: Path) -> None:
    # `[diff].fail_on = "BREAKING"` should match the CLI's
    # case-insensitive `--fail-on BREAKING`. Lower-case before
    # the membership check.
    cfg = tmp_path / "pgrls.toml"
    cfg.write_text(
        '[database]\nurl = "postgres://x/"\n'
        '[diff]\nfail_on = "BREAKING"\n'
    )
    config = load_config(cfg)
    assert config.diff_fail_on == "breaking"


def test_diff_fail_on_invalid_value_raises(tmp_path: Path) -> None:
    import pytest

    from pgrls.config import ConfigError

    cfg = tmp_path / "pgrls.toml"
    cfg.write_text(
        '[database]\nurl = "postgres://x/"\n'
        '[diff]\nfail_on = "super-extra-dangerous"\n'
    )
    with pytest.raises(ConfigError, match=r"\[diff\]\.fail_on"):
        load_config(cfg)


def test_diff_section_must_be_a_table(tmp_path: Path) -> None:
    import pytest

    from pgrls.config import ConfigError

    # `diff = "..."` MUST go before any `[...]` header so TOML
    # parses it as a top-level scalar (root.diff), not as a
    # key inside the prior section. With it at the top, raw["diff"]
    # is the string "not-a-table" and the isinstance(dict) check
    # in _build_config rejects it.
    cfg = tmp_path / "pgrls.toml"
    cfg.write_text(
        'diff = "not-a-table"\n'
        '[database]\nurl = "postgres://x/"\n'
    )
    with pytest.raises(ConfigError, match=r"\[diff\] must be a table"):
        load_config(cfg)


# --- per-rule severity override ------------------------------------------


def test_severity_override_is_parsed(tmp_path: Path) -> None:
    cfg_file = tmp_path / "pgrls.toml"
    cfg_file.write_text('[lint.rules.SEC005]\nseverity = "error"\n')
    cfg = load_config(path=cfg_file)
    assert cfg.severity_overrides == {"SEC005": "error"}


def test_severity_override_default_is_empty(tmp_path: Path) -> None:
    cfg_file = tmp_path / "pgrls.toml"
    cfg_file.write_text('[lint.rules.SEC005]\nallowlist = ["public.t.p"]\n')
    cfg = load_config(path=cfg_file)
    assert cfg.severity_overrides == {}


def test_severity_override_is_extracted_from_rule_options(
    tmp_path: Path,
) -> None:
    # `severity` is a meta-directive, not an option passed to the
    # rule's check() — it must NOT leak into rule_options alongside
    # the genuine options.
    cfg_file = tmp_path / "pgrls.toml"
    cfg_file.write_text(
        "[lint.rules.SEC005]\n"
        'severity = "error"\n'
        'allowlist = ["public.t.p"]\n'
    )
    cfg = load_config(path=cfg_file)
    assert cfg.severity_overrides == {"SEC005": "error"}
    assert cfg.rule_options == {"SEC005": {"allowlist": ["public.t.p"]}}


def test_severity_override_is_case_insensitive_in_value(
    tmp_path: Path,
) -> None:
    # Mirrors the `--fail-on ERROR` / `[lint].fail_on` contract.
    cfg_file = tmp_path / "pgrls.toml"
    cfg_file.write_text('[lint.rules.SEC005]\nseverity = "ERROR"\n')
    cfg = load_config(path=cfg_file)
    assert cfg.severity_overrides == {"SEC005": "error"}


def test_severity_override_normalizes_rule_id_case(tmp_path: Path) -> None:
    cfg_file = tmp_path / "pgrls.toml"
    cfg_file.write_text('[lint.rules.sec005]\nseverity = "info"\n')
    cfg = load_config(path=cfg_file)
    assert cfg.severity_overrides == {"SEC005": "info"}


def test_severity_override_rejects_invalid_value(tmp_path: Path) -> None:
    cfg_file = tmp_path / "pgrls.toml"
    cfg_file.write_text('[lint.rules.SEC005]\nseverity = "critical"\n')
    with pytest.raises(ConfigError, match="severity") as excinfo:
        load_config(path=cfg_file)
    assert "critical" in str(excinfo.value)


def test_severity_override_rejects_non_string(tmp_path: Path) -> None:
    cfg_file = tmp_path / "pgrls.toml"
    cfg_file.write_text("[lint.rules.SEC005]\nseverity = 3\n")
    with pytest.raises(ConfigError, match="severity"):
        load_config(path=cfg_file)


def test_severity_override_on_unknown_rule_id_rejected(
    tmp_path: Path,
) -> None:
    # The existing unknown-rule-id guard fires before severity is
    # parsed — a `[lint.rules.<bad>]` section is rejected outright.
    cfg_file = tmp_path / "pgrls.toml"
    cfg_file.write_text('[lint.rules.SEC9999]\nseverity = "error"\n')
    with pytest.raises(ConfigError, match="unknown rule id"):
        load_config(path=cfg_file)


# --- extends (shared base config) ----------------------------------------


def test_extends_inherits_and_overrides(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("DATABASE_URL", raising=False)
    (tmp_path / "base.toml").write_text(
        '[database]\nschemas = ["public", "tenant"]\n'
        '[lint]\nfail_on = "error"\ndisable = ["SEC022"]\n'
    )
    child = tmp_path / "pgrls.toml"
    child.write_text(
        'extends = "base.toml"\n[lint]\nfail_on = "warning"\n'
    )
    cfg = load_config(path=child)
    # schemas inherited from base; fail_on overridden by child.
    assert cfg.schemas == ["public", "tenant"]
    assert cfg.fail_on == "warning"
    # disable inherited (child didn't set it).
    assert cfg.disable == ["SEC022"]


def test_extends_deep_merges_rule_table(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A child can set one key of [lint.rules.SEC001] while inheriting
    # the rest from the base (table-level deep merge).
    monkeypatch.delenv("DATABASE_URL", raising=False)
    (tmp_path / "base.toml").write_text(
        '[lint.rules.SEC001]\nallowlist = ["public.countries"]\n'
    )
    child = tmp_path / "pgrls.toml"
    child.write_text(
        'extends = "base.toml"\n[lint.rules.SEC001]\nseverity = "error"\n'
    )
    cfg = load_config(path=child)
    assert cfg.rule_options["SEC001"]["allowlist"] == ["public.countries"]
    assert cfg.severity_overrides["SEC001"] == "error"


def test_extends_arrays_replace_not_append(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("DATABASE_URL", raising=False)
    (tmp_path / "base.toml").write_text('[lint]\ndisable = ["SEC022"]\n')
    child = tmp_path / "pgrls.toml"
    child.write_text('extends = "base.toml"\n[lint]\ndisable = ["PERF002"]\n')
    cfg = load_config(path=child)
    # Replace, not union — the child list wins wholesale.
    assert cfg.disable == ["PERF002"]


def test_extends_list_later_entries_win(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("DATABASE_URL", raising=False)
    (tmp_path / "a.toml").write_text('[lint]\nfail_on = "error"\n')
    (tmp_path / "b.toml").write_text('[lint]\nfail_on = "info"\n')
    child = tmp_path / "pgrls.toml"
    child.write_text('extends = ["a.toml", "b.toml"]\n')
    cfg = load_config(path=child)
    # b.toml is listed later, so it overrides a.toml.
    assert cfg.fail_on == "info"


def test_extends_resolves_relative_to_declaring_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The base path is relative to the file that declares `extends`,
    # not the cwd. Put the base in a subdir and extend from there.
    monkeypatch.delenv("DATABASE_URL", raising=False)
    sub = tmp_path / "configs"
    sub.mkdir()
    (sub / "base.toml").write_text('[database]\nschemas = ["fromsub"]\n')
    child = sub / "pgrls.toml"
    child.write_text('extends = "base.toml"\n')
    monkeypatch.chdir(tmp_path)  # cwd != the config's dir
    cfg = load_config(path=child)
    assert cfg.schemas == ["fromsub"]


def test_extends_env_interpolation_runs_after_merge(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A base's `url = "$VAR"` interpolates after the merge.
    monkeypatch.setenv("PGRLS_TEST_URL", "postgres://localhost/merged")
    (tmp_path / "base.toml").write_text(
        '[database]\nurl = "$PGRLS_TEST_URL"\n'
    )
    child = tmp_path / "pgrls.toml"
    child.write_text('extends = "base.toml"\n')
    cfg = load_config(path=child)
    assert cfg.database_url == "postgres://localhost/merged"


def test_extends_missing_target_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("DATABASE_URL", raising=False)
    child = tmp_path / "pgrls.toml"
    child.write_text('extends = "nope.toml"\n')
    with pytest.raises(ConfigError, match="not found"):
        load_config(path=child)


def test_extends_wrong_type_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("DATABASE_URL", raising=False)
    child = tmp_path / "pgrls.toml"
    child.write_text("extends = 42\n")
    with pytest.raises(ConfigError, match="must be a config path"):
        load_config(path=child)


def test_extends_cycle_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("DATABASE_URL", raising=False)
    (tmp_path / "a.toml").write_text('extends = "b.toml"\n')
    (tmp_path / "b.toml").write_text('extends = "a.toml"\n')
    with pytest.raises(ConfigError, match="cycle"):
        load_config(path=tmp_path / "a.toml")


def test_extends_self_cycle_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("DATABASE_URL", raising=False)
    child = tmp_path / "pgrls.toml"
    child.write_text('extends = "pgrls.toml"\n')
    with pytest.raises(ConfigError, match="cycle"):
        load_config(path=child)


def test_extends_diamond_is_allowed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # top extends [l, r]; both l and r extend the same base. A base
    # reached twice through different paths is NOT a cycle.
    monkeypatch.delenv("DATABASE_URL", raising=False)
    (tmp_path / "base.toml").write_text('[database]\nschemas = ["b"]\n')
    (tmp_path / "l.toml").write_text(
        'extends = "base.toml"\n[lint]\nfail_on = "info"\n'
    )
    (tmp_path / "r.toml").write_text(
        'extends = "base.toml"\n[lint]\ndisable = ["SEC001"]\n'
    )
    top = tmp_path / "pgrls.toml"
    top.write_text('extends = ["l.toml", "r.toml"]\n')
    cfg = load_config(path=top)
    assert cfg.schemas == ["b"]  # inherited via the diamond
    assert cfg.fail_on == "info"  # from l
    assert cfg.disable == ["SEC001"]  # from r


def test_extends_chain_too_deep_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A pathologically deep (non-cyclic) chain raises a clean
    # ConfigError, not a raw RecursionError.
    monkeypatch.delenv("DATABASE_URL", raising=False)
    depth = 50  # > _MAX_EXTENDS_DEPTH
    for i in range(depth):
        nxt = f'extends = "c{i + 1}.toml"\n' if i < depth - 1 else ""
        (tmp_path / f"c{i}.toml").write_text(nxt)
    with pytest.raises(ConfigError, match="too deep"):
        load_config(path=tmp_path / "c0.toml")
