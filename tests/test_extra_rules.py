"""Tests for the `[lint].extra_rules` SDK.

A project ships its own rules by:

  1. Writing a Python package that exposes a `RULES` sequence of
     `Rule`-protocol objects.
  2. Listing the module's dotted path in `[lint].extra_rules` in
     its `pgrls.toml`.

The loader (`pgrls.rules.load_extra_rules`) imports each listed
module, validates the `RULES` shape, and returns the rule list.
The config-load path (`pgrls.config._build_config`) parses the
`extra_rules` field as `list[str]`. The CLI's `_run_rules` builds
a per-invocation registry that merges built-ins + extras and
catches ID collisions.

These tests cover each of those surfaces.
"""
from __future__ import annotations

import sys
import textwrap
from pathlib import Path

import pytest

from pgrls.config import ConfigError, load_config
from pgrls.rules import (
    ExtraRulesError,
    RuleRegistry,
    load_extra_rules,
)


# ──────────────────────────────────────────────────────────────────
# Helper fixture: build a temporary package on sys.path that
# exports `RULES`. Each test installs its own custom shape so the
# loader's validation paths can be exercised in isolation.
# ──────────────────────────────────────────────────────────────────


@pytest.fixture
def make_extras_pkg(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Return a factory: write a package on a temp path + sys.path."""
    pkg_root = tmp_path / "extras_root"
    pkg_root.mkdir()
    monkeypatch.syspath_prepend(str(pkg_root))

    def _make(module_name: str, body: str) -> Path:
        pkg_dir = pkg_root / module_name
        pkg_dir.mkdir()
        (pkg_dir / "__init__.py").write_text(textwrap.dedent(body))
        # Invalidate any cached version of the module
        sys.modules.pop(module_name, None)
        return pkg_dir

    return _make


# ──────────────────────────────────────────────────────────────────
# Loader contract
# ──────────────────────────────────────────────────────────────────


def test_load_extra_rules_returns_rules_from_named_module(
    make_extras_pkg,
):
    make_extras_pkg(
        "ok_extras",
        """
        from pgrls.violations import Violation

        class ExtraRule:
            id = "EXT001"
            severity = "warning"
            title = "Example extra rule"
            def check(self, schema, options):
                return []

        RULES = [ExtraRule()]
        """,
    )
    rules = load_extra_rules(["ok_extras"])
    assert len(rules) == 1
    assert rules[0].id == "EXT001"


def test_load_extra_rules_accepts_multiple_modules(make_extras_pkg):
    make_extras_pkg(
        "pkg_a",
        """
        class A:
            id = "EXT_A"
            severity = "warning"
            title = "A"
            def check(self, s, o): return []
        RULES = [A()]
        """,
    )
    make_extras_pkg(
        "pkg_b",
        """
        class B:
            id = "EXT_B"
            severity = "info"
            title = "B"
            def check(self, s, o): return []
        RULES = [B()]
        """,
    )
    rules = load_extra_rules(["pkg_a", "pkg_b"])
    assert {r.id for r in rules} == {"EXT_A", "EXT_B"}


def test_load_extra_rules_empty_input_returns_empty_list():
    assert load_extra_rules([]) == []
    assert load_extra_rules(()) == []


def test_load_extra_rules_rejects_non_string_entry():
    with pytest.raises(ExtraRulesError) as exc:
        load_extra_rules([42])  # type: ignore[list-item]
    assert "non-empty string" in str(exc.value)


def test_load_extra_rules_rejects_empty_string_entry():
    with pytest.raises(ExtraRulesError) as exc:
        load_extra_rules([""])
    assert "non-empty string" in str(exc.value)


def test_load_extra_rules_wraps_import_error():
    with pytest.raises(ExtraRulesError) as exc:
        load_extra_rules(["pgrls_does_not_exist_xyz"])
    assert "cannot import" in str(exc.value)
    assert "pgrls_does_not_exist_xyz" in str(exc.value)


def test_load_extra_rules_rejects_module_without_RULES(make_extras_pkg):
    make_extras_pkg(
        "no_rules_attr",
        "# This module exposes nothing.\n",
    )
    with pytest.raises(ExtraRulesError) as exc:
        load_extra_rules(["no_rules_attr"])
    assert "does not expose a `RULES` attribute" in str(exc.value)


def test_load_extra_rules_rejects_non_iterable_RULES(make_extras_pkg):
    make_extras_pkg(
        "rules_not_iter",
        "RULES = 42  # not iterable\n",
    )
    with pytest.raises(ExtraRulesError) as exc:
        load_extra_rules(["rules_not_iter"])
    assert "must be iterable" in str(exc.value)


@pytest.mark.parametrize(
    "field,bad_value,phrase",
    [
        ("id", '""', "id` must be a non-empty"),
        ("id", "None", "id` must be a non-empty"),
        ("severity", "'lol'", "invalid severity"),
        ("title", '""', "empty or non-string"),
    ],
)
def test_load_extra_rules_validates_each_rule_shape(
    make_extras_pkg, field, bad_value, phrase
):
    body = f"""
    class Bad:
        id = "EXT001"
        severity = "warning"
        title = "Bad"
        def check(self, s, o): return []
    Bad.{field} = {bad_value}
    RULES = [Bad()]
    """
    make_extras_pkg(f"bad_{field}_{abs(hash(bad_value)) % 99999}", body)
    mod_name = f"bad_{field}_{abs(hash(bad_value)) % 99999}"
    with pytest.raises(ExtraRulesError) as exc:
        load_extra_rules([mod_name])
    assert phrase in str(exc.value)


def test_load_extra_rules_requires_callable_check(make_extras_pkg):
    make_extras_pkg(
        "bad_check",
        """
        class Bad:
            id = "EXT001"
            severity = "warning"
            title = "Bad"
            check = 42  # not callable
        RULES = [Bad()]
        """,
    )
    with pytest.raises(ExtraRulesError) as exc:
        load_extra_rules(["bad_check"])
    assert "callable" in str(exc.value)


# ──────────────────────────────────────────────────────────────────
# Config plumbing
# ──────────────────────────────────────────────────────────────────


def test_config_parses_extra_rules(tmp_path: Path, make_extras_pkg):
    # Config-load actually imports listed modules so the
    # downstream [lint].disable / [lint.rules.<ID>] validation
    # can see extras' IDs. Use real packages on the test path.
    make_extras_pkg(
        "ok_extras_for_cfg",
        """
        class CfgRule:
            id = "CFG001"
            severity = "info"
            title = "Cfg test"
            def check(self, s, o): return []
        RULES = [CfgRule()]
        """,
    )
    cfg = tmp_path / "pgrls.toml"
    cfg.write_text(
        '[lint]\nextra_rules = ["ok_extras_for_cfg"]\n'
    )
    loaded = load_config(cfg)
    assert loaded.extra_rules == ["ok_extras_for_cfg"]


def test_config_rejects_non_list_extra_rules(tmp_path: Path):
    cfg = tmp_path / "pgrls.toml"
    cfg.write_text('[lint]\nextra_rules = "mycompany.rules"\n')
    with pytest.raises(ConfigError) as exc:
        load_config(cfg)
    assert "must be a list" in str(exc.value)


def test_config_rejects_non_string_entries(tmp_path: Path):
    cfg = tmp_path / "pgrls.toml"
    cfg.write_text('[lint]\nextra_rules = ["ok", 42]\n')
    with pytest.raises(ConfigError) as exc:
        load_config(cfg)
    assert "must be a list of dotted Python" in str(exc.value)


def test_config_extra_rules_default_is_empty():
    from pgrls.config import Config

    assert Config().extra_rules == []


# ──────────────────────────────────────────────────────────────────
# Registry merge — collision detection at register-time
# ──────────────────────────────────────────────────────────────────


# ──────────────────────────────────────────────────────────────────
# Config-load integration: [lint].disable and [lint.rules.<ID>]
# tables for extras must work after the extras are loaded.
# These cover the iter-2 reviewer's MUST-FIX #1.
# ──────────────────────────────────────────────────────────────────


def test_config_accepts_lint_disable_with_extra_rule_id(
    tmp_path: Path, make_extras_pkg
):
    make_extras_pkg(
        "ext_for_disable",
        """
        class R:
            id = "EXT_DIS_001"
            severity = "warning"
            title = "Disable me"
            def check(self, s, o): return []
        RULES = [R()]
        """,
    )
    cfg = tmp_path / "pgrls.toml"
    cfg.write_text(
        '[lint]\n'
        'extra_rules = ["ext_for_disable"]\n'
        'disable = ["EXT_DIS_001"]\n'
    )
    loaded = load_config(cfg)
    assert "EXT_DIS_001" in loaded.disable


def test_config_accepts_lint_rules_table_for_extra_rule(
    tmp_path: Path, make_extras_pkg
):
    make_extras_pkg(
        "ext_for_options",
        """
        class R:
            id = "EXT_OPT_001"
            severity = "warning"
            title = "With options"
            def check(self, s, o): return []
        RULES = [R()]
        """,
    )
    cfg = tmp_path / "pgrls.toml"
    cfg.write_text(
        '[lint]\n'
        'extra_rules = ["ext_for_options"]\n'
        '\n'
        '[lint.rules.EXT_OPT_001]\n'
        'severity = "error"\n'
        'allowlist = ["public.tbl.policy"]\n'
    )
    loaded = load_config(cfg)
    assert loaded.severity_overrides["EXT_OPT_001"] == "error"
    assert loaded.rule_options["EXT_OPT_001"] == {
        "allowlist": ["public.tbl.policy"],
    }


def test_config_still_rejects_disable_of_unknown_id(
    tmp_path: Path, make_extras_pkg
):
    # Even with extras loaded, a typo'd id outside the combined
    # built-in+extras set must still fail loud.
    make_extras_pkg(
        "ext_unknown_disable",
        """
        class R:
            id = "EXT_001"
            severity = "warning"
            title = "x"
            def check(self, s, o): return []
        RULES = [R()]
        """,
    )
    cfg = tmp_path / "pgrls.toml"
    cfg.write_text(
        '[lint]\n'
        'extra_rules = ["ext_unknown_disable"]\n'
        'disable = ["NOSUCH"]\n'
    )
    with pytest.raises(ConfigError) as exc:
        load_config(cfg)
    assert "NOSUCH" in str(exc.value)


def test_config_propagates_extra_rules_loader_failure(tmp_path: Path):
    cfg = tmp_path / "pgrls.toml"
    cfg.write_text(
        '[lint]\n'
        'extra_rules = ["pgrls_xyz_definitely_missing"]\n'
    )
    with pytest.raises(ConfigError) as exc:
        load_config(cfg)
    # The loader's ExtraRulesError surfaces as ConfigError but
    # carries the original message so the user sees both the
    # locus and the cause in one place.
    assert "cannot import" in str(exc.value)
    assert "pgrls_xyz_definitely_missing" in str(exc.value)


def test_config_rejects_whitespace_only_extra_rule_entry(
    tmp_path: Path,
):
    cfg = tmp_path / "pgrls.toml"
    cfg.write_text('[lint]\nextra_rules = ["   "]\n')
    with pytest.raises(ConfigError) as exc:
        load_config(cfg)
    assert "non-empty" in str(exc.value)


def test_runtime_rules_rejects_extra_shadowing_builtin(
    make_extras_pkg,
):
    # `_runtime_rules` is the read-only consumer used by
    # `pgrls explain --config` and the `--rule` validation set.
    # Without collision detection, an extra declaring id="SEC001"
    # would produce a duplicate catalog row instead of erroring.
    from pgrls.cli import ToolError, _runtime_rules
    from pgrls.config import Config

    make_extras_pkg(
        "ext_shadows_runtime",
        """
        class Shadow:
            id = "SEC001"
            severity = "error"
            title = "Shadow built-in"
            def check(self, s, o): return []
        RULES = [Shadow()]
        """,
    )
    cfg = Config(extra_rules=["ext_shadows_runtime"])
    with pytest.raises(ToolError) as exc:
        _runtime_rules(cfg)
    assert "SEC001" in str(exc.value)
    assert "already registered" in str(exc.value)


def test_registry_rejects_extra_with_builtin_id_collision(
    make_extras_pkg,
):
    make_extras_pkg(
        "collides_with_builtin",
        """
        class Shadow:
            id = "SEC001"   # collides with built-in SEC001
            severity = "error"
            title = "Shadow built-in"
            def check(self, s, o): return []
        RULES = [Shadow()]
        """,
    )
    # The loader itself doesn't know about built-ins; collision
    # detection happens at registry-register time. The CLI's
    # `_run_rules` wraps the ValueError into a ToolError.
    from pgrls.rules import all_rules

    registry = RuleRegistry()
    for r in all_rules():
        registry.register(r)
    extras = load_extra_rules(["collides_with_builtin"])
    with pytest.raises(ValueError) as exc:
        registry.register(extras[0])
    assert "already registered" in str(exc.value)
