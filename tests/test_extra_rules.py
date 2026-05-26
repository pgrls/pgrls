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


def test_config_parses_extra_rules(tmp_path: Path):
    cfg = tmp_path / "pgrls.toml"
    cfg.write_text(
        '[lint]\nextra_rules = ["mycompany.rules", "another.pkg"]\n'
    )
    loaded = load_config(cfg)
    assert loaded.extra_rules == ["mycompany.rules", "another.pkg"]


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
