"""Validate the published `.pre-commit-hooks.yaml` and its README docs."""
from __future__ import annotations

import pathlib

import yaml

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_HOOKS = yaml.safe_load((_ROOT / ".pre-commit-hooks.yaml").read_text())
_BY_ID = {h["id"]: h for h in _HOOKS}


def test_hooks_are_well_formed() -> None:
    # Both published hooks invoke `pgrls lint` as an installable Python package,
    # and analyze the whole schema (never per-changed-file), so pass_filenames
    # must be false — pgrls rejects positional file args.
    assert set(_BY_ID) == {"pgrls-lint", "pgrls-lint-sql"}
    for hook in _HOOKS:
        assert hook["entry"] == "pgrls lint"
        assert hook["language"] == "python"
        assert hook["pass_filenames"] is False


def test_live_hook_runs_every_commit_offline_hook_is_sql_scoped() -> None:
    # The live-database hook can't know when the schema changed (it lives in the
    # DB), so it always runs; the offline hook's schema is tracked SQL, so it
    # fires only when a .sql file changes.
    assert _BY_ID["pgrls-lint"]["always_run"] is True
    assert _BY_ID["pgrls-lint-sql"]["files"] == r"\.sql$"
    assert "always_run" not in _BY_ID["pgrls-lint-sql"]


def test_readme_references_real_hook_ids() -> None:
    # The README pre-commit example must name hook ids that actually exist, or
    # a copy-paste of it fails with "hook id not present".
    readme = (_ROOT / "README.md").read_text()
    section = readme.split("### pre-commit", 1)[1].split("### GitHub Actions", 1)[0]
    for hook_id in _BY_ID:
        assert f"id: {hook_id}" in section, f"README omits hook {hook_id!r}"
