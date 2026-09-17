"""The shipped pgrls.toml JSON Schema (pgrls.schema.json) must stay valid
and in step with the config surface the linter actually reads.

These checks are deliberately validator-free (no `jsonschema` dependency):
they assert the schema is well-formed JSON Schema and that its declared
top-level tables match the `pgrls init` template, which guards against the
schema drifting from the documented config.
"""
from __future__ import annotations

import json
import tomllib
from pathlib import Path

from pgrls.cli import _INIT_PRESETS, _render_init_config

_SCHEMA_PATH = Path(__file__).resolve().parents[1] / "pgrls.schema.json"


def _schema() -> dict:
    return json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))


def test_schema_is_valid_json_and_well_formed() -> None:
    s = _schema()
    assert s["$schema"].startswith("https://json-schema.org/")
    assert s["type"] == "object"
    # Strict top level so a typo'd table (`[Lint]`, stray key) is flagged.
    assert s["additionalProperties"] is False
    # Exactly the top-level tables pgrls's config loader recognizes.
    assert set(s["properties"]) == {"extends", "database", "lint", "diff", "generate"}
    assert s["$defs"]["severity"]["enum"] == ["error", "warning", "info"]
    # The hyphenated diff classification is a real gotcha; pin it.
    diff_values = s["properties"]["diff"]["properties"]["fail_on"]["enum"]
    assert diff_values == ["safe", "breaking", "requires-review", "dangerous"]


def test_schema_top_level_tables_match_init_template() -> None:
    # tomllib ignores the leading `#:schema` comment. Every top-level
    # table the documented template uses must be a declared schema
    # property — if `pgrls init` grows a new table, the schema (and this
    # test) must grow with it. Checked for every preset, since a preset
    # could in principle introduce a stack-specific table.
    schema_props = set(_schema()["properties"])
    for preset in _INIT_PRESETS:
        parsed = tomllib.loads(_render_init_config(preset))
        assert set(parsed) <= schema_props, preset
        assert {"database", "lint", "diff"} <= set(parsed), preset
