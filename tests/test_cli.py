import inspect
import json
from pathlib import Path

from click.testing import CliRunner

from pgrls.cli import _merge_overrides, _run_rules, _should_fail, main
from pgrls.config import Config
from pgrls.model import Schema, Table
from pgrls.rules import all_rules
from pgrls.violations import Violation


def test_root_help_lists_lint():
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "lint" in result.output


def test_lint_help_runs():
    runner = CliRunner()
    result = runner.invoke(main, ["lint", "--help"])
    assert result.exit_code == 0
    for flag in ("--database-url", "--config", "--schemas", "--fail-on"):
        assert flag in result.output


def test_root_version_flag():
    # Pull the version from the package itself rather than
    # hard-coding the literal — release bumps that forget to
    # update test_cli.py would otherwise pass for substring-
    # of-substring reasons (e.g. "0.0.7" is in "0.0.71").
    from pgrls import __version__

    runner = CliRunner()
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_package_version_matches_pyproject() -> None:
    # `pgrls.__version__` is sourced from `importlib.metadata.version`,
    # which reads the installed distribution's metadata. That metadata
    # is written from `pyproject.toml`'s `[project].version` at install
    # time. Without this assertion, a previous regression went silent
    # for 22 patch releases: `__version__` was hard-coded to "0.6.0"
    # while pyproject was bumped each release, so every test comparing
    # `__version__` to itself passed for the wrong reason. Compare
    # the two sources directly.
    import tomllib
    from pathlib import Path

    from pgrls import __version__

    pyproject_path = Path(__file__).resolve().parent.parent / "pyproject.toml"
    pyproject = tomllib.loads(pyproject_path.read_text())
    assert __version__ == pyproject["project"]["version"], (
        f"pgrls.__version__ ({__version__!r}) does not match "
        f"pyproject [project].version "
        f"({pyproject['project']['version']!r}); re-run "
        "`pip install -e .` to refresh the editable install's "
        "metadata."
    )


def test_python_dash_m_pgrls_invokes_cli(monkeypatch, capsys) -> None:
    # `python -m pgrls` runs `src/pgrls/__main__.py`, whose
    # `if __name__ == "__main__": main()` block dispatches to the CLI.
    # `runpy.run_module(run_name="__main__")` executes that block
    # in-process (so it's the same entry the documented subprocess form
    # uses). `--version` exits 0 after printing the version.
    import runpy

    import pytest

    from pgrls import __version__

    monkeypatch.setattr("sys.argv", ["pgrls", "--version"])
    with pytest.raises(SystemExit) as exc_info:
        runpy.run_module("pgrls", run_name="__main__")
    assert exc_info.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_init_writes_parseable_default_config(tmp_path) -> None:
    # `init` needs no database. The file it writes must parse through
    # load_config AND leave every setting at its default, so a fresh
    # `pgrls lint` runs unchanged against it.
    from pgrls.config import load_config

    out = tmp_path / "pgrls.toml"
    runner = CliRunner()
    result = runner.invoke(main, ["init", "--output", str(out)])
    assert result.exit_code == 0, result.output
    assert out.is_file()
    cfg = load_config(str(out))
    assert cfg.schemas == ["public"]
    assert cfg.fail_on == "warning"
    assert cfg.diff_fail_on == "dangerous"
    # url is left commented, so no env-var interpolation fires on a
    # fresh file with DATABASE_URL unset.
    assert cfg.database_url is None
    assert cfg.disable == []
    assert cfg.severity_overrides == {}
    assert cfg.rule_options == {}


def test_init_emits_schema_directive(tmp_path) -> None:
    # The first line is an Even Better TOML `#:schema` directive pointing
    # at the published JSON Schema, so editors validate / autocomplete the
    # generated pgrls.toml. It is a comment, so it must not affect parsing
    # (covered by test_init_writes_parseable_default_config).
    out = tmp_path / "pgrls.toml"
    result = CliRunner().invoke(main, ["init", "--output", str(out)])
    assert result.exit_code == 0, result.output
    first_line = out.read_text(encoding="utf-8").splitlines()[0]
    assert first_line == (
        "#:schema https://raw.githubusercontent.com/pgrls/pgrls/main/"
        "pgrls.schema.json"
    )


def test_init_defaults_to_pgrls_toml_in_cwd(tmp_path) -> None:
    runner = CliRunner()
    with runner.isolated_filesystem(temp_dir=tmp_path):
        result = runner.invoke(main, ["init"])
        assert result.exit_code == 0, result.output
        assert Path("pgrls.toml").is_file()


def test_init_refuses_to_overwrite_without_force(tmp_path) -> None:
    out = tmp_path / "pgrls.toml"
    out.write_text("existing = true\n", encoding="utf-8")
    runner = CliRunner()
    result = runner.invoke(main, ["init", "--output", str(out)])
    # Exit 2 (ToolError) — and the existing file is left untouched.
    assert result.exit_code == 2
    assert "already exists" in result.output
    assert out.read_text(encoding="utf-8") == "existing = true\n"


def test_init_force_overwrites(tmp_path) -> None:
    out = tmp_path / "pgrls.toml"
    out.write_text("existing = true\n", encoding="utf-8")
    runner = CliRunner()
    result = runner.invoke(main, ["init", "--output", str(out), "--force"])
    assert result.exit_code == 0, result.output
    written = out.read_text(encoding="utf-8")
    assert "existing = true" not in written
    assert "[lint]" in written


def test_init_unwritable_path_exits_two_cleanly(tmp_path) -> None:
    # A path whose parent directory doesn't exist is an OSError, which
    # must surface as a ToolError (exit 2) with a message — not a
    # traceback. Pins the clean-error contract for the write path.
    out = tmp_path / "missing_dir" / "pgrls.toml"
    runner = CliRunner()
    result = runner.invoke(main, ["init", "--output", str(out)])
    assert result.exit_code == 2
    assert "Cannot write" in result.output


def test_root_help_lists_init() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "init" in result.output


def test_init_default_preset_is_generic(tmp_path) -> None:
    # `pgrls init` with no --preset must produce exactly the generic
    # template — the default behaviour is unchanged by the preset feature.
    from pgrls.cli import _render_init_config

    out = tmp_path / "pgrls.toml"
    result = CliRunner().invoke(main, ["init", "--output", str(out)])
    assert result.exit_code == 0, result.output
    assert out.read_text(encoding="utf-8") == _render_init_config("generic")


def test_init_every_preset_parses_with_defaults(tmp_path) -> None:
    # Every preset is a documentation-only variation: the file must parse
    # through load_config and leave EVERY rule at its default, exactly like
    # the generic template, so `pgrls lint` runs unchanged regardless of
    # which preset scaffolded the config.
    from pgrls.cli import _INIT_PRESETS
    from pgrls.config import load_config

    for preset in _INIT_PRESETS:
        out = tmp_path / f"{preset}.toml"
        result = CliRunner().invoke(
            main, ["init", "--output", str(out), "--preset", preset]
        )
        assert result.exit_code == 0, (preset, result.output)
        assert f"({preset} preset)" in result.output
        cfg = load_config(str(out))
        assert cfg.schemas == ["public"], preset
        assert cfg.fail_on == "warning", preset
        assert cfg.diff_fail_on == "dangerous", preset
        assert cfg.database_url is None, preset
        assert cfg.disable == [], preset
        assert cfg.severity_overrides == {}, preset
        assert cfg.rule_options == {}, preset
        # The schema directive stays the first line for every preset.
        first_line = out.read_text(encoding="utf-8").splitlines()[0]
        assert first_line.startswith("#:schema "), preset


def test_init_preset_documents_matching_generate_command(tmp_path) -> None:
    # The payoff of a preset: it names the stack and documents the exact
    # `pgrls generate` invocation (using only flags generate accepts) that
    # scaffolds matching, lint-clean policies.
    expected = {
        "generic": (
            "per-tenant",
            "pgrls generate --apply",
        ),
        "supabase": (
            "Supabase",
            "pgrls generate --model owner --convention supabase --apply",
        ),
        "postgrest": (
            "PostgREST",
            "pgrls generate --convention postgrest --apply",
        ),
        "neon": (
            "Neon Authorize",
            "pgrls generate --model owner --convention supabase "
            "--auth-function auth.user_id --apply",
        ),
    }
    runner = CliRunner()
    for preset, (marker, command) in expected.items():
        out = tmp_path / f"{preset}.toml"
        result = runner.invoke(
            main, ["init", "--output", str(out), "--preset", preset]
        )
        assert result.exit_code == 0, (preset, result.output)
        text = out.read_text(encoding="utf-8")
        assert marker in text, preset
        assert command in text, preset


def test_init_preset_is_case_insensitive(tmp_path) -> None:
    out = tmp_path / "pgrls.toml"
    result = CliRunner().invoke(
        main, ["init", "--output", str(out), "--preset", "SUPABASE"]
    )
    assert result.exit_code == 0, result.output
    assert "(supabase preset)" in result.output
    assert "Supabase" in out.read_text(encoding="utf-8")


def test_init_rejects_unknown_preset(tmp_path) -> None:
    out = tmp_path / "pgrls.toml"
    result = CliRunner().invoke(
        main, ["init", "--output", str(out), "--preset", "django"]
    )
    # click rejects an invalid Choice with a usage error (exit 2) and
    # writes nothing.
    assert result.exit_code == 2
    assert "django" in result.output
    assert not out.exists()


def test_init_help_lists_presets() -> None:
    result = CliRunner().invoke(main, ["init", "--help"])
    assert result.exit_code == 0
    for preset in ("generic", "supabase", "postgrest", "neon"):
        assert preset in result.output


def test_explain_prints_rule_rationale() -> None:
    # `explain` needs no database — it reads only pgrls's own rule
    # catalog. The output is a header line plus the rule's
    # module-doc rationale.
    runner = CliRunner()
    result = runner.invoke(main, ["explain", "SEC023"])
    assert result.exit_code == 0, result.output
    assert "SEC023" in result.output
    assert "[warning]" in result.output
    assert "Policy applies to a role that bypasses RLS" in result.output
    # A substring unique to SEC023's rationale body — proves the
    # docstring, not just the header, reached the output.
    assert "BYPASSRLS" in result.output


def test_explain_succeeds_when_config_url_env_var_unset(
    tmp_path: Path, monkeypatch
) -> None:
    """Regression: `explain --config cfg.toml` must run even when the
    config's `[database].url` references an unset env var.

    `explain` reads only the rule catalog — never the DB. load_config
    used to raise during eager `[database].url` interpolation, breaking
    a command documented as needing no connection. The failure is now
    deferred, so this must exit 0 and still print the rule rationale.
    """
    monkeypatch.delenv("UNSET_DB_URL", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    cfg = tmp_path / "pgrls.toml"
    cfg.write_text('[database]\nurl = "$UNSET_DB_URL"\n', encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(main, ["explain", "SEC001", "--config", str(cfg)])

    assert result.exit_code == 0, result.output
    assert "SEC001" in result.output


def test_lint_surfaces_deferred_url_error_at_connection_guard(
    tmp_path: Path, monkeypatch
) -> None:
    """A DB-needing command (`lint`) with an unresolvable configured
    URL still fails — but with the SPECIFIC deferred cause, not the
    generic 'No database connection' guidance. No DB is touched: the
    connection guard fires before any connect attempt."""
    monkeypatch.delenv("UNSET_DB_URL", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    cfg = tmp_path / "pgrls.toml"
    cfg.write_text('[database]\nurl = "$UNSET_DB_URL"\n', encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(main, ["lint", "--config", str(cfg)])

    assert result.exit_code == 2, result.output
    assert "UNSET_DB_URL" in result.output


def test_explain_is_case_insensitive() -> None:
    # `explain sec001` and `explain SEC001` resolve the same rule
    # and produce byte-identical output.
    runner = CliRunner()
    lower = runner.invoke(main, ["explain", "sec001"])
    upper = runner.invoke(main, ["explain", "SEC001"])
    assert lower.exit_code == 0, lower.output
    assert lower.output == upper.output


def test_explain_unknown_rule_exits_two() -> None:
    # An unknown rule is a tool error (exit 2), not a lint finding
    # (exit 1) — the same three-tier convention the other commands
    # follow.
    runner = CliRunner()
    result = runner.invoke(main, ["explain", "SEC999"])
    assert result.exit_code == 2
    assert "Unknown rule" in result.output
    assert "SEC999" in result.output


def test_explain_no_argument_lists_the_rule_catalog() -> None:
    # Bare `pgrls explain` lists every registered rule (ID,
    # severity, title) as a quick at-a-glance catalog. RULE is
    # optional; the per-rule reference is one argument away.
    runner = CliRunner()
    result = runner.invoke(main, ["explain"])
    assert result.exit_code == 0, result.output
    # Every registered rule must appear in the catalog — ID,
    # bracketed severity, and title. Mirrors the every-rule
    # contract test below for the per-rule path.
    for rule in all_rules():
        assert rule.id in result.output, f"{rule.id} missing"
        assert rule.title in result.output, f"{rule.id} title missing"
        assert f"[{rule.severity}]" in result.output, (
            f"{rule.id} severity missing"
        )
    # And a pointer to the per-rule path.
    assert "pgrls explain <RULE>" in result.output


def test_explain_covers_every_registered_rule() -> None:
    # Every registered rule must be explainable: exit 0, a header
    # naming the rule and its title, and a rationale body. Catches
    # a rule shipped without a module docstring — `explain` would
    # then print only the bare header line.
    runner = CliRunner()
    for rule in all_rules():
        result = runner.invoke(main, ["explain", rule.id])
        assert result.exit_code == 0, f"{rule.id}: {result.output}"
        assert rule.id in result.output
        assert rule.title in result.output
        assert len(result.output.strip().splitlines()) > 2, (
            f"{rule.id} printed no rationale body"
        )
        # `explain` drops the docstring's leading "<ID> — <title>."
        # line so the printed header is not immediately restated.
        # Pin that strip: the exact first line must be absent from
        # the output, or a silent strip regression would go unseen.
        module = inspect.getmodule(type(rule))
        first_line = (
            (module.__doc__ if module else None) or ""
        ).strip().splitlines()[0]
        assert first_line not in result.output, (
            f"{rule.id}: docstring title line was not stripped"
        )


def test_explain_format_is_case_insensitive() -> None:
    # R11 #9: `--format` on `explain` must accept mixed/upper case like
    # every other command's --format (lint, diff, perf). `JSON` must
    # behave exactly like `json`, not exit 2 with a usage error.
    runner = CliRunner()
    for value in ("JSON", "Json", "MARKDOWN"):
        result = runner.invoke(
            main, ["explain", "SEC001", "--format", value]
        )
        assert result.exit_code == 0, (value, result.output)
    # `JSON` produces parseable JSON, identical to `json`.
    upper = runner.invoke(main, ["explain", "SEC001", "--format", "JSON"])
    lower = runner.invoke(main, ["explain", "SEC001", "--format", "json"])
    assert json.loads(upper.output) == json.loads(lower.output)


def test_explain_format_markdown_per_rule_renders_heading_and_body() -> None:
    # `pgrls explain SEC001 --format markdown` emits an H2 heading,
    # a `**Severity:**` line, then the rule's reference body — the
    # paste-ready shape for a project runbook or wiki.
    runner = CliRunner()
    result = runner.invoke(
        main, ["explain", "SEC001", "--format", "markdown"]
    )
    assert result.exit_code == 0, result.output
    out = result.output
    assert "## SEC001 — RLS not enabled on table" in out
    assert "**Severity:** error" in out
    # Substring from the rule's docstring body (not the message
    # template) proves the body was appended.
    assert "pg_class.relrowsecurity" in out


def test_explain_format_markdown_strips_docstring_title_line() -> None:
    # The Markdown heading replaces the docstring's leading
    # "<ID> — <title>." line; the body must not restate it.
    runner = CliRunner()
    result = runner.invoke(
        main, ["explain", "SEC001", "--format", "markdown"]
    )
    # The exact docstring first line is absent from the body
    # (the H2 carries the same information). `inspect` is already
    # imported at module top.
    from pgrls.rules.sec001 import SEC001
    module = inspect.getmodule(SEC001)
    docstring_first_line = (
        (module.__doc__ if module else None) or ""
    ).strip().splitlines()[0]
    assert docstring_first_line not in result.output


def test_explain_format_markdown_catalog_renders_table() -> None:
    # Bare `pgrls explain --format markdown` lists every rule as
    # a Markdown table. The table header and at least one rule
    # row must appear; the H1 anchors the document.
    runner = CliRunner()
    result = runner.invoke(main, ["explain", "--format", "markdown"])
    assert result.exit_code == 0, result.output
    out = result.output
    assert "# pgrls rule catalog" in out
    # The summary line names the pgrls version and the rule
    # count and points at the per-rule lookup.
    from pgrls import __version__
    assert __version__ in out
    assert "pgrls explain <RULE>" in out
    assert "| ID | Severity | Title |" in out
    assert "|---|---|---|" in out
    # Every registered rule has a row.
    for rule in all_rules():
        assert f"| {rule.id} |" in out
        assert rule.title in out


def test_explain_format_json_per_rule_has_metadata_and_reference() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["explain", "SEC001", "--format", "json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["id"] == "SEC001"
    assert payload["severity"] == "error"
    assert payload["title"]
    # SEC001 has an auto-fixer.
    assert payload["fixable"] is True
    # The reference body (rule docstring minus its title line) is
    # included so JSON consumers get everything `--format text` shows.
    assert isinstance(payload["reference"], str)
    assert payload["reference"].strip()


def test_explain_format_json_marks_unfixable_rule() -> None:
    # SEC003 (permissive policy grants to PUBLIC) has no auto-fixer —
    # the right role to replace PUBLIC with is application-specific
    # (`authenticated`? a tenant role? a service role?) and pgrls
    # can't infer it.
    runner = CliRunner()
    result = runner.invoke(main, ["explain", "SEC003", "--format", "json"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["fixable"] is False


def test_explain_format_json_is_case_insensitive() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["explain", "sec001", "--format", "json"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["id"] == "SEC001"


def test_explain_format_json_catalog_lists_every_rule() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["explain", "--format", "json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    from pgrls import __version__

    assert payload["pgrls_version"] == __version__
    registered = {r.id for r in all_rules()}
    assert payload["count"] == len(registered)
    catalog_ids = {r["id"] for r in payload["rules"]}
    assert catalog_ids == registered
    # Every entry carries the compact metadata quartet.
    for entry in payload["rules"]:
        assert set(entry) == {"id", "severity", "title", "fixable"}


def test_explain_json_reference_equals_text_body_for_every_rule() -> None:
    # The strongest invariant: the json `reference` is the SAME body
    # `--format text` prints (both call `_rule_docstring_body`), and
    # severity/title mirror the Rule. Locks the shared-source contract
    # so text and json can't drift.
    from pgrls.cli import (
        _fixable_rule_ids,
        _render_rule_json,
        _rule_docstring_body,
    )

    fixable = _fixable_rule_ids()
    for rule in all_rules():
        payload = json.loads(_render_rule_json(rule, fixable_ids=fixable))
        assert payload["reference"] == _rule_docstring_body(rule)
        assert payload["severity"] == rule.severity
        assert payload["title"] == rule.title
        assert payload["fixable"] == (rule.id in fixable)


def test_explain_json_catalog_fixable_matches_fixer_registry() -> None:
    # The catalog's `fixable` flags must be exactly the set `pgrls fix`
    # can remediate — no hand-maintained drift.
    from pgrls.cli import _fixable_rule_ids, _render_catalog_json

    fixable = _fixable_rule_ids()
    payload = json.loads(
        _render_catalog_json(all_rules(), fixable_ids=fixable)
    )
    flagged = {r["id"] for r in payload["rules"] if r["fixable"]}
    assert flagged == fixable


def test_explain_format_text_remains_the_default() -> None:
    # Omitting --format gives the existing text shape (no leading
    # `##` heading, no `**Severity:**` line). The text path is
    # the regression check for everything that doesn't use the
    # new flag.
    runner = CliRunner()
    result = runner.invoke(main, ["explain", "SEC001"])
    assert result.exit_code == 0
    # Text header is `SEC001  [error]  ...`, not the Markdown H2.
    assert "## SEC001" not in result.output
    assert "**Severity:**" not in result.output
    assert "SEC001  [error]  " in result.output


def test_explain_format_unknown_value_errors() -> None:
    # `--format xml` is not a supported choice; Click rejects it.
    runner = CliRunner()
    result = runner.invoke(
        main, ["explain", "SEC001", "--format", "xml"]
    )
    assert result.exit_code != 0
    assert "xml" in result.output


# ----------------------------------------------------------------------------
# `pgrls explain --format html` (v0.6.21)
# ----------------------------------------------------------------------------


def test_explain_format_html_per_rule_renders_standalone_page() -> None:
    runner = CliRunner()
    result = runner.invoke(
        main, ["explain", "SEC001", "--format", "html"]
    )
    assert result.exit_code == 0, result.output
    # Standalone HTML5 document, no external assets.
    assert result.output.startswith("<!DOCTYPE html>")
    assert '<html lang="en">' in result.output
    assert "<title>pgrls explain — SEC001</title>" in result.output
    assert "<style>" in result.output
    assert "<link" not in result.output
    assert "<script" not in result.output
    # Rule ID + title appear in the H1.
    assert "<h1>SEC001 —" in result.output
    # Severity pill carries the right CSS class.
    assert 'class="pill sev-error">error' in result.output
    # SEC001 is auto-fixable → fixable badge present.
    assert "auto-fixable" in result.output


def test_explain_format_html_unfixable_rule_omits_fixable_badge() -> None:
    # SEC003 has no auto-fixer.
    runner = CliRunner()
    result = runner.invoke(
        main, ["explain", "SEC003", "--format", "html"]
    )
    assert result.exit_code == 0, result.output
    assert "<title>pgrls explain — SEC003</title>" in result.output
    # Fixable badge is conditionally omitted.
    assert "auto-fixable" not in result.output


def test_explain_format_html_renders_reference_body_in_pre_block() -> None:
    # The rule's docstring body lands in a `<pre>` element so the
    # rule-author's intended whitespace/indentation/code-fences
    # survive. (Future iteration may add full Markdown→HTML
    # conversion; today the contract is "pre-formatted text".)
    runner = CliRunner()
    result = runner.invoke(
        main, ["explain", "SEC001", "--format", "html"]
    )
    assert "<pre>" in result.output
    assert "</pre>" in result.output
    # Verify part of SEC001's actual reference body lands in the pre.
    assert "row-level security" in result.output.lower()


def test_explain_format_html_escapes_rule_metadata() -> None:
    # Even though no real rule has special chars in id/title/severity,
    # the renderer html.escape-s them so a future test rule containing
    # `<` / `>` / `&` can't break layout or inject markup.
    from pgrls.cli import _render_rule_html

    class _FakeRule:
        id = "FOO<bar>"
        severity = "warning"
        title = "Has & in <title>"
        __doc__ = "Has & < > in body."

    out = _render_rule_html(_FakeRule(), fixable_ids=set())
    # Raw `<bar>` must not survive as a literal tag.
    assert "<bar>" not in out
    assert "FOO&lt;bar&gt;" in out
    assert "Has &amp; in &lt;title&gt;" in out


def test_explain_format_html_catalog_renders_every_rule_row() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["explain", "--format", "html"])
    assert result.exit_code == 0, result.output
    assert "<title>pgrls rule catalog</title>" in result.output
    # 52 rules ship today (catalog header should say so).
    assert "<strong>52</strong> rules" in result.output
    # Header carries the auto-fixable count (17 as of v0.6.20+).
    # Use the actual value via the python API to avoid hard-coding.
    from pgrls.cli import _fixable_rule_ids
    fc = len(_fixable_rule_ids())
    assert f"<strong class=\"sev-info\">{fc}</strong>" in result.output
    # One row per rule.
    from pgrls.rules import all_rules
    for rule in all_rules():
        assert f"<code>{rule.id}</code>" in result.output


def test_explain_format_html_catalog_links_rule_ids_to_docs() -> None:
    # Each rule ID in the catalog links to docs/RULES.md anchor
    # so a reviewer can click through to the canonical reference.
    runner = CliRunner()
    result = runner.invoke(main, ["explain", "--format", "html"])
    assert (
        "https://github.com/pgrls/pgrls/blob/main/docs/"
        "RULES.md#rule-sec001" in result.output
    )


def test_explain_format_html_carries_no_trailing_double_newline() -> None:
    # `nl=False` in the dispatch — the renderer ends in a trailing
    # newline and click.echo shouldn't add another.
    runner = CliRunner()
    result = runner.invoke(
        main, ["explain", "SEC001", "--format", "html"]
    )
    # Exactly one trailing newline, no doubled blank line at EOF.
    assert result.output.endswith("</html>\n")
    assert not result.output.endswith("</html>\n\n")


# --- docstring-degradation helpers ---------------------------------------
#
# Every SHIPPED rule has a two-paragraph module docstring (title line +
# reference paragraph), enforced by test_explain_covers_every_registered_rule.
# These tests pin the graceful-degradation paths the helpers take for a
# rule whose docstring is absent (e.g. under `python -OO`) or doesn't
# follow the two-paragraph convention — paths no shipped rule reaches.


def _fake_rule(monkeypatch, *, module_doc: str | None):
    """Build a Rule whose class module has the given `__doc__`.

    `_rule_docstring` reads `inspect.getmodule(type(rule)).__doc__`, so
    the docstring is controlled by registering a throwaway module in
    `sys.modules` (auto-restored by monkeypatch) and pointing the fake
    rule class's `__module__` at it.
    """
    import sys
    import types

    mod_name = "pgrls_fake_rule_module_for_test"
    mod = types.ModuleType(mod_name)
    mod.__doc__ = module_doc
    monkeypatch.setitem(sys.modules, mod_name, mod)

    class _FakeRule:
        id = "FAKE001"
        severity = "info"
        title = "Fake rule"

        def check(self, schema, options):  # pragma: no cover - never run
            return []

    _FakeRule.__module__ = mod_name
    return _FakeRule()


def test_rule_rationale_paragraph_empty_when_docstring_absent(
    monkeypatch,
) -> None:
    # No module docstring → `pgrls lint --explain` degrades to the
    # un-augmented message (empty rationale).
    from pgrls.cli import _rule_rationale_paragraph

    rule = _fake_rule(monkeypatch, module_doc=None)
    assert _rule_rationale_paragraph(rule) == ""


def test_rule_rationale_paragraph_empty_when_single_paragraph(
    monkeypatch,
) -> None:
    # A docstring with only the title line (no blank-line-separated
    # reference paragraph) has nothing to surface as a rationale.
    from pgrls.cli import _rule_rationale_paragraph

    rule = _fake_rule(
        monkeypatch, module_doc="FAKE001 — Fake rule. One line only."
    )
    assert _rule_rationale_paragraph(rule) == ""


def test_rule_docstring_body_empty_when_docstring_absent(
    monkeypatch,
) -> None:
    # `explain` (text + json + markdown) shows an empty reference body
    # for a rule with no docstring rather than crashing.
    from pgrls.cli import _rule_docstring_body

    rule = _fake_rule(monkeypatch, module_doc=None)
    assert _rule_docstring_body(rule) == ""


def test_human_bytes_renders_petabytes() -> None:
    # `_human_bytes` walks B → kB → MB → GB → TB and, for sizes that
    # exceed every named unit, falls through the loop to the PB suffix.
    # Cache images never reach this scale, but the final return must be
    # exercised so the unit ladder has no dead rung.
    from pgrls.cli import _human_bytes

    # 2000 TB = 2 PB (decimal, 1000-based — matching `docker images`).
    assert _human_bytes(2 * 1000**5) == "2.0PB"
    # Just over 1 PB stays in the PB rung too.
    assert _human_bytes(1500 * 1000**4).endswith("PB")


FIXTURES_DIR = Path(__file__).parent / "fixtures"

# A connection string that fails instantly with a psycopg.Error: it
# dials a Unix socket in a directory that cannot exist, so psycopg
# raises OperationalError synchronously — no DNS/TCP timeout, no
# network. Drives the "Database error" ToolError paths deterministically
# without needing (or reaching) a real server.
_BAD_SOCKET_URL = "postgresql://u@/db?host=/nonexistent_pgrls_socket_dir"

# Derive from the rule registry so a new rule lands without the
# tuple drifting silently. `all_rules()` itself is covered by
# tests/test_readme_currency.py against the README rules table.
_ALL_RULE_IDS = tuple(rule.id for rule in all_rules())


def _assert_rules_fire_exactly(output: str, expected: set[str]) -> None:
    """Assert exactly `expected` rule IDs appear in lint output.

    Pins which rules a fixture is meant to exercise, so silent
    cross-firing or silent regressions on other rules show up as
    test failures rather than going unnoticed.
    """
    found = {rid for rid in _ALL_RULE_IDS if rid in output}
    assert found == expected, (
        f"expected {sorted(expected)}, got {sorted(found)}\n"
        f"output:\n{output}"
    )


def test_lint_against_known_bad_db_exits_nonzero(pg_url: str, apply_sql) -> None:
    apply_sql((FIXTURES_DIR / "known_bad.sql").read_text())
    runner = CliRunner()
    result = runner.invoke(main, ["lint", "--database-url", pg_url])
    assert result.exit_code == 1, result.output
    assert "public.users" in result.output
    # users → SEC001. orders.orders_owner is permissive PUBLIC → SEC003.
    # orders has only that one permissive policy → SEC007 (info), and
    # that policy is FOR SELECT, so orders has no write-side policy →
    # SEC022 (info).
    _assert_rules_fire_exactly(
        result.output, {"SEC001", "SEC003", "SEC007", "SEC022"}
    )


def test_lint_clean_db_exits_zero(pg_url: str, apply_sql) -> None:
    # RLS + FORCE + a PERMISSIVE-non-PUBLIC policy + a RESTRICTIVE
    # floor + PRIMARY KEY = the canonical clean shape:
    #   - SEC001: RLS on
    #   - SEC002: FORCE on
    #   - SEC003: PERMISSIVE is to postgres, not PUBLIC
    #   - SEC005: USING references the own column `id`
    #   - SEC006: the FOR ALL policies each carry a WITH CHECK
    #   - SEC007: at least one RESTRICTIVE → not all-permissive
    #   - SEC009: at least one policy → not RLS-without-policies
    #   - SEC012: at least one PERMISSIVE → not silent deny-all
    #   - SEC020: WITH CHECK is `id > 0`, not a constant `true`
    #   - SEC022: the FOR ALL policies cover writes → not read-only
    #   - PERF003: PRIMARY KEY creates an implicit B-tree on `id`,
    #     so the `id > 0` predicate has a leading-column index
    apply_sql(
        """
        CREATE TABLE public.t (id INT PRIMARY KEY);
        ALTER TABLE public.t ENABLE ROW LEVEL SECURITY;
        ALTER TABLE public.t FORCE ROW LEVEL SECURITY;
        CREATE POLICY t_permit ON public.t
            FOR ALL TO postgres USING (id > 0) WITH CHECK (id > 0);
        CREATE POLICY t_lock ON public.t
            AS RESTRICTIVE FOR ALL TO postgres
            USING (id > 0) WITH CHECK (id > 0);
        """
    )
    runner = CliRunner()
    result = runner.invoke(main, ["lint", "--database-url", pg_url])
    assert result.exit_code == 0, result.output
    assert "no issues" in result.output.lower()


def test_lint_missing_database_url_errors_clearly(monkeypatch) -> None:
    monkeypatch.delenv("DATABASE_URL", raising=False)
    runner = CliRunner()
    result = runner.invoke(main, ["lint"])
    # Tool error (config / setup), not findings — exit code 2
    # distinguishes "your DATABASE_URL is wrong" from "your schema
    # has an RLS bug" so CI alerts can route differently.
    assert result.exit_code == 2
    assert "DATABASE_URL" in result.output or "database-url" in result.output


def test_lint_exit_code_1_is_violations_at_threshold_only(
    pg_url: str, apply_sql
) -> None:
    # Pin the contract: exit 1 means "lint completed, findings
    # reached threshold." Bad TOML, missing DB, unknown schema all
    # produce exit 2 (tested below). This separation lets `pgrls
    # lint && deploy` distinguish the two.
    apply_sql((FIXTURES_DIR / "known_bad.sql").read_text())
    runner = CliRunner()
    result = runner.invoke(main, ["lint", "--database-url", pg_url])
    assert result.exit_code == 1
    assert "SEC001" in result.output


def test_lint_unknown_schema_exits_2_not_1(
    pg_url: str,
) -> None:
    # `--schemas` typo is a setup error, not a findings result.
    # Pin exit 2 explicitly so a future regression that reroutes
    # introspect.ValueError through `sys.exit(1)` fails this.
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["lint", "--database-url", pg_url, "--schemas", "no_such_schema"],
    )
    assert result.exit_code == 2


def test_lint_bad_toml_exits_2_not_1(tmp_path) -> None:
    cfg = tmp_path / "pgrls.toml"
    cfg.write_text("[database\n")  # malformed TOML
    runner = CliRunner()
    result = runner.invoke(main, ["lint", "--config", str(cfg)])
    assert result.exit_code == 2


def test_lint_database_connection_error_exits_2_cleanly() -> None:
    # A connection that fails at the psycopg layer (bad conninfo)
    # surfaces as a ToolError (exit 2) with a "Database error" prefix,
    # not exit 1 (findings) and not a raw traceback. Pins lint's
    # `except psycopg.Error` branch.
    runner = CliRunner()
    result = runner.invoke(main, ["lint", "--database-url", _BAD_SOCKET_URL])
    assert result.exit_code == 2, result.output
    assert "Database error" in result.output
    assert "Traceback" not in result.output


def test_lint_disable_skips_rule(pg_url: str, apply_sql, tmp_path) -> None:
    apply_sql((FIXTURES_DIR / "known_bad.sql").read_text())
    cfg = tmp_path / "pgrls.toml"
    cfg.write_text('[lint]\ndisable = ["SEC001", "SEC003"]\n')
    runner = CliRunner()
    result = runner.invoke(
        main, ["lint", "--database-url", pg_url, "--config", str(cfg)]
    )
    assert result.exit_code == 0, result.output
    assert "SEC001" not in result.output


def test_run_rules_applies_severity_override() -> None:
    # An RLS-disabled table trips SEC001 (declared severity: error)
    # and nothing else. `_run_rules` must remap every SEC001
    # violation to the configured override severity.
    schema = Schema(
        tables=(
            Table(
                schema="public",
                name="t",
                rls_enabled=False,
                force_rls=False,
                policies=(),
            ),
        )
    )
    base = _run_rules(schema, config=Config())
    assert [(v.rule_id, v.severity) for v in base] == [("SEC001", "error")]

    demoted = _run_rules(
        schema, config=Config(severity_overrides={"SEC001": "info"})
    )
    assert [(v.rule_id, v.severity) for v in demoted] == [
        ("SEC001", "info")
    ]
    # The remap is direction-agnostic — a non-overridden run is
    # unaffected, an overridden run takes the configured value
    # verbatim. The violation's other fields are preserved.
    assert demoted[0].location == base[0].location
    assert demoted[0].message == base[0].message


def test_run_rules_severity_override_remaps_every_violation() -> None:
    # Two RLS-disabled tables trip SEC001 twice. The remap is
    # per-violation — every finding must land at the override
    # severity, not just the first.
    schema = Schema(
        tables=(
            Table(
                schema="public",
                name="a",
                rls_enabled=False,
                force_rls=False,
                policies=(),
            ),
            Table(
                schema="public",
                name="b",
                rls_enabled=False,
                force_rls=False,
                policies=(),
            ),
        )
    )
    found = _run_rules(
        schema, config=Config(severity_overrides={"SEC001": "info"})
    )
    assert {v.rule_id for v in found} == {"SEC001"}
    assert [v.severity for v in found] == ["info", "info"]


def test_run_rules_severity_override_inert_when_rule_disabled() -> None:
    # `disable` wins over `severity`: a disabled rule never runs, so
    # its override has nothing to remap. Pins the contrast the
    # feature draws — `severity` re-tiers, `disable` silences.
    schema = Schema(
        tables=(
            Table(
                schema="public",
                name="t",
                rls_enabled=False,
                force_rls=False,
                policies=(),
            ),
        )
    )
    found = _run_rules(
        schema,
        config=Config(
            disable=["SEC001"],
            severity_overrides={"SEC001": "info"},
        ),
    )
    assert found == []


def test_run_rules_severity_override_remaps_what_survives_allowlist() -> None:
    # The allowlist filters inside the rule's check(); the override
    # remaps whatever survives. Table `a` is allowlisted out, `b` is
    # not — the single surviving SEC001 finding is remapped.
    schema = Schema(
        tables=(
            Table(
                schema="public",
                name="a",
                rls_enabled=False,
                force_rls=False,
                policies=(),
            ),
            Table(
                schema="public",
                name="b",
                rls_enabled=False,
                force_rls=False,
                policies=(),
            ),
        )
    )
    surviving = schema.tables[1]  # "public.b"
    found = _run_rules(
        schema,
        config=Config(
            rule_options={"SEC001": {"allowlist": ["a"]}},
            severity_overrides={"SEC001": "info"},
        ),
    )
    assert [(v.rule_id, v.location, v.severity) for v in found] == [
        ("SEC001", surviving.qualified_name, "info")
    ]


def test_run_rules_recursion_error_becomes_runtime_error(monkeypatch) -> None:
    # A rule whose check() blows the recursion limit (a pathologically
    # deep policy AST) must surface as a clean RuntimeError naming the
    # rule, not crash the whole lint run with a raw RecursionError.
    # Inject a registry with one rule that raises RecursionError so the
    # path is exercised without hand-crafting a thousand-deep AST.
    import pytest

    import pgrls.cli as cli_mod
    from pgrls.rules import RuleRegistry

    class _DeepRule:
        id = "DEEP001"
        severity = "error"
        title = "Always recurses"

        def check(self, schema, options):
            raise RecursionError("simulated deep AST")

    registry = RuleRegistry()
    registry.register(_DeepRule())
    monkeypatch.setattr(cli_mod, "default_registry", lambda: registry)

    schema = Schema(tables=())
    with pytest.raises(RuntimeError, match="DEEP001: policy AST too deep"):
        _run_rules(schema, config=Config())


def test_lint_severity_override_changes_exit_code(
    pg_url: str, apply_sql, tmp_path
) -> None:
    # An RLS-disabled table trips SEC001 (error). With the default
    # fail_on=warning that is exit 1. A `[lint.rules.SEC001]
    # severity = "info"` override demotes it below the threshold —
    # exit 0 — while the finding still prints, now at info.
    apply_sql("CREATE TABLE public.t (id INT);")
    runner = CliRunner()

    base = runner.invoke(main, ["lint", "--database-url", pg_url])
    assert base.exit_code == 1, base.output
    assert "SEC001" in base.output
    assert "ERROR" in base.output

    cfg = tmp_path / "pgrls.toml"
    cfg.write_text('[lint.rules.SEC001]\nseverity = "info"\n')
    overridden = runner.invoke(
        main, ["lint", "--database-url", pg_url, "--config", str(cfg)]
    )
    assert overridden.exit_code == 0, overridden.output
    # Still reported — the override demotes, it does not silence.
    assert "SEC001" in overridden.output
    assert "INFO" in overridden.output


def test_lint_schemas_flag_overrides_config(pg_url: str, apply_sql) -> None:
    apply_sql(
        """
        CREATE SCHEMA tenant;
        CREATE TABLE public.public_t (id INT);
        CREATE TABLE tenant.tenant_t (id INT);
        """
    )
    runner = CliRunner()
    result = runner.invoke(
        main, ["lint", "--database-url", pg_url, "--schemas", "tenant"]
    )
    assert result.exit_code == 1, result.output
    assert "tenant.tenant_t" in result.output
    assert "public.public_t" not in result.output


def test_lint_unknown_schema_errors_clearly(pg_url: str) -> None:
    runner = CliRunner()
    result = runner.invoke(
        main, ["lint", "--database-url", pg_url, "--schemas", "does_not_exist"]
    )
    assert result.exit_code != 0
    assert "does_not_exist" in result.output
    assert "Traceback" not in result.output


def test_lint_empty_schemas_errors_clearly(pg_url: str) -> None:
    runner = CliRunner()
    result = runner.invoke(
        main, ["lint", "--database-url", pg_url, "--schemas", ",,,"]
    )
    assert result.exit_code != 0
    assert "empty schema list" in result.output.lower()


def test_lint_bad_allowlist_type_errors_clearly(pg_url: str, tmp_path) -> None:
    cfg = tmp_path / "pgrls.toml"
    cfg.write_text(
        '[lint.rules.SEC001]\nallowlist = "users"\n'
    )
    runner = CliRunner()
    result = runner.invoke(
        main, ["lint", "--database-url", pg_url, "--config", str(cfg)]
    )
    assert result.exit_code != 0
    assert "Traceback" not in result.output
    assert "allowlist" in result.output


def test_lint_allowlist_via_config_exempts_table(pg_url: str, apply_sql, tmp_path) -> None:
    apply_sql((FIXTURES_DIR / "known_bad.sql").read_text())
    cfg = tmp_path / "pgrls.toml"
    cfg.write_text(
        '[lint.rules.SEC001]\nallowlist = ["users"]\n'
        '[lint.rules.SEC003]\nallowlist = ["public.orders.orders_owner"]\n'
    )
    runner = CliRunner()
    result = runner.invoke(
        main, ["lint", "--database-url", pg_url, "--config", str(cfg)]
    )
    assert result.exit_code == 0, result.output
    assert "SEC001" not in result.output


def test_lint_fail_on_info_flag_accepted(pg_url: str, apply_sql) -> None:
    apply_sql((FIXTURES_DIR / "known_bad.sql").read_text())
    runner = CliRunner()
    result = runner.invoke(
        main, ["lint", "--database-url", pg_url, "--fail-on", "info"]
    )
    assert result.exit_code == 1, result.output
    assert "SEC001" in result.output


def _violation(severity: str) -> Violation:
    return Violation(
        rule_id="X",
        severity=severity,  # type: ignore[arg-type]
        title="t",
        message="m",
        location=None,
    )


def test_should_fail_returns_true_when_violation_meets_threshold() -> None:
    assert _should_fail([_violation("error")], threshold="error") is True
    assert _should_fail([_violation("error")], threshold="warning") is True
    assert _should_fail([_violation("error")], threshold="info") is True
    assert _should_fail([_violation("warning")], threshold="warning") is True
    assert _should_fail([_violation("warning")], threshold="info") is True
    assert _should_fail([_violation("info")], threshold="info") is True


def test_should_fail_returns_false_below_threshold() -> None:
    assert _should_fail([_violation("warning")], threshold="error") is False
    assert _should_fail([_violation("info")], threshold="warning") is False
    assert _should_fail([_violation("info")], threshold="error") is False
    assert _should_fail([], threshold="info") is False


def test_merge_overrides_cli_takes_precedence_over_config() -> None:
    config = Config(
        database_url="postgres://config",
        schemas=["config_schema"],
        disable=[],
        fail_on="error",
        rule_options={},
    )
    merged = _merge_overrides(
        config,
        database_url="postgres://cli",
        schemas_csv="cli_a,cli_b",
        fail_on="warning",
    )
    assert merged.database_url == "postgres://cli"
    assert merged.schemas == ["cli_a", "cli_b"]
    assert merged.fail_on == "warning"


def test_merge_overrides_falls_back_to_config_when_cli_missing() -> None:
    config = Config(
        database_url="postgres://config",
        schemas=["config_schema"],
        disable=["X"],
        fail_on="error",
        rule_options={"R": {"k": "v"}},
    )
    merged = _merge_overrides(
        config, database_url=None, schemas_csv=None, fail_on=None
    )
    assert merged.database_url == "postgres://config"
    assert merged.schemas == ["config_schema"]
    assert merged.fail_on == "error"
    assert merged.disable == ["X"]
    assert merged.rule_options == {"R": {"k": "v"}}


def test_merge_overrides_preserves_diff_fail_on() -> None:
    # `_merge_overrides` is a lint-side helper, but every command
    # that goes through it (`lint`, `fix`, `snapshot`) must round-
    # trip every Config field. Dropping `diff_fail_on` would let
    # a hypothetical caller chain `lint`/`fix` and then `diff` and
    # silently lose the user's `[diff].fail_on` setting. Pin the
    # threading so a future refactor of the Config(...) constructor
    # call can't regress it.
    config = Config(
        database_url="postgres://config",
        schemas=["public"],
        disable=[],
        fail_on="warning",
        rule_options={},
        diff_fail_on="requires-review",
    )
    merged = _merge_overrides(
        config, database_url=None, schemas_csv=None, fail_on=None
    )
    assert merged.diff_fail_on == "requires-review"


def test_merge_overrides_preserves_extra_rules() -> None:
    # `pgrls lint` runs custom `[lint].extra_rules` via the merged
    # Config. Dropping the field here (the dataclass default is [])
    # makes `_run_rules` silently never run them while `explain` and
    # --rule validation still see them — a silent false-negative for
    # the documented SDK extension point. Pin the threading.
    config = Config(
        database_url="postgres://config",
        schemas=["public"],
        disable=[],
        fail_on="warning",
        rule_options={},
        extra_rules=["my_pkg.rules:TenantCheck"],
    )
    merged = _merge_overrides(
        config, database_url=None, schemas_csv=None, fail_on=None
    )
    assert merged.extra_rules == ["my_pkg.rules:TenantCheck"]


def test_introspect_populates_policy_using_ast(pg_url: str, apply_sql) -> None:
    apply_sql(
        """
        CREATE TABLE public.t (id INT, tenant_id TEXT);
        ALTER TABLE public.t ENABLE ROW LEVEL SECURITY;
        ALTER TABLE public.t FORCE ROW LEVEL SECURITY;
        CREATE POLICY p ON public.t
            FOR SELECT TO PUBLIC
            USING (tenant_id = current_setting('app.tenant_id'));
        """
    )
    import psycopg
    from pgrls.introspect import introspect

    with psycopg.connect(pg_url) as conn:
        schema = introspect(conn, schemas=["public"])

    table = next(t for t in schema.tables if t.name == "t")
    policy = table.policies[0]
    assert policy.using_sql is not None
    assert policy.using_ast is not None
    assert policy.with_check_sql is None
    assert policy.with_check_ast is None


def test_introspect_populates_table_columns(pg_url: str, apply_sql) -> None:
    apply_sql(
        """
        CREATE TABLE public.cols_test (id INT, email TEXT, tenant_id TEXT);
        """
    )
    import psycopg
    from pgrls.introspect import introspect

    with psycopg.connect(pg_url) as conn:
        schema = introspect(conn, schemas=["public"])

    table = next(t for t in schema.tables if t.name == "cols_test")
    assert table.columns == ("id", "email", "tenant_id")


def test_introspect_omits_dropped_columns(pg_url: str, apply_sql) -> None:
    apply_sql(
        """
        CREATE TABLE public.dropped_cols (id INT, gone TEXT, kept TEXT);
        ALTER TABLE public.dropped_cols DROP COLUMN gone;
        """
    )
    import psycopg
    from pgrls.introspect import introspect

    with psycopg.connect(pg_url) as conn:
        schema = introspect(conn, schemas=["public"])

    table = next(t for t in schema.tables if t.name == "dropped_cols")
    assert "gone" not in table.columns
    assert table.columns == ("id", "kept")


def test_lint_fires_sec002_on_missing_force(pg_url: str, apply_sql) -> None:
    apply_sql((FIXTURES_DIR / "sec002_bad.sql").read_text())
    runner = CliRunner()
    result = runner.invoke(main, ["lint", "--database-url", pg_url])
    assert result.exit_code == 1, result.output
    assert "SEC002" in result.output
    assert "public.sec002_target" in result.output
    # Both tables are RLS-on with FOR SELECT-only policies, so SEC022
    # fires on each — anchor the clean-table check to SEC002 itself.
    assert "SEC002  public.sec002_clean" not in result.output


def test_lint_sec002_allowlist_via_config_exempts(
    pg_url: str, apply_sql, tmp_path
) -> None:
    apply_sql((FIXTURES_DIR / "sec002_bad.sql").read_text())
    cfg = tmp_path / "pgrls.toml"
    cfg.write_text(
        '[lint.rules.SEC002]\nallowlist = ["sec002_target"]\n'
    )
    runner = CliRunner()
    result = runner.invoke(
        main, ["lint", "--database-url", pg_url, "--config", str(cfg)]
    )
    assert result.exit_code == 0, result.output
    assert "SEC002" not in result.output


def test_lint_sec002_fires_on_partition_child_with_self_enabled_rls(
    pg_url: str, apply_sql
) -> None:
    # Pins that SEC002 stays partition-agnostic: a partition child that
    # the operator explicitly RLS-enables but forgot to FORCE must fire,
    # regardless of whether the parent itself has FORCE. The semantics:
    # direct queries on the child use the child's own flags only, and
    # the operator opted into RLS on this specific child — they meant
    # to FORCE it too. A future regression that gives SEC002 the same
    # ancestor-suppression as SEC001 would silence this case incorrectly.
    apply_sql(
        """
        CREATE TABLE public.events (id INT, day DATE)
            PARTITION BY RANGE (day);
        CREATE TABLE public.events_2026 PARTITION OF public.events
            FOR VALUES FROM ('2026-01-01') TO ('2027-01-01');
        ALTER TABLE public.events ENABLE ROW LEVEL SECURITY;
        ALTER TABLE public.events FORCE ROW LEVEL SECURITY;
        ALTER TABLE public.events_2026 ENABLE ROW LEVEL SECURITY;
        -- Child intentionally lacks FORCE — owner can bypass on direct
        -- access to this partition. SEC002 must catch that.
        """
    )
    runner = CliRunner()
    result = runner.invoke(main, ["lint", "--database-url", pg_url])
    assert "SEC002  public.events_2026\n" in result.output
    # Parent has FORCE, so it must NOT fire.
    assert "SEC002  public.events\n" not in result.output


def test_lint_fires_sec003_on_permissive_public_policy(
    pg_url: str, apply_sql
) -> None:
    apply_sql((FIXTURES_DIR / "sec003_bad.sql").read_text())
    runner = CliRunner()
    result = runner.invoke(main, ["lint", "--database-url", pg_url])
    assert result.exit_code == 1, result.output
    assert "public.sec003_target.public_read" in result.output
    # Both tables are RLS-on with FOR SELECT-only policies, so SEC022
    # fires on each — anchor the clean-table check to SEC003 itself.
    assert "SEC003  public.sec003_clean" not in result.output
    # sec003_target has only one permissive PUBLIC policy → SEC003 +
    # SEC007 (info: no RESTRICTIVE floor). Both tables have only
    # FOR SELECT policies → SEC022 (info). sec003_clean is RESTRICTIVE.
    _assert_rules_fire_exactly(
        result.output, {"SEC003", "SEC007", "SEC022"}
    )


def test_lint_sec003_allowlist_via_config_exempts(
    pg_url: str, apply_sql, tmp_path
) -> None:
    apply_sql((FIXTURES_DIR / "sec003_bad.sql").read_text())
    cfg = tmp_path / "pgrls.toml"
    cfg.write_text(
        '[lint.rules.SEC003]\n'
        'allowlist = ["public.sec003_target.public_read"]\n'
    )
    runner = CliRunner()
    result = runner.invoke(
        main, ["lint", "--database-url", pg_url, "--config", str(cfg)]
    )
    assert "SEC003" not in result.output


def test_lint_sec006_fires_on_open_insert_not_reused_using(
    pg_url: str, apply_sql
) -> None:
    apply_sql((FIXTURES_DIR / "sec006_bad.sql").read_text())
    runner = CliRunner()
    result = runner.invoke(main, ["lint", "--database-url", pg_url])
    assert result.exit_code == 1, result.output
    # SEC006 fires on the genuinely-open write: a permissive INSERT with
    # no WITH CHECK and no USING for Postgres to reuse.
    assert "SEC006  public.sec006_open.open_insert" in result.output
    # SEC006 must NOT fire on permissive UPDATE/ALL with a real USING and
    # no WITH CHECK: Postgres reuses the USING as the implicit WITH CHECK,
    # so the write side is constrained. (Those policies still appear in the
    # output via other rules, so anchor the regression to the SEC006 line.)
    assert "SEC006  public.sec006_update.update_bad" not in result.output
    assert "SEC006  public.sec006_all.all_bad" not in result.output
    assert "public.sec006_clean" not in result.output
    # update_bad / all_bad / open_insert are permissive PUBLIC →
    # SEC003 + SEC007. update_bad / all_bad have unwrapped current_setting
    # → PERF001, and scope by a nullable `tenant_id` (TEXT) → SEC030.
    # insert_bad's WITH CHECK (true) has no own-col ref → SEC005, and is a
    # permissive write policy with a constant-true WITH CHECK → SEC028
    # (open write). open_insert (INSERT, no WITH CHECK) → SEC006.
    _assert_rules_fire_exactly(
        result.output,
        {
            "SEC003",
            "SEC005",
            "SEC006",
            "SEC007",
            "PERF001",
            "SEC028",
            "SEC030",
        },
    )


def test_lint_sec006_allowlist_via_config_exempts(
    pg_url: str, apply_sql, tmp_path
) -> None:
    apply_sql((FIXTURES_DIR / "sec006_bad.sql").read_text())
    cfg = tmp_path / "pgrls.toml"
    # open_insert is the only policy SEC006 fires on now (the reused-USING
    # update_bad / all_bad are correctly silent); allowlisting it suppresses
    # the rule entirely.
    cfg.write_text(
        '[lint.rules.SEC006]\n'
        'allowlist = ["public.sec006_open.open_insert"]\n'
    )
    runner = CliRunner()
    result = runner.invoke(
        main, ["lint", "--database-url", pg_url, "--config", str(cfg)]
    )
    assert "SEC006" not in result.output


def test_lint_fires_sec004_on_lovable_cve_pattern(
    pg_url: str, apply_sql
) -> None:
    apply_sql((FIXTURES_DIR / "sec004_bad.sql").read_text())
    runner = CliRunner()
    result = runner.invoke(main, ["lint", "--database-url", pg_url])
    assert result.exit_code == 1, result.output
    assert "public.sec004_target.inverted_auth" in result.output
    # Both tables are RLS-on with FOR SELECT-only policies, so SEC022
    # fires on each — anchor the clean-table check to SEC004 itself.
    assert "SEC004  public.sec004_clean" not in result.output
    # inverted_auth is permissive PUBLIC → SEC003 + SEC007 (only
    # permissive on the table). USING has unwrapped current_setting →
    # PERF001. Both tables have only FOR SELECT policies → SEC022
    # (info). sec004_clean policy is RESTRICTIVE so SEC003/SEC007
    # don't fire on that table. Both tables scope by a nullable
    # `user_id` (TEXT) against current_setting → SEC030 (the rule
    # detects the auth value whether bare on sec004_target or wrapped
    # in a sub-select on sec004_clean). SEC038 (semantic, Z3-backed)
    # co-fires with SEC004 on inverted_auth — the `current_setting()
    # IS NULL OR …` USING is provably anon-valid (TRUE for every row
    # under anon). Both detectors agreeing on the catastrophic leak.
    _assert_rules_fire_exactly(
        result.output,
        {"SEC003", "SEC004", "SEC007", "PERF001", "SEC022", "SEC030", "SEC038"},
    )


# --- --exclude-rule / --min-severity / --output --------------------------


def test_lint_exclude_rule_skips_named_rule(pg_url: str, apply_sql) -> None:
    apply_sql((FIXTURES_DIR / "sec004_bad.sql").read_text())
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["lint", "--database-url", pg_url, "--exclude-rule", "SEC003"],
    )
    # SEC003 is excluded; the rest of sec004_bad's findings remain.
    # SEC038 co-fires with SEC004 on the anon-valid inverted_auth USING.
    _assert_rules_fire_exactly(
        result.output,
        {"SEC004", "SEC007", "PERF001", "SEC022", "SEC030", "SEC038"},
    )


def test_lint_exclude_rule_unknown_id_exits_two() -> None:
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["lint", "--database-url", "x", "--exclude-rule", "SEC999"],
    )
    assert result.exit_code == 2
    assert "SEC999" in result.output


def test_lint_rule_and_exclude_rule_overlap_exits_two() -> None:
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "lint",
            "--database-url",
            "x",
            "--rule",
            "SEC003",
            "--exclude-rule",
            "SEC003",
        ],
    )
    assert result.exit_code == 2
    assert "both --rule and --exclude-rule" in result.output


def test_lint_min_severity_warning_hides_info(
    pg_url: str, apply_sql
) -> None:
    apply_sql((FIXTURES_DIR / "sec004_bad.sql").read_text())
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["lint", "--database-url", pg_url, "--min-severity", "warning"],
    )
    # Errors + the warning are shown; the info findings are hidden.
    assert "SEC004" in result.output  # error
    assert "PERF001" in result.output  # warning
    assert "SEC007" not in result.output  # info
    assert "SEC022" not in result.output  # info
    assert "SEC030" not in result.output  # info
    # Errors present → still exit 1.
    assert result.exit_code == 1


def test_lint_min_severity_filters_display_not_exit(
    pg_url: str, apply_sql
) -> None:
    # Scope to PERF001 (a warning) only, then hide warnings with
    # --min-severity error. The report shows nothing, but the run
    # still fails: the exit code evaluates the FULL finding set
    # against --fail-on (default warning), so a hidden finding can't
    # silently flip CI green.
    apply_sql((FIXTURES_DIR / "sec004_bad.sql").read_text())
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "lint",
            "--database-url",
            pg_url,
            "--rule",
            "PERF001",
            "--min-severity",
            "error",
        ],
    )
    assert "PERF001" not in result.output
    assert result.exit_code == 1


def test_lint_output_writes_report_to_file(
    pg_url: str, apply_sql, tmp_path
) -> None:
    apply_sql((FIXTURES_DIR / "sec004_bad.sql").read_text())
    runner = CliRunner()
    out = tmp_path / "report.txt"
    result = runner.invoke(
        main, ["lint", "--database-url", pg_url, "--output", str(out)]
    )
    assert result.exit_code == 1
    assert out.is_file()
    file_report = out.read_text(encoding="utf-8")
    assert "SEC004" in file_report
    # The report went to the file, not stdout.
    assert "SEC004" not in result.output
    # File is byte-for-byte what stdout would have received.
    stdout_run = runner.invoke(main, ["lint", "--database-url", pg_url])
    assert file_report == stdout_run.output
    # Byte-level: no newline translation (the `newline=""` write).
    # read_text would normalize \r\n→\n, so check raw bytes — this is
    # what pins the cross-platform guarantee.
    raw = out.read_bytes()
    assert b"\r\n" not in raw
    assert b"\n" in raw


def test_lint_output_unwritable_path_exits_two(
    pg_url: str, apply_sql, tmp_path
) -> None:
    # A path whose parent dir is missing surfaces a ToolError (exit 2)
    # with a message, not a traceback.
    apply_sql((FIXTURES_DIR / "sec004_bad.sql").read_text())
    runner = CliRunner()
    out = tmp_path / "missing_dir" / "report.txt"
    result = runner.invoke(
        main, ["lint", "--database-url", pg_url, "--output", str(out)]
    )
    assert result.exit_code == 2
    assert "Cannot write" in result.output


def test_lint_output_honors_format_and_min_severity(
    pg_url: str, apply_sql, tmp_path
) -> None:
    # --output composes with --format (the file gets SARIF) and with
    # --min-severity (the file gets the filtered report).
    apply_sql((FIXTURES_DIR / "sec004_bad.sql").read_text())
    runner = CliRunner()
    out = tmp_path / "report.sarif"
    result = runner.invoke(
        main,
        [
            "lint",
            "--database-url",
            pg_url,
            "--format",
            "sarif",
            "--min-severity",
            "warning",
            "--output",
            str(out),
        ],
    )
    assert result.exit_code == 1
    payload = json.loads(out.read_text(encoding="utf-8"))
    # Valid SARIF, and the info-level rules were filtered out of the
    # written report.
    assert payload["version"].startswith("2.1")
    flat = json.dumps(payload)
    assert "SEC004" in flat  # error, kept
    assert "SEC007" not in flat  # info, filtered


def test_lint_output_with_update_baseline_exits_two(tmp_path) -> None:
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "lint",
            "--database-url",
            "x",
            "--output",
            str(tmp_path / "r.txt"),
            "--update-baseline",
            "--baseline",
            str(tmp_path / "b.json"),
        ],
    )
    assert result.exit_code == 2
    assert "--output and --update-baseline cannot be combined" in result.output


def test_lint_sec004_auth_functions_override_suppresses(
    pg_url: str, apply_sql, tmp_path
) -> None:
    apply_sql((FIXTURES_DIR / "sec004_bad.sql").read_text())
    cfg = tmp_path / "pgrls.toml"
    cfg.write_text(
        '[lint.rules.SEC004]\nauth_functions = ["my.custom_auth"]\n'
    )
    runner = CliRunner()
    # Exclude SEC038 here: this test pins SEC004's auth_functions
    # override, but SEC038 (the semantic sibling) fires on the same
    # inverted_auth policy with its own default auth set and its finding
    # message cross-references "SEC004" in prose — which would defeat the
    # bare-substring assertion below. SEC038's own override is covered by
    # tests/rules/test_sec038.py.
    result = runner.invoke(
        main,
        [
            "lint",
            "--database-url", pg_url,
            "--config", str(cfg),
            "--exclude-rule", "SEC038",
        ],
    )
    assert "SEC004" not in result.output


def test_lint_fires_hyg001_on_orphaned_column_ref(
    pg_url: str, apply_sql
) -> None:
    # Simulate the orphaned-column state: the column 'gone' is marked as
    # dropped in pg_attribute (Postgres 16+ prevents DROP COLUMN when a
    # policy depends on it, so we replicate the internal state directly).
    # Postgres renders dropped column refs as '?dropped?column?' in pg_get_expr.
    apply_sql((FIXTURES_DIR / "hyg001_bad.sql").read_text())
    runner = CliRunner()
    result = runner.invoke(main, ["lint", "--database-url", pg_url])
    assert result.exit_code == 1, result.output
    assert "public.hyg001_target.orphaned" in result.output
    assert "?dropped?column?" in result.output
    # Both tables are RLS-on with FOR SELECT-only policies, so SEC022
    # fires on each — anchor the clean-table check to HYG001 itself.
    assert "HYG001  public.hyg001_clean" not in result.output
    # `orphaned` is permissive PUBLIC → SEC003 + SEC007 (only permissive
    # on the table). The dropped column is excluded from table.columns,
    # so SEC005 fires too — the policy has no live own-col ref. HYG001
    # is the headline. Both tables have only FOR SELECT policies →
    # SEC022 (info). hyg001_clean is RESTRICTIVE.
    _assert_rules_fire_exactly(
        result.output,
        {"SEC003", "SEC005", "SEC007", "HYG001", "SEC022"},
    )


def test_lint_does_not_fire_sec001_on_child_of_rls_enabled_parent(
    pg_url: str, apply_sql
) -> None:
    # Postgres declarative partitioning: parent has RLS + a tenant policy,
    # children inherit it at query time. Before the partition fix,
    # introspection skipped the parent (relkind='p') and SEC001 falsely
    # fired on every child because their relrowsecurity is independently
    # false. With the fix the parent is visible AND SEC001 walks
    # `partition_of` to recognize ancestor coverage.
    apply_sql(
        """
        CREATE TABLE public.events (id BIGINT, tenant_id UUID, day DATE)
            PARTITION BY RANGE (day);
        CREATE TABLE public.events_2026 PARTITION OF public.events
            FOR VALUES FROM ('2026-01-01') TO ('2027-01-01');
        ALTER TABLE public.events ENABLE ROW LEVEL SECURITY;
        ALTER TABLE public.events FORCE ROW LEVEL SECURITY;
        CREATE POLICY tenant_read ON public.events FOR SELECT TO PUBLIC
            USING (tenant_id = current_setting('app.t', true)::uuid);
        """
    )
    runner = CliRunner()
    result = runner.invoke(main, ["lint", "--database-url", pg_url])
    # No SEC001/SEC002 on parent or child.
    assert "SEC001  public.events" not in result.output
    assert "SEC002  public.events" not in result.output
    # SEC003 still fires on the parent's permissive PUBLIC policy — that
    # behavior is untouched by the partition fix and is correct.
    assert "SEC003  public.events.tenant_read\n" in result.output


def test_lint_fires_sec001_on_partition_child_when_parent_has_no_rls(
    pg_url: str, apply_sql
) -> None:
    # Conservative side of the suppression: when no ancestor has RLS,
    # SEC001 still fires on every level — parent and child.
    apply_sql(
        """
        CREATE TABLE public.events (id INT, day DATE)
            PARTITION BY RANGE (day);
        CREATE TABLE public.events_2026 PARTITION OF public.events
            FOR VALUES FROM ('2026-01-01') TO ('2027-01-01');
        """
    )
    runner = CliRunner()
    result = runner.invoke(main, ["lint", "--database-url", pg_url])
    assert "SEC001  public.events\n" in result.output
    assert "SEC001  public.events_2026\n" in result.output


def test_lint_emits_unscoped_chain_message_when_parent_in_unscoped_schema(
    pg_url: str, apply_sql
) -> None:
    # End-to-end coverage of the differentiated SEC001 message: parent
    # lives in a schema not passed to `--schemas`, so pgrls cannot
    # verify upstream RLS coverage. The unit test in test_sec001.py
    # builds Schema by hand; this test exercises the real Postgres
    # path including pg_inherits resolution across schemas.
    apply_sql(
        """
        CREATE SCHEMA private;
        CREATE TABLE private.events (id INT, day DATE)
            PARTITION BY RANGE (day);
        ALTER TABLE private.events ENABLE ROW LEVEL SECURITY;
        ALTER TABLE private.events FORCE ROW LEVEL SECURITY;
        CREATE TABLE public.events_2026 PARTITION OF private.events
            FOR VALUES FROM ('2026-01-01') TO ('2027-01-01');
        """
    )
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["lint", "--database-url", pg_url, "--schemas", "public"],
    )
    assert "SEC001  public.events_2026" in result.output
    assert "leaves the scanned schemas" in result.output
    # The classic message must NOT appear for this child — the rule
    # was specifically refactored to differentiate the two.
    classic_for_child = (
        "Table public.events_2026 does not have row-level security"
    )
    assert classic_for_child not in result.output


def test_lint_partition_x_sec003_fires_on_parent_policy(
    pg_url: str, apply_sql
) -> None:
    # Cross-rule integration: when partition suppression silences
    # SEC001 on a child, the per-policy rules must still fire on the
    # parent's policies. Pins that partition awareness is scoped to
    # SEC001 and doesn't leak into SEC003/SEC008 (the two that fire
    # on a `USING (true) TO PUBLIC` permissive policy).
    apply_sql(
        """
        CREATE TABLE public.events (id INT, tenant_id UUID, day DATE)
            PARTITION BY RANGE (day);
        CREATE TABLE public.events_2026 PARTITION OF public.events
            FOR VALUES FROM ('2026-01-01') TO ('2027-01-01');
        ALTER TABLE public.events ENABLE ROW LEVEL SECURITY;
        ALTER TABLE public.events FORCE ROW LEVEL SECURITY;
        CREATE POLICY all_read ON public.events
            FOR SELECT TO PUBLIC USING (true);
        """
    )
    runner = CliRunner()
    result = runner.invoke(main, ["lint", "--database-url", pg_url])
    # SEC001 quiet on both parent (RLS enabled) and child (ancestor
    # covers).
    assert "SEC001  public.events\n" not in result.output
    assert "SEC001  public.events_2026" not in result.output
    # Per-policy rules fire on the parent's policy.
    assert "SEC003  public.events.all_read\n" in result.output
    assert "SEC008  public.events.all_read\n" in result.output
    # Children have no policies of their own → no per-policy rules
    # touch them.
    assert "SEC003  public.events_2026" not in result.output
    assert "SEC008  public.events_2026" not in result.output


def test_lint_handles_partition_cycle_with_clean_error(
    pg_url: str, monkeypatch
) -> None:
    # Postgres cannot produce a cycle in pg_inherits; only corrupted
    # introspection state can. The CLI catches `ValueError` from the
    # rule loop and turns it into a ClickException — pin that the
    # path is exercised by something, since it is otherwise
    # unreachable from any real database. Patch `introspect` to hand
    # back a hand-built cycle Schema and verify the CLI exits cleanly
    # without a Python traceback in the output.
    import pgrls.cli as cli_mod
    from pgrls.model import Schema, Table

    a = Table(
        schema="public",
        name="a",
        rls_enabled=False,
        force_rls=False,
        policies=(),
        partition_of=("public", "b"),
    )
    b = Table(
        schema="public",
        name="b",
        rls_enabled=False,
        force_rls=False,
        policies=(),
        partition_of=("public", "a"),
    )
    cycle = Schema(tables=(a, b))
    monkeypatch.setattr(
        cli_mod, "introspect", lambda conn, schemas: cycle
    )

    runner = CliRunner()
    result = runner.invoke(main, ["lint", "--database-url", pg_url])
    assert result.exit_code != 0
    assert "cycle" in result.output.lower()
    # ClickException prints the message; an unhandled exception would
    # leak a Python traceback. Pin the absence.
    assert "Traceback" not in result.output


def test_lint_fires_every_registered_rule_in_combined_fixture(
    pg_url: str, apply_sql
) -> None:
    # Cross-rule combined fixture — every shipped rule must fire
    # at least once. Renaming from "every rule" to "every
    # registered rule" makes the contract explicit: when a new
    # rule is added to default_registry(), this test fails until
    # all_bad.sql gets a block that triggers it. Catches a class
    # of silent under-coverage drift (e.g., when SEC011, PERF002,
    # HYG002 were added to the registry but missing from the
    # then-current fixture).
    #
    # all_bad.sql's SEC016 block creates a cluster-global BYPASSRLS
    # role (roles are not reset by the per-test schema teardown); the
    # `finally` drops it so it can't leak into the shared container
    # and trip SEC016 in the clean-DB e2e test. The SEC023 block
    # grants a policy TO that role, recording a
    # SHARED_DEPENDENCY_POLICY entry that blocks DROP ROLE — so the
    # `finally` drops the public schema (cascading the policy) first.
    try:
        apply_sql((FIXTURES_DIR / "all_bad.sql").read_text())
        runner = CliRunner()
        result = runner.invoke(main, ["lint", "--database-url", pg_url])
        assert result.exit_code == 1, result.output
        from pgrls.diff._z3_compare import Z3_AVAILABLE
        from pgrls.rules import all_rules

        # HYG004 (policy has no behavioral test) and PERF005 (RLS table
        # observed to seq-scan) are artifact-gated: they only fire when
        # `pgrls lint --coverage` / `--perf` supplies an artifact, which a
        # plain lint of all_bad.sql doesn't. Exempt them from the "every
        # rule fires" contract — their firing is covered by
        # tests/rules/test_hyg004.py / test_perf005.py and the integration
        # tests in tests/test_perf.py.
        #
        # SEC038 (semantic anon-read) uses z3-solver, a core dependency
        # since 0.16.0, so it fires wherever pgrls is installed. The
        # Z3_AVAILABLE check stays as a defensive guard: if z3 is somehow
        # absent the rule NO-OPs, so drop it from the expected set (and the
        # pinned-location assertion below) in that case.
        expected = {r.id for r in all_rules()} - {"HYG004", "PERF005"}
        if not Z3_AVAILABLE:
            expected -= {"SEC038"}
        _assert_rules_fire_exactly(result.output, expected)
        # Pin each (rule, location) pair to its intended target.
        # Substring plus trailing newline anchors against the
        # output's `RULE  LOC\n` shape (formatters/text.py) so a
        # rule drifting onto the wrong policy fails loudly instead
        # of silently slipping by. SEC016's location is a bare role
        # name — roles have no schema, so no `public.` prefix.
        for rule_loc in (
            "SEC001  public.allbad_sec001\n",
            "SEC002  public.allbad_sec002\n",
            "SEC003  public.allbad_sec003.public_perm\n",
            "SEC004  public.allbad_sec004.inverted\n",
            "SEC005  public.allbad_sec003.public_perm\n",
            "SEC005  public.allbad_hyg001.orphan\n",
            "SEC005  public.allbad_sec010.block_all\n",
            "SEC006  public.allbad_sec006.insert_dead\n",
            "SEC007  public.allbad_sec003\n",
            "SEC008  public.allbad_sec003.public_perm\n",
            "SEC009  public.allbad_sec002\n",
            "SEC010  public.allbad_sec010.block_all\n",
            "SEC011  public.allbad_sec011.or_true_bypass\n",
            "SEC013  public.allbad_sec013.audit_writes\n",
            "SEC016  allbad_sec016_role\n",
            "SEC017  public.allbad_sec017_leaky\n",
            "SEC018  public.allbad_sec018.owner_is_current_user\n",
            "SEC019  public.allbad_sec019.tenant_scope\n",
            "SEC020  public.allbad_sec020.open_write_check\n",
            "SEC021  public.allbad_sec021.tenant_pinned\n",
            "SEC022  public.allbad_sec022\n",
            "SEC023  public.allbad_sec023.bypassed_grant\n",
            "SEC024  public.allbad_sec024.tenant_scope\n",
            "SEC025  public.allbad_sec025.tenant_scope\n",
            "SEC026  public.allbad_sec026.email_pattern\n",
            "SEC027  public.allbad_sec027\n",
            "SEC028  public.allbad_sec028.open_insert\n",
            "SEC029  allbad_sec029_member\n",
            "SEC030  public.allbad_sec030\n",
            "SEC031  public.allbad_sec031.restrictive_noop\n",
            "SEC032  public.allbad_sec032\n",
            "SEC039  public.allbad_sec039.anon_insert\n",
            "PERF001  public.allbad_sec004.inverted\n",
            "PERF003  public.allbad_perf003.tenant_unindexed\n",
            "PERF004  public.allbad_perf004.by_email\n",
            "PERF001  public.allbad_sec006.update_no_check\n",
            "PERF002  public.allbad_perf002.randomized\n",
            "HYG001  public.allbad_hyg001.orphan\n",
            "HYG002  public.allbad_hyg002.todo_replace_me_later\n",
            "HYG003  public.allbad_hyg003.tenant_scope_b\n",
            "VIEW001  public.allbad_view001\n",
            "VIEW002  public.allbad_view002\n",
            "VIEW003  public.allbad_view003\n",
            "VIEW004  public.allbad_view004\n",
        ):
            assert rule_loc in result.output, (
                f"{rule_loc!r} missing from output:\n{result.output}"
            )
        # SEC038's pinned location is gated behind the optional z3 extra
        # (see the expected-set guard above): with z3 it fires on the
        # NOT-wrapped inverted-auth policy; without it the rule NO-OPs.
        if Z3_AVAILABLE:
            sec038_loc = "SEC038  public.allbad_sec038.anon_read\n"
            assert sec038_loc in result.output, (
                f"{sec038_loc!r} missing from output:\n{result.output}"
            )
    finally:
        # Drop the schema before the role: the SEC023 policy's
        # TO clause makes the role undroppable until its policy is
        # gone. The next test's pg_conn fixture resets the schema
        # anyway; recreating it here just leaves a sane state.
        apply_sql(
            "DROP SCHEMA IF EXISTS public CASCADE; "
            "CREATE SCHEMA public; "
            "DROP ROLE IF EXISTS allbad_sec029_member; "
            "DROP ROLE IF EXISTS allbad_sec016_role; "
            "DROP ROLE IF EXISTS anon"
        )


# ============================================================
# `pgrls lint --rule` integration tests
# ============================================================


def test_lint_rule_filter_limits_to_requested_rule(
    pg_url: str, apply_sql
) -> None:
    # Two RLS issues on two tables: SEC001 (RLS off) on one,
    # SEC003 (permissive PUBLIC policy) on the other. `--rule
    # SEC001` runs SEC001 only — SEC003 is filtered out.
    apply_sql(
        """
        CREATE TABLE public.lint_filter_a (id INT);
        -- ^ SEC001: RLS not enabled

        CREATE TABLE public.lint_filter_b (id INT);
        ALTER TABLE public.lint_filter_b ENABLE ROW LEVEL SECURITY;
        ALTER TABLE public.lint_filter_b FORCE ROW LEVEL SECURITY;
        CREATE POLICY p ON public.lint_filter_b
            FOR SELECT TO PUBLIC USING (id > 0);
        -- ^ SEC003: permissive policy granted to PUBLIC
        """
    )
    runner = CliRunner()
    result = runner.invoke(
        main, ["lint", "--database-url", pg_url, "--rule", "SEC001"]
    )
    assert "SEC001" in result.output
    assert "lint_filter_a" in result.output
    # SEC003 was filtered out — neither the rule ID nor the
    # offending table appears in the output.
    assert "SEC003" not in result.output
    assert "lint_filter_b" not in result.output


def test_lint_rule_filter_is_case_insensitive(
    pg_url: str, apply_sql
) -> None:
    # `--rule sec001` resolves the same as `--rule SEC001`.
    apply_sql("CREATE TABLE public.lint_filter_case (id INT);")
    runner = CliRunner()
    lower = runner.invoke(
        main, ["lint", "--database-url", pg_url, "--rule", "sec001"]
    )
    upper = runner.invoke(
        main, ["lint", "--database-url", pg_url, "--rule", "SEC001"]
    )
    # Both runs find SEC001 on the same table, exit code identical.
    assert lower.exit_code == upper.exit_code
    assert "SEC001" in lower.output


def test_lint_rule_filter_unknown_rule_errors_clearly(
    pg_url: str, apply_sql
) -> None:
    # `--rule SEC999` is a typo. Validate eagerly so the user sees
    # the typo rather than a quiet empty result. Mirrors
    # `pgrls fix --rule`'s validation.
    apply_sql("CREATE TABLE public.lint_filter_unknown (id INT);")
    runner = CliRunner()
    result = runner.invoke(
        main, ["lint", "--database-url", pg_url, "--rule", "SEC999"]
    )
    assert result.exit_code == 2
    assert "unknown rule" in result.output.lower()
    assert "SEC999" in result.output

    # A known rule alongside an unknown does not mask the typo,
    # and the error lists every unknown ID so a multi-typo command
    # doesn't need multiple rounds to fix.
    multi = runner.invoke(
        main,
        [
            "lint", "--database-url", pg_url,
            "--rule", "SEC001", "--rule", "SEC999", "--rule", "BOGUS",
        ],
    )
    assert multi.exit_code == 2
    assert "SEC999" in multi.output
    assert "BOGUS" in multi.output


def test_lint_rule_filter_repeatable(
    pg_url: str, apply_sql
) -> None:
    # `--rule X --rule Y` runs both rules; everything else is
    # filtered out.
    apply_sql(
        """
        CREATE TABLE public.lint_filter_multi_a (id INT);
        -- ^ SEC001
        CREATE TABLE public.lint_filter_multi_b (id INT);
        ALTER TABLE public.lint_filter_multi_b ENABLE ROW LEVEL SECURITY;
        ALTER TABLE public.lint_filter_multi_b FORCE ROW LEVEL SECURITY;
        CREATE POLICY p ON public.lint_filter_multi_b
            FOR SELECT TO PUBLIC USING (id > 0);
        -- ^ SEC003
        """
    )
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "lint", "--database-url", pg_url,
            "--rule", "SEC001", "--rule", "SEC003",
        ],
    )
    assert "SEC001" in result.output
    assert "SEC003" in result.output


def test_lint_rule_filter_overrides_disable(
    pg_url: str, apply_sql, tmp_path
) -> None:
    # `--rule` is an explicit "run only these" — it overrides
    # `[lint] disable` so an operator can pull a disabled rule
    # back in for one run without editing the config.
    apply_sql("CREATE TABLE public.lint_filter_override (id INT);")
    config = tmp_path / "pgrls.toml"
    config.write_text('[lint]\ndisable = ["SEC001"]\n')

    runner = CliRunner()
    # Without `--rule`, the disabled SEC001 stays silent.
    silent = runner.invoke(
        main,
        [
            "lint", "--database-url", pg_url,
            "--config", str(config),
        ],
    )
    assert "SEC001" not in silent.output

    # `--rule SEC001` overrides the disable — SEC001 runs and
    # fires on the table.
    forced = runner.invoke(
        main,
        [
            "lint", "--database-url", pg_url,
            "--config", str(config), "--rule", "SEC001",
        ],
    )
    assert "SEC001" in forced.output
    assert "lint_filter_override" in forced.output


# ============================================================
# `pgrls lint --explain` integration tests
# ============================================================


def test_lint_explain_appends_rule_rationale_to_text_output(
    pg_url: str, apply_sql
) -> None:
    # SEC001-tripping fixture. `--explain` should append the
    # rule's reference paragraph beneath the finding so a CI log
    # carries the why next to the where.
    apply_sql("CREATE TABLE public.lint_explain_target (id INT);")
    runner = CliRunner()
    plain = runner.invoke(main, ["lint", "--database-url", pg_url])
    explained = runner.invoke(
        main, ["lint", "--database-url", pg_url, "--explain"]
    )
    assert "SEC001" in plain.output
    assert "SEC001" in explained.output
    # The explained output must be strictly longer (the rationale
    # was appended) and contain a substring that lives ONLY in
    # SEC001's docstring — not its message template. `pg_class
    # .relrowsecurity` is the catalog column SEC001's detection
    # paragraph describes; the violation message uses prose
    # ("does not have row-level security enabled") and never
    # mentions the catalog column.
    assert len(explained.output) > len(plain.output)
    assert "pg_class.relrowsecurity" in explained.output
    assert "pg_class.relrowsecurity" not in plain.output


def test_lint_explain_is_silent_when_no_findings(
    pg_url: str, apply_sql
) -> None:
    # A clean fixture produces "no issues found." regardless of
    # --explain — with no violations there's nothing to explain.
    # Use the canonical clean shape (RLS+FORCE, a PERMISSIVE
    # FOR ALL + a RESTRICTIVE floor, PRIMARY KEY) so SEC007 and
    # SEC022 stay silent too.
    apply_sql(
        """
        CREATE TABLE public.lint_explain_clean (id INT PRIMARY KEY);
        ALTER TABLE public.lint_explain_clean ENABLE ROW LEVEL SECURITY;
        ALTER TABLE public.lint_explain_clean FORCE ROW LEVEL SECURITY;
        CREATE POLICY perm ON public.lint_explain_clean
            FOR ALL TO postgres USING (id > 0) WITH CHECK (id > 0);
        CREATE POLICY restrict_floor ON public.lint_explain_clean
            AS RESTRICTIVE FOR ALL TO PUBLIC
            USING (id > 0) WITH CHECK (id > 0);
        """
    )
    runner = CliRunner()
    result = runner.invoke(
        main, ["lint", "--database-url", pg_url, "--explain"]
    )
    assert result.exit_code == 0
    assert "no issues" in result.output.lower()


def test_lint_explain_only_affects_text_format(
    pg_url: str, apply_sql
) -> None:
    # --explain is text-only — the structured formats keep their
    # schemas stable so downstream parsers don't see a new field
    # appear conditionally.
    apply_sql("CREATE TABLE public.lint_explain_json (id INT);")
    runner = CliRunner()
    plain = runner.invoke(
        main,
        ["lint", "--database-url", pg_url, "--format", "json"],
    )
    explained = runner.invoke(
        main,
        [
            "lint", "--database-url", pg_url,
            "--format", "json", "--explain",
        ],
    )
    # The JSON outputs are byte-identical — --explain is ignored
    # for non-text formats.
    assert plain.output == explained.output


def test_lint_format_github_emits_workflow_command(
    pg_url: str, apply_sql
) -> None:
    # `--format github` emits a GitHub Actions workflow command per
    # finding. An RLS-disabled table trips SEC001 (error severity),
    # which maps to `::error` with the rule id + location in the
    # title.
    apply_sql("CREATE TABLE public.lint_github_target (id INT);")
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["lint", "--database-url", pg_url, "--format", "github"],
    )
    # Findings present ⇒ exit 1 under the default fail-on; the test
    # pins the OUTPUT shape, not the code.
    assert result.exit_code == 1, result.output
    assert "::error title=SEC001 public.lint_github_target::" in result.output


def test_lint_format_github_clean_db_emits_nothing(
    pg_url: str, apply_sql
) -> None:
    # No findings ⇒ no annotations. The github format stays silent
    # on a clean run (unlike text/markdown, which print a
    # "no issues found" line).
    apply_sql(
        """
        CREATE TABLE public.lint_github_clean (id INT PRIMARY KEY);
        ALTER TABLE public.lint_github_clean ENABLE ROW LEVEL SECURITY;
        ALTER TABLE public.lint_github_clean FORCE ROW LEVEL SECURITY;
        CREATE POLICY perm ON public.lint_github_clean
            FOR ALL TO postgres USING (id > 0) WITH CHECK (id > 0);
        CREATE POLICY restrict_floor ON public.lint_github_clean
            AS RESTRICTIVE FOR ALL TO PUBLIC
            USING (id > 0) WITH CHECK (id > 0);
        """
    )
    runner = CliRunner()
    result = runner.invoke(
        main, ["lint", "--database-url", pg_url, "--format", "github"]
    )
    assert result.exit_code == 0, result.output
    assert "::" not in result.output


# ============================================================
# `pgrls lint --baseline` integration tests
# ============================================================

def test_lint_baseline_first_run_writes_file(
    pg_url: str, apply_sql, tmp_path
) -> None:
    # An RLS-disabled table trips SEC001. The first --baseline run
    # records the finding and exits 0; the file is created.
    apply_sql("CREATE TABLE public.legacy (id INT);")
    baseline = tmp_path / "pgrls-baseline.json"
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["lint", "--database-url", pg_url, "--baseline", str(baseline)],
    )
    assert result.exit_code == 0, result.output
    assert baseline.exists()
    payload = json.loads(baseline.read_text(encoding="utf-8"))
    assert any(f["rule_id"] == "SEC001" for f in payload["findings"])


def test_lint_baseline_first_run_json_format_emits_valid_json(
    pg_url: str, apply_sql, tmp_path
) -> None:
    # A first --baseline run under --format json must still emit a
    # valid (empty-findings) JSON document to stdout — a `| jq`
    # pipeline must not choke on the run that creates the baseline.
    apply_sql("CREATE TABLE public.legacy (id INT);")
    baseline = tmp_path / "b.json"
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "lint",
            "--database-url",
            pg_url,
            "--baseline",
            str(baseline),
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 0, result.output
    # stdout (only) parses as JSON — the new-findings view, empty
    # on the first run since every finding was just baselined.
    # `result.stdout` excludes the stderr "wrote baseline" note.
    json.loads(result.stdout)


def test_lint_baseline_suppresses_recorded_findings(
    pg_url: str, apply_sql, tmp_path
) -> None:
    # First run records the SEC001 finding; a second run against
    # the same database suppresses it — exit 0, nothing reported.
    apply_sql("CREATE TABLE public.legacy (id INT);")
    baseline = tmp_path / "b.json"
    runner = CliRunner()
    first = runner.invoke(
        main,
        ["lint", "--database-url", pg_url, "--baseline", str(baseline)],
    )
    assert first.exit_code == 0, first.output
    second = runner.invoke(
        main,
        ["lint", "--database-url", pg_url, "--baseline", str(baseline)],
    )
    assert second.exit_code == 0, second.output
    assert "SEC001" not in second.output


def test_lint_baseline_fails_on_new_finding(
    pg_url: str, apply_sql, tmp_path
) -> None:
    # Two RLS-disabled tables both trip SEC001. The baseline records
    # only `public.legacy`; `public.fresh` is a NEW finding and must
    # fail the run.
    apply_sql(
        """
        CREATE TABLE public.legacy (id INT);
        CREATE TABLE public.fresh (id INT);
        """
    )
    baseline = tmp_path / "b.json"
    baseline.write_text(
        json.dumps(
            {
                "version": 1,
                "generated_by": "pgrls test",
                "findings": [
                    {"rule_id": "SEC001", "location": "public.legacy"}
                ],
            }
        ),
        encoding="utf-8",
    )
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["lint", "--database-url", pg_url, "--baseline", str(baseline)],
    )
    assert result.exit_code == 1, result.output
    assert "public.fresh" in result.output
    # `public.legacy` is baselined — suppressed from the report.
    assert "public.legacy" not in result.output


def test_lint_baseline_notes_stale_entries(
    pg_url: str, apply_sql, tmp_path
) -> None:
    # A baseline entry that matches no current finding is stale —
    # the run notes it on stderr so the operator can regenerate.
    apply_sql("CREATE TABLE public.legacy (id INT);")
    baseline = tmp_path / "b.json"
    baseline.write_text(
        json.dumps(
            {
                "version": 1,
                "generated_by": "pgrls test",
                "findings": [
                    {"rule_id": "SEC001", "location": "public.legacy"},
                    {
                        "rule_id": "SEC001",
                        "location": "public.long_gone",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["lint", "--database-url", pg_url, "--baseline", str(baseline)],
    )
    assert result.exit_code == 0, result.output
    assert "no longer match" in result.output


def test_lint_baseline_malformed_file_errors_clearly(
    pg_url: str, apply_sql, tmp_path
) -> None:
    apply_sql("CREATE TABLE public.legacy (id INT);")
    baseline = tmp_path / "b.json"
    baseline.write_text("{ not json", encoding="utf-8")
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["lint", "--database-url", pg_url, "--baseline", str(baseline)],
    )
    assert result.exit_code != 0
    assert "baseline" in result.output.lower()


def test_lint_baseline_first_run_unwritable_path_errors_clearly(
    pg_url: str, apply_sql, tmp_path
) -> None:
    # First `--baseline` run (file absent) tries to WRITE the baseline.
    # When the target path is unwritable (parent dir doesn't exist),
    # `write_baseline` raises BaselineError, which `_apply_baseline`
    # turns into a ToolError (exit 2) with a clear message — not a
    # traceback. Distinct from the `--update-baseline` write path
    # (already covered): this is the auto-create-on-first-run write.
    apply_sql("CREATE TABLE public.legacy (id INT);")
    baseline = tmp_path / "missing_dir" / "b.json"
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["lint", "--database-url", pg_url, "--baseline", str(baseline)],
    )
    assert result.exit_code == 2, result.output
    assert "baseline" in result.output.lower()
    assert "Traceback" not in result.output


def test_lint_update_baseline_requires_baseline_flag() -> None:
    # --update-baseline names the *action*; --baseline names the
    # *file*. Without the latter there is no target — surface a
    # clear tool error rather than guessing.
    runner = CliRunner()
    result = runner.invoke(
        main, ["lint", "--database-url", "x", "--update-baseline"]
    )
    assert result.exit_code == 2
    assert "--update-baseline" in result.output
    assert "--baseline" in result.output


def test_lint_update_baseline_creates_file_when_absent(
    pg_url: str, apply_sql, tmp_path
) -> None:
    # A first --update-baseline run with a missing file writes the
    # baseline from scratch — same end state as the first-run
    # `--baseline` path, but the user typed the explicit verb.
    apply_sql("CREATE TABLE public.update_baseline_a (id INT);")
    baseline = tmp_path / "fresh.json"
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "lint", "--database-url", pg_url,
            "--baseline", str(baseline), "--update-baseline",
        ],
    )
    assert result.exit_code == 0, result.output
    assert baseline.exists()
    payload = json.loads(baseline.read_text(encoding="utf-8"))
    assert any(f["rule_id"] == "SEC001" for f in payload["findings"])
    # Status message names the file and the count.
    assert "updated baseline" in result.output
    assert str(baseline) in result.output


def test_lint_update_baseline_replaces_existing_baseline(
    pg_url: str, apply_sql, tmp_path
) -> None:
    # Write a stale baseline first (containing entries for tables
    # that no longer exist in the DB). After --update-baseline,
    # the file reflects current findings only — stale entries
    # are dropped (REPLACE semantics, not MERGE).
    baseline = tmp_path / "stale.json"
    baseline.write_text(
        json.dumps(
            {
                "version": 1,
                "tool_version": "0.0.0",
                "findings": [
                    {
                        "rule_id": "SEC001",
                        "location": "public.never_existed",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    # The actual DB has a different SEC001-tripping table.
    apply_sql("CREATE TABLE public.update_baseline_b (id INT);")
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "lint", "--database-url", pg_url,
            "--baseline", str(baseline), "--update-baseline",
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(baseline.read_text(encoding="utf-8"))
    locs = {f["location"] for f in payload["findings"]}
    # The stale entry is gone.
    assert "public.never_existed" not in locs
    # The current finding is recorded.
    assert "public.update_baseline_b" in locs


def test_lint_update_baseline_exits_zero_even_with_findings(
    pg_url: str, apply_sql, tmp_path
) -> None:
    # The user is *recording*, not gating — exit 0 regardless of
    # the finding count and irrespective of --fail-on.
    apply_sql("CREATE TABLE public.update_baseline_c (id INT);")
    baseline = tmp_path / "b.json"
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "lint", "--database-url", pg_url,
            "--baseline", str(baseline),
            "--update-baseline",
            "--fail-on", "info",
        ],
    )
    assert result.exit_code == 0, result.output


def test_lint_update_baseline_composes_with_rule_filter(
    pg_url: str, apply_sql, tmp_path
) -> None:
    # `--rule` narrows the lint scope; that scope flows through
    # to `--update-baseline` too. The recorded baseline contains
    # ONLY the rule(s) the user asked for — replace semantics
    # mean other rules' findings are dropped from the file. Pin
    # that behaviour: an operator who composes the two flags is
    # explicitly asking for a scoped baseline.
    apply_sql(
        """
        CREATE TABLE public.update_baseline_filter_a (id INT);
        -- ^ SEC001 (RLS off)
        CREATE TABLE public.update_baseline_filter_b (id INT);
        ALTER TABLE public.update_baseline_filter_b ENABLE ROW LEVEL SECURITY;
        CREATE POLICY p ON public.update_baseline_filter_b
            FOR SELECT TO PUBLIC USING (id > 0);
        -- ^ SEC003 (permissive PUBLIC)
        """
    )
    baseline = tmp_path / "scoped.json"
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "lint", "--database-url", pg_url,
            "--baseline", str(baseline),
            "--update-baseline",
            "--rule", "SEC001",
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(baseline.read_text(encoding="utf-8"))
    rule_ids = {f["rule_id"] for f in payload["findings"]}
    # Only the in-scope rule was recorded; SEC003's finding on
    # the other table didn't make it.
    assert rule_ids == {"SEC001"}


def test_lint_update_baseline_unwritable_path_errors_clearly(
    pg_url: str, apply_sql, tmp_path
) -> None:
    # `write_baseline` raises BaselineError when the target file
    # can't be written; the lint command wraps that as a tool
    # error (exit 2). A non-existent parent directory triggers
    # the same path without depending on filesystem permissions.
    apply_sql("CREATE TABLE public.update_baseline_unwritable (id INT);")
    bad_path = tmp_path / "no" / "such" / "dir" / "b.json"
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "lint", "--database-url", pg_url,
            "--baseline", str(bad_path), "--update-baseline",
        ],
    )
    assert result.exit_code == 2, result.output


def test_lint_update_baseline_with_json_format_emits_no_stdout(
    pg_url: str, apply_sql, tmp_path
) -> None:
    # The output suppression is format-agnostic — a user passing
    # `--format json --update-baseline` should not see a stray
    # JSON document on stdout (the run is recording, not
    # formatting findings).
    apply_sql("CREATE TABLE public.update_baseline_json (id INT);")
    baseline = tmp_path / "b.json"
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "lint", "--database-url", pg_url,
            "--baseline", str(baseline),
            "--update-baseline",
            "--format", "json",
        ],
    )
    assert result.exit_code == 0, result.output
    assert result.stdout == ""
    assert "updated baseline" in result.stderr


def test_lint_update_baseline_suppresses_normal_lint_output(
    pg_url: str, apply_sql, tmp_path
) -> None:
    # The status message lives on stderr; stdout (the lint-format
    # channel) is empty, so a CI step capturing stdout to a log
    # doesn't see a misleading "findings" listing on an
    # update-baseline run.
    apply_sql("CREATE TABLE public.update_baseline_d (id INT);")
    baseline = tmp_path / "b.json"
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "lint", "--database-url", pg_url,
            "--baseline", str(baseline), "--update-baseline",
        ],
    )
    assert result.exit_code == 0
    # The status line is on stderr; the lint-output channel
    # (stdout) is empty under --update-baseline.
    assert result.stdout == ""
    assert "updated baseline" in result.stderr


# ============================================================
# `pgrls fix` integration tests
# ============================================================

def test_fix_dry_run_emits_sec002_sql_without_applying(
    pg_url: str, apply_sql
) -> None:
    apply_sql(
        """
        CREATE TABLE public.fix_target (id INT);
        ALTER TABLE public.fix_target ENABLE ROW LEVEL SECURITY;
        -- FORCE intentionally missing → SEC002 fixable
        CREATE POLICY p ON public.fix_target
            FOR SELECT TO postgres USING (id > 0);
        """
    )
    runner = CliRunner()
    result = runner.invoke(
        main, ["fix", "--database-url", pg_url]
    )
    assert result.exit_code == 0, result.output
    # SQL was printed but not executed.
    assert "ALTER TABLE public.fix_target FORCE ROW LEVEL SECURITY;" in result.output
    assert "dry-run" in result.output

    # Verify the DB was NOT modified — connect and check force_rls.
    import psycopg
    with psycopg.connect(pg_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT relforcerowsecurity FROM pg_catalog.pg_class "
                "WHERE oid = 'public.fix_target'::regclass"
            )
            (force,) = cur.fetchone()
            assert force is False


def test_fix_apply_executes_sec002_sql(
    pg_url: str, apply_sql
) -> None:
    apply_sql(
        """
        CREATE TABLE public.fix_apply_target (id INT PRIMARY KEY);
        ALTER TABLE public.fix_apply_target ENABLE ROW LEVEL SECURITY;
        CREATE POLICY p ON public.fix_apply_target
            FOR SELECT TO postgres USING (id > 0);
        """
    )
    runner = CliRunner()
    result = runner.invoke(
        main, ["fix", "--database-url", pg_url, "--apply"]
    )
    assert result.exit_code == 0, result.output
    assert "applied 1 fix" in result.output

    # Verify the DB WAS modified.
    import psycopg
    with psycopg.connect(pg_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT relforcerowsecurity FROM pg_catalog.pg_class "
                "WHERE oid = 'public.fix_apply_target'::regclass"
            )
            (force,) = cur.fetchone()
            assert force is True


def test_fix_rule_filter_limits_to_requested_rule(
    pg_url: str, apply_sql
) -> None:
    apply_sql(
        """
        CREATE TABLE public.fix_filter_a (id INT);
        ALTER TABLE public.fix_filter_a ENABLE ROW LEVEL SECURITY;
        CREATE POLICY p ON public.fix_filter_a
            FOR SELECT TO postgres USING (id > 0);
        -- ^ SEC002 fixable

        CREATE TABLE public.fix_filter_b (id INT, user_id TEXT);
        ALTER TABLE public.fix_filter_b ENABLE ROW LEVEL SECURITY;
        ALTER TABLE public.fix_filter_b FORCE ROW LEVEL SECURITY;
        CREATE POLICY p ON public.fix_filter_b
            AS RESTRICTIVE FOR SELECT TO PUBLIC
            USING (user_id = current_setting('app.user', true));
        -- ^ PERF001 fixable
        """
    )
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "fix", "--database-url", pg_url,
            "--rule", "SEC002",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "fix_filter_a" in result.output
    assert "fix_filter_b" not in result.output


def test_fix_no_violations_emits_clear_message(
    pg_url: str, apply_sql
) -> None:
    apply_sql(
        """
        CREATE TABLE public.fix_clean (id INT PRIMARY KEY);
        ALTER TABLE public.fix_clean ENABLE ROW LEVEL SECURITY;
        ALTER TABLE public.fix_clean FORCE ROW LEVEL SECURITY;
        CREATE POLICY p ON public.fix_clean
            FOR SELECT TO postgres USING (id > 0);
        """
    )
    runner = CliRunner()
    result = runner.invoke(
        main, ["fix", "--database-url", pg_url]
    )
    assert result.exit_code == 0, result.output
    assert "no auto-fixable" in result.output


def test_fix_missing_database_url_errors_clearly(monkeypatch) -> None:
    monkeypatch.delenv("DATABASE_URL", raising=False)
    runner = CliRunner()
    result = runner.invoke(main, ["fix"])
    assert result.exit_code != 0
    assert "DATABASE_URL" in result.output or "database-url" in result.output


def test_fix_database_connection_error_exits_2_cleanly() -> None:
    # A connection that fails at the psycopg layer surfaces as a
    # ToolError (exit 2) with a "Database error" prefix, not a raw
    # traceback. Pins the `except psycopg.Error` branch in `fix`.
    runner = CliRunner()
    result = runner.invoke(main, ["fix", "--database-url", _BAD_SOCKET_URL])
    assert result.exit_code == 2, result.output
    assert "Database error" in result.output
    assert "Traceback" not in result.output


def test_fix_unknown_schema_exits_2_cleanly(pg_url: str) -> None:
    # An unknown schema makes `introspect` raise ValueError inside the
    # connection block; `fix` converts it to a ToolError (exit 2) via
    # its `except ValueError` branch — not a traceback.
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["fix", "--database-url", pg_url, "--schemas", "no_such_schema"],
    )
    assert result.exit_code == 2, result.output
    assert "no_such_schema" in result.output
    assert "Traceback" not in result.output


def test_fix_bad_toml_exits_2_not_1(tmp_path) -> None:
    # A malformed config file is a ConfigError, surfaced as a ToolError
    # (exit 2) before any DB connection — the same clean-error contract
    # `pgrls lint` follows for bad TOML. Pins `fix`'s `except
    # ConfigError` branch.
    cfg = tmp_path / "pgrls.toml"
    cfg.write_text("[database\n")  # malformed TOML
    runner = CliRunner()
    result = runner.invoke(main, ["fix", "--config", str(cfg)])
    assert result.exit_code == 2, result.output
    assert "Traceback" not in result.output


def test_fix_bad_toml_precedes_unknown_rule(tmp_path) -> None:
    # When --config is malformed AND --rule names an unknown rule, the
    # config-parse error must win — matching the pre-refactor fix()
    # error order (config, then --rule, then db-url). Pins the
    # precedence so the connect/introspect preamble dedup cannot
    # silently reorder which of several simultaneous user errors
    # surfaces first.
    cfg = tmp_path / "pgrls.toml"
    cfg.write_text("[database\n")  # malformed TOML
    runner = CliRunner()
    result = runner.invoke(
        main, ["fix", "--config", str(cfg), "--rule", "BOGUS"]
    )
    assert result.exit_code == 2, result.output
    # The config-parse error, NOT "unknown auto-fixable rule(s): BOGUS".
    assert "unknown auto-fixable rule" not in result.output
    assert "Traceback" not in result.output


def test_fix_apply_handles_multiple_fixes(
    pg_url: str, apply_sql
) -> None:
    # Two SEC002-fixable tables. `--apply` runs both ALTER TABLE
    # statements in one shot.
    apply_sql(
        """
        CREATE TABLE public.fix_multi_a (id INT);
        ALTER TABLE public.fix_multi_a ENABLE ROW LEVEL SECURITY;
        CREATE POLICY p ON public.fix_multi_a
            FOR SELECT TO postgres USING (id > 0);

        CREATE TABLE public.fix_multi_b (id INT);
        ALTER TABLE public.fix_multi_b ENABLE ROW LEVEL SECURITY;
        CREATE POLICY p ON public.fix_multi_b
            FOR SELECT TO postgres USING (id > 0);
        """
    )
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["fix", "--database-url", pg_url, "--rule", "SEC002", "--apply"],
    )
    assert result.exit_code == 0, result.output
    assert "applied 2 fixes" in result.output

    import psycopg
    with psycopg.connect(pg_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT relname FROM pg_catalog.pg_class "
                "WHERE relrowsecurity AND relforcerowsecurity "
                "AND relname LIKE 'fix_multi_%' "
                "ORDER BY relname"
            )
            assert [row[0] for row in cur.fetchall()] == [
                "fix_multi_a",
                "fix_multi_b",
            ]


def test_fix_emits_sec001_enable_rls(pg_url: str, apply_sql) -> None:
    # `pgrls fix` with no --rule filter picks up the SEC001 fixer
    # and emits ENABLE ROW LEVEL SECURITY for an RLS-less table.
    apply_sql("CREATE TABLE public.fix_sec001 (id INT);")
    runner = CliRunner()
    result = runner.invoke(main, ["fix", "--database-url", pg_url])
    assert result.exit_code == 0, result.output
    assert (
        "ALTER TABLE public.fix_sec001 ENABLE ROW LEVEL SECURITY;"
        in result.output
    )
    assert "dry-run" in result.output


def test_fix_emits_sec006_with_check(pg_url: str, apply_sql) -> None:
    # `pgrls fix` picks up the SEC006 fixer and emits an
    # ALTER POLICY … WITH CHECK mirroring the USING predicate of a
    # write-side policy that has no WITH CHECK.
    apply_sql(
        """
        CREATE TABLE public.fix_sec006 (id INT);
        ALTER TABLE public.fix_sec006 ENABLE ROW LEVEL SECURITY;
        ALTER TABLE public.fix_sec006 FORCE ROW LEVEL SECURITY;
        CREATE POLICY p ON public.fix_sec006
            FOR ALL TO postgres USING (id > 0);
        """
    )
    runner = CliRunner()
    result = runner.invoke(main, ["fix", "--database-url", pg_url])
    assert result.exit_code == 0, result.output
    assert "ALTER POLICY p ON public.fix_sec006" in result.output
    assert "WITH CHECK (id > 0)" in result.output
    assert "dry-run" in result.output


def test_fix_emits_sec020_with_check(pg_url: str, apply_sql) -> None:
    # `pgrls fix` picks up the SEC020 fixer and emits an
    # ALTER POLICY … WITH CHECK that replaces a constant-true
    # WITH CHECK with the policy's own USING predicate.
    apply_sql(
        """
        CREATE TABLE public.fix_sec020 (id INT PRIMARY KEY);
        ALTER TABLE public.fix_sec020 ENABLE ROW LEVEL SECURITY;
        ALTER TABLE public.fix_sec020 FORCE ROW LEVEL SECURITY;
        CREATE POLICY p ON public.fix_sec020
            FOR ALL TO postgres USING (id > 0) WITH CHECK (true);
        """
    )
    runner = CliRunner()
    result = runner.invoke(main, ["fix", "--database-url", pg_url])
    assert result.exit_code == 0, result.output
    assert "ALTER POLICY p ON public.fix_sec020" in result.output
    assert "WITH CHECK (id > 0)" in result.output
    assert "dry-run" in result.output


def test_fix_apply_executes_sec020_with_check(
    pg_url: str, apply_sql
) -> None:
    apply_sql(
        """
        CREATE TABLE public.fix_sec020_apply (id INT PRIMARY KEY);
        ALTER TABLE public.fix_sec020_apply ENABLE ROW LEVEL SECURITY;
        ALTER TABLE public.fix_sec020_apply FORCE ROW LEVEL SECURITY;
        CREATE POLICY p ON public.fix_sec020_apply
            FOR ALL TO postgres USING (id > 0) WITH CHECK (true);
        """
    )
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["fix", "--database-url", pg_url, "--rule", "SEC020", "--apply"],
    )
    assert result.exit_code == 0, result.output
    assert "applied 1 fix" in result.output

    # The constant-true WITH CHECK was replaced by the USING
    # predicate — pg_policies.with_check now carries `id > 0`.
    import psycopg
    with psycopg.connect(pg_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT with_check FROM pg_catalog.pg_policies "
                "WHERE schemaname = 'public' "
                "AND tablename = 'fix_sec020_apply' "
                "AND policyname = 'p'"
            )
            (with_check,) = cur.fetchone()
    assert with_check is not None
    assert "id > 0" in with_check
    assert "true" not in with_check.lower()


def test_fix_emits_sec019_missing_ok(pg_url: str, apply_sql) -> None:
    # `pgrls fix` picks up the SEC019 fixer and emits an
    # ALTER POLICY that adds `, true` to a one-argument
    # current_setting() call. The call is wrapped in
    # `(SELECT …)` so PERF001 stays silent and SEC019 is the
    # only fixer that fires on this fixture.
    apply_sql(
        """
        CREATE TABLE public.fix_sec019 (id INT PRIMARY KEY, tenant_id TEXT);
        ALTER TABLE public.fix_sec019 ENABLE ROW LEVEL SECURITY;
        ALTER TABLE public.fix_sec019 FORCE ROW LEVEL SECURITY;
        CREATE POLICY p ON public.fix_sec019
            FOR SELECT TO postgres
            USING (
                tenant_id = (SELECT current_setting('app.tenant'))
            );
        CREATE INDEX fix_sec019_t_idx ON public.fix_sec019 (tenant_id);
        """
    )
    runner = CliRunner()
    result = runner.invoke(main, ["fix", "--database-url", pg_url])
    assert result.exit_code == 0, result.output
    assert "[SEC019]" in result.output
    assert "ALTER POLICY p ON public.fix_sec019" in result.output
    # The rewrite added `, TRUE` as the second arg. (pglast
    # renders the literal in uppercase; the deparsed string
    # literal uses CAST(...) rather than the `::text` shorthand,
    # so just pin the comma + TRUE pair as the marker.)
    assert ", TRUE)" in result.output
    assert "dry-run" in result.output


def test_fix_apply_executes_sec019_missing_ok(
    pg_url: str, apply_sql
) -> None:
    apply_sql(
        """
        CREATE TABLE public.fix_sec019_apply (id INT PRIMARY KEY, tenant_id TEXT);
        ALTER TABLE public.fix_sec019_apply ENABLE ROW LEVEL SECURITY;
        ALTER TABLE public.fix_sec019_apply FORCE ROW LEVEL SECURITY;
        CREATE POLICY p ON public.fix_sec019_apply
            FOR SELECT TO postgres
            USING (
                tenant_id = (SELECT current_setting('app.tenant'))
            );
        CREATE INDEX fix_sec019_apply_t_idx
            ON public.fix_sec019_apply (tenant_id);
        """
    )
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["fix", "--database-url", pg_url, "--rule", "SEC019", "--apply"],
    )
    assert result.exit_code == 0, result.output
    assert "applied 1 fix" in result.output

    # The policy's qual (USING) now carries the two-argument
    # current_setting form. `pg_policies.qual` is deparsed by
    # Postgres itself; both args must appear, separated by a
    # comma, with the boolean second arg.
    import psycopg
    with psycopg.connect(pg_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT qual FROM pg_catalog.pg_policies "
                "WHERE schemaname = 'public' "
                "AND tablename = 'fix_sec019_apply' "
                "AND policyname = 'p'"
            )
            (qual,) = cur.fetchone()
    assert qual is not None
    assert "current_setting" in qual
    assert "'app.tenant'" in qual
    # Before fix: one-arg call (no `true` in the qual).
    # After fix: two-arg with `true` as the missing_ok argument.
    assert "true" in qual.lower()


def test_fix_emits_sec011_strip_or_true(pg_url: str, apply_sql) -> None:
    # `pgrls fix` picks up the SEC011 fixer and emits an ALTER
    # POLICY that strips the `OR true` debug bypass. The remaining
    # predicate (tenant_id = ...) references the table's own column,
    # so the only thing that changed is the dropped disjunct.
    apply_sql(
        """
        CREATE TABLE public.fix_sec011 (id INT PRIMARY KEY, tenant_id TEXT);
        ALTER TABLE public.fix_sec011 ENABLE ROW LEVEL SECURITY;
        ALTER TABLE public.fix_sec011 FORCE ROW LEVEL SECURITY;
        CREATE POLICY p ON public.fix_sec011
            FOR SELECT TO postgres
            USING (tenant_id = 'acme' OR true);
        CREATE INDEX fix_sec011_t_idx ON public.fix_sec011 (tenant_id);
        """
    )
    runner = CliRunner()
    result = runner.invoke(
        main, ["fix", "--database-url", pg_url, "--rule", "SEC011"]
    )
    assert result.exit_code == 0, result.output
    assert "[SEC011]" in result.output
    assert "ALTER POLICY p ON public.fix_sec011" in result.output
    # The bypass disjunct is gone; the real predicate remains.
    # Postgres deparses the string literal via pg_get_expr as
    # `CAST('acme' AS text)`, so pin that form. The trailing
    # `OR true);` would be present if the strip had not run — its
    # absence (distinct from the description's "OR true`") confirms
    # the rewrite.
    assert "USING (tenant_id = CAST('acme' AS text))" in result.output
    assert "OR true);" not in result.output
    assert "dry-run" in result.output


def test_fix_apply_executes_sec011_strip_or_true(
    pg_url: str, apply_sql
) -> None:
    apply_sql(
        """
        CREATE TABLE public.fix_sec011_apply (id INT PRIMARY KEY, tenant_id TEXT);
        ALTER TABLE public.fix_sec011_apply ENABLE ROW LEVEL SECURITY;
        ALTER TABLE public.fix_sec011_apply FORCE ROW LEVEL SECURITY;
        CREATE POLICY p ON public.fix_sec011_apply
            FOR SELECT TO postgres
            USING (tenant_id = 'acme' OR true);
        CREATE INDEX fix_sec011_apply_t_idx
            ON public.fix_sec011_apply (tenant_id);
        """
    )
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["fix", "--database-url", pg_url, "--rule", "SEC011", "--apply"],
    )
    assert result.exit_code == 0, result.output
    assert "applied 1 fix" in result.output

    # The policy's qual no longer carries the constant-true bypass.
    # `pg_policies.qual` is deparsed by Postgres itself.
    import psycopg
    with psycopg.connect(pg_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT qual FROM pg_catalog.pg_policies "
                "WHERE schemaname = 'public' "
                "AND tablename = 'fix_sec011_apply' "
                "AND policyname = 'p'"
            )
            (qual,) = cur.fetchone()
    assert qual is not None
    assert "'acme'" in qual
    # The OR-true disjunct is gone — Postgres would render a kept
    # `OR true` as `OR true`; after the fix the qual is a bare
    # equality with no disjunction.
    assert "true" not in qual.lower()
    assert " or " not in qual.lower()


def test_fix_emits_hyg003_drop_policy(pg_url: str, apply_sql) -> None:
    # `pgrls fix` picks up the HYG003 fixer and emits a DROP POLICY
    # for a policy that exactly duplicates another on the same
    # table. The name-sorted-first policy ('p_a') is kept as the
    # original; the redundant twin ('p_b') is dropped.
    apply_sql(
        """
        CREATE TABLE public.fix_hyg003 (id INT);
        ALTER TABLE public.fix_hyg003 ENABLE ROW LEVEL SECURITY;
        ALTER TABLE public.fix_hyg003 FORCE ROW LEVEL SECURITY;
        CREATE POLICY p_a ON public.fix_hyg003
            FOR SELECT TO postgres USING (id > 0);
        CREATE POLICY p_b ON public.fix_hyg003
            FOR SELECT TO postgres USING (id > 0);
        """
    )
    runner = CliRunner()
    result = runner.invoke(main, ["fix", "--database-url", pg_url])
    assert result.exit_code == 0, result.output
    assert "DROP POLICY p_b ON public.fix_hyg003;" in result.output
    # The kept original is never dropped.
    assert "DROP POLICY p_a" not in result.output
    assert "dry-run" in result.output


def test_fix_apply_drops_duplicate_hyg003_policy(
    pg_url: str, apply_sql
) -> None:
    # HYG003 is the first DROP-emitting fixer — verify --apply
    # actually removes the redundant policy from the live catalog
    # and leaves the original in place.
    apply_sql(
        """
        CREATE TABLE public.fix_hyg003_apply (id INT PRIMARY KEY);
        ALTER TABLE public.fix_hyg003_apply ENABLE ROW LEVEL SECURITY;
        ALTER TABLE public.fix_hyg003_apply FORCE ROW LEVEL SECURITY;
        CREATE POLICY p_a ON public.fix_hyg003_apply
            FOR SELECT TO postgres USING (id > 0);
        CREATE POLICY p_b ON public.fix_hyg003_apply
            FOR SELECT TO postgres USING (id > 0);
        """
    )
    runner = CliRunner()
    result = runner.invoke(
        main, ["fix", "--database-url", pg_url, "--apply"]
    )
    assert result.exit_code == 0, result.output
    assert "applied 1 fix" in result.output

    # Exactly the duplicate is gone; the original survives.
    import psycopg
    with psycopg.connect(pg_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT policyname FROM pg_catalog.pg_policies "
                "WHERE schemaname = 'public' "
                "AND tablename = 'fix_hyg003_apply' "
                "ORDER BY policyname"
            )
            assert [r[0] for r in cur.fetchall()] == ["p_a"]


def test_fix_emits_perf003_create_index(pg_url: str, apply_sql) -> None:
    # `pgrls fix` picks up the PERF003 fixer and emits a plain
    # CREATE INDEX for a policy-predicate column that has no
    # leading-column index.
    apply_sql(
        """
        CREATE TABLE public.fix_perf003 (id INT, tenant_id TEXT);
        ALTER TABLE public.fix_perf003 ENABLE ROW LEVEL SECURITY;
        ALTER TABLE public.fix_perf003 FORCE ROW LEVEL SECURITY;
        CREATE POLICY p ON public.fix_perf003
            FOR ALL TO postgres
            USING (tenant_id = (SELECT current_setting('app.t', true)))
            WITH CHECK (tenant_id = (SELECT current_setting('app.t', true)));
        """
    )
    runner = CliRunner()
    result = runner.invoke(main, ["fix", "--database-url", pg_url])
    assert result.exit_code == 0, result.output
    assert "CREATE INDEX IF NOT EXISTS pgrls_idx_" in result.output
    assert "ON public.fix_perf003 (tenant_id);" in result.output
    assert "dry-run" in result.output


def test_fix_apply_creates_perf003_index(pg_url: str, apply_sql) -> None:
    # The PERF003 fixer emits a plain (non-CONCURRENT) CREATE INDEX,
    # so it runs inside `--apply`'s single transaction. Verify the
    # index actually lands on the table.
    #
    # `tenant_id` is declared NOT NULL so the SEC030 fixer (added in
    # v0.6.15) doesn't piggyback an ALTER COLUMN onto this test —
    # the assertion below expects exactly one fix (the PERF003
    # index) and the fixture is about PERF003 specifically.
    apply_sql(
        """
        CREATE TABLE public.fix_perf003_apply
            (id INT, tenant_id TEXT NOT NULL);
        ALTER TABLE public.fix_perf003_apply ENABLE ROW LEVEL SECURITY;
        ALTER TABLE public.fix_perf003_apply FORCE ROW LEVEL SECURITY;
        CREATE POLICY p ON public.fix_perf003_apply
            FOR ALL TO postgres
            USING (tenant_id = (SELECT current_setting('app.t', true)))
            WITH CHECK (tenant_id = (SELECT current_setting('app.t', true)));
        """
    )
    runner = CliRunner()
    result = runner.invoke(
        main, ["fix", "--database-url", pg_url, "--apply"]
    )
    assert result.exit_code == 0, result.output
    assert "applied 1 fix" in result.output

    # The index now exists on the table.
    import psycopg
    with psycopg.connect(pg_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT indexdef FROM pg_indexes "
                "WHERE schemaname = 'public' "
                "AND tablename = 'fix_perf003_apply'"
            )
            defs = [r[0] for r in cur.fetchall()]
    assert any("tenant_id" in d for d in defs), defs


def test_fix_apply_is_idempotent(pg_url: str, apply_sql) -> None:
    # First --apply executes; second --apply finds nothing to do.
    apply_sql(
        """
        CREATE TABLE public.fix_idempotent (id INT PRIMARY KEY);
        ALTER TABLE public.fix_idempotent ENABLE ROW LEVEL SECURITY;
        CREATE POLICY p ON public.fix_idempotent
            FOR SELECT TO postgres USING (id > 0);
        """
    )
    runner = CliRunner()
    first = runner.invoke(
        main, ["fix", "--database-url", pg_url, "--apply"]
    )
    assert first.exit_code == 0
    assert "applied 1 fix" in first.output

    second = runner.invoke(
        main, ["fix", "--database-url", pg_url, "--apply"]
    )
    assert second.exit_code == 0
    assert "no auto-fixable" in second.output


def test_fix_unknown_rule_filter_errors_clearly(
    pg_url: str, apply_sql
) -> None:
    # `--rule SEC999` is a typo. Producing zero fixes silently
    # would be indistinguishable from "DB is clean" — confusing.
    # Validate eagerly and tell the user which rules are
    # auto-fixable.
    apply_sql(
        """
        CREATE TABLE public.fix_unknown (id INT);
        ALTER TABLE public.fix_unknown ENABLE ROW LEVEL SECURITY;
        CREATE POLICY p ON public.fix_unknown
            FOR SELECT TO postgres USING (id > 0);
        """
    )
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["fix", "--database-url", pg_url, "--rule", "SEC999"],
    )
    assert result.exit_code != 0
    assert "unknown auto-fixable rule" in result.output
    assert "SEC999" in result.output
    # The error message should list the actually-fixable rules
    # so the user can spot their typo.
    assert "SEC002" in result.output
    assert "PERF001" in result.output
    assert "VIEW001" in result.output
    assert "VIEW002" in result.output


def test_fix_rule_filter_normalizes_case(
    pg_url: str, apply_sql
) -> None:
    # `--rule sec002` is the same as `--rule SEC002` — mirrors the
    # case-insensitive contract on `[lint].disable`,
    # `[lint.rules.<ID>]`, `--fail-on`, etc. Without normalization,
    # lowercase input would error with "unknown auto-fixable rule"
    # even though the rule exists.
    apply_sql(
        """
        CREATE TABLE public.fix_case_norm (id INT);
        ALTER TABLE public.fix_case_norm ENABLE ROW LEVEL SECURITY;
        CREATE POLICY p ON public.fix_case_norm
            AS RESTRICTIVE FOR SELECT TO PUBLIC USING (id > 0);
        """
    )
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["fix", "--database-url", pg_url, "--rule", "sec002"],
    )
    assert result.exit_code == 0
    # SEC002 emits ALTER TABLE … FORCE ROW LEVEL SECURITY; the
    # canonical fix output should reach stdout despite the
    # lowercase input.
    assert "FORCE ROW LEVEL SECURITY" in result.output


def test_fix_unknown_rule_does_not_block_known_rule_in_same_invocation(
    pg_url: str, apply_sql
) -> None:
    # `--rule SEC002 --rule SEC999` — one valid, one typo. The
    # validation rejects the whole invocation rather than silently
    # filtering out the typo.
    apply_sql(
        """
        CREATE TABLE public.fix_mixed (id INT);
        ALTER TABLE public.fix_mixed ENABLE ROW LEVEL SECURITY;
        CREATE POLICY p ON public.fix_mixed
            FOR SELECT TO postgres USING (id > 0);
        """
    )
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "fix",
            "--database-url", pg_url,
            "--rule", "SEC002",
            "--rule", "SEC999",
        ],
    )
    assert result.exit_code != 0
    assert "SEC999" in result.output


def test_fix_apply_rolls_back_on_statement_failure(
    pg_url: str, apply_sql, monkeypatch
) -> None:
    # Force the second SEC002 fix to fail at execute time and
    # confirm that the all-or-nothing semantic holds: the first
    # fix is rolled back, the user sees a clear ClickException
    # with the offending (rule_id, location), and exit code is
    # nonzero.
    apply_sql(
        """
        CREATE TABLE public.fix_rollback_a (id INT);
        ALTER TABLE public.fix_rollback_a ENABLE ROW LEVEL SECURITY;
        CREATE POLICY p ON public.fix_rollback_a
            FOR SELECT TO postgres USING (id > 0);

        CREATE TABLE public.fix_rollback_b (id INT);
        ALTER TABLE public.fix_rollback_b ENABLE ROW LEVEL SECURITY;
        CREATE POLICY p ON public.fix_rollback_b
            FOR SELECT TO postgres USING (id > 0);
        """
    )

    # Inject a fixer that returns a deliberately-broken second
    # statement so we can observe rollback.
    from pgrls.fixers import Fix
    import pgrls.cli as cli_mod

    real_generate = cli_mod.generate_fixes

    def fake(schema, *, rule_options, rule_filter=None):
        real = real_generate(
            schema, rule_options=rule_options, rule_filter=rule_filter
        )
        # Replace the second SEC002 fix with one that will fail at
        # execute time (table doesn't exist).
        out: list[Fix] = []
        for i, f in enumerate(real):
            if i == 1 and f.rule_id == "SEC002":
                out.append(
                    Fix(
                        rule_id="SEC002",
                        location="public.does_not_exist",
                        sql="ALTER TABLE public.does_not_exist FORCE ROW LEVEL SECURITY;",
                        description="will fail",
                    )
                )
            else:
                out.append(f)
        return out

    monkeypatch.setattr(cli_mod, "generate_fixes", fake)
    # Pin that the patch actually replaced the symbol cli.py
    # references; if a future refactor changes the import shape
    # to `import pgrls.fixers as F; F.generate_fixes(...)` the
    # monkeypatch would silently no-op and this test would pass
    # vacuously. The assert below catches that.
    assert cli_mod.generate_fixes is fake

    runner = CliRunner()
    result = runner.invoke(
        main,
        ["fix", "--database-url", pg_url, "--rule", "SEC002", "--apply"],
    )
    assert result.exit_code != 0
    assert "fix 2/2 failed" in result.output
    assert "public.does_not_exist" in result.output
    assert "No fixes were applied" in result.output

    # The first fix's table should NOT have FORCE applied — proving
    # rollback worked.
    import psycopg
    with psycopg.connect(pg_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT relforcerowsecurity FROM pg_catalog.pg_class "
                "WHERE oid = 'public.fix_rollback_a'::regclass"
            )
            (force,) = cur.fetchone()
            assert force is False, "rollback failed: fix 1's change persisted"


def test_fix_routes_sql_to_stdout_and_status_to_stderr(
    pg_url: str, apply_sql
) -> None:
    # `pgrls fix > migration.sql` must produce a clean SQL file —
    # no "dry-run" status lines mixed in. Status messages go to
    # stderr; SQL bodies (and their `-- [rule] description`
    # comments) go to stdout.
    apply_sql(
        """
        CREATE TABLE public.fix_streams (id INT);
        ALTER TABLE public.fix_streams ENABLE ROW LEVEL SECURITY;
        CREATE POLICY p ON public.fix_streams
            FOR SELECT TO postgres USING (id > 0);
        """
    )
    # Click 8.2 dropped the `mix_stderr` kwarg; stderr is exposed
    # separately on the result by default.
    runner = CliRunner()
    result = runner.invoke(main, ["fix", "--database-url", pg_url])
    assert result.exit_code == 0, result.output
    # SQL body lands on stdout.
    assert (
        "ALTER TABLE public.fix_streams FORCE ROW LEVEL SECURITY;"
        in result.stdout
    )
    # Status messages land on stderr.
    assert "dry-run" in result.stderr
    assert "dry-run" not in result.stdout


def test_fix_output_writes_migration_file(
    pg_url: str, apply_sql, tmp_path
) -> None:
    # `pgrls fix --output FILE` writes the remediation SQL to a
    # migration-ready file; nothing lands on stdout.
    apply_sql(
        """
        CREATE TABLE public.fix_out (id INT);
        ALTER TABLE public.fix_out ENABLE ROW LEVEL SECURITY;
        """
    )
    out_file = tmp_path / "migration.sql"
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["fix", "--database-url", pg_url, "--output", str(out_file)],
    )
    assert result.exit_code == 0, result.output
    assert out_file.exists()
    text = out_file.read_text(encoding="utf-8")
    # Header naming the tool, plus the SEC002 fix (RLS on, no FORCE).
    assert text.startswith("-- Remediation SQL generated by pgrls")
    assert (
        "ALTER TABLE public.fix_out FORCE ROW LEVEL SECURITY;" in text
    )
    # The SQL went to the file, not stdout.
    assert result.stdout.strip() == ""
    # stderr confirms the write and names the path.
    assert "wrote 1 fix" in result.stderr
    assert str(out_file) in result.stderr


def test_fix_output_refuses_to_clobber_without_force(
    pg_url: str, apply_sql, tmp_path
) -> None:
    # `pgrls fix --output FILE` must not silently overwrite an existing
    # file (a hand-edited migration). Without --force it errors and
    # leaves the file byte-for-byte intact; with --force it overwrites.
    # Mirrors `pgrls generate` / `pgrls init`.
    apply_sql(
        """
        CREATE TABLE public.fix_out_force (id INT);
        ALTER TABLE public.fix_out_force ENABLE ROW LEVEL SECURITY;
        """
    )
    out_file = tmp_path / "migration.sql"
    sentinel = "-- hand-edited, do not clobber\n"
    out_file.write_text(sentinel, encoding="utf-8")
    runner = CliRunner()

    # Second write without --force is rejected; the file is untouched.
    rejected = runner.invoke(
        main,
        ["fix", "--database-url", pg_url, "--output", str(out_file)],
    )
    assert rejected.exit_code == 2
    assert "already exists" in rejected.output
    assert "--force" in rejected.output
    assert out_file.read_text(encoding="utf-8") == sentinel

    # With --force it overwrites with the real migration.
    forced = runner.invoke(
        main,
        [
            "fix", "--database-url", pg_url,
            "--output", str(out_file), "--force",
        ],
    )
    assert forced.exit_code == 0, forced.output
    text = out_file.read_text(encoding="utf-8")
    assert sentinel not in text
    assert "ALTER TABLE public.fix_out_force FORCE ROW LEVEL SECURITY;" in text


def test_fix_write_migration_passes_newline_empty(tmp_path, monkeypatch) -> None:
    # R12 #7: the migration must be written with newline="" so the LF
    # render_migration emits is byte-identical to the stdout dry-run and
    # to `generate --output` across platforms (text mode on Windows
    # rewrites \n -> \r\n otherwise). A byte-level test can't catch this
    # on POSIX runners, so assert the write kwarg directly.
    from pathlib import Path

    from pgrls.cli import _fix_write_migration
    from pgrls.fixers import Fix

    captured: dict = {}
    orig = Path.write_text

    def spy(self, data, **kwargs):  # type: ignore[no-untyped-def]
        captured.update(kwargs)
        return orig(self, data, **kwargs)

    monkeypatch.setattr(Path, "write_text", spy)
    fix = Fix(
        rule_id="SEC002",
        location="public.t",
        sql="ALTER TABLE public.t FORCE ROW LEVEL SECURITY;",
        description="enable FORCE row security",
    )
    _fix_write_migration([fix], str(tmp_path / "m.sql"), force=True)
    assert captured.get("newline") == ""


def test_fix_output_cannot_combine_with_apply(
    pg_url: str, tmp_path
) -> None:
    # --output writes a migration to run later, --apply executes
    # now — the two are mutually exclusive.
    out_file = tmp_path / "migration.sql"
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "fix", "--database-url", pg_url,
            "--output", str(out_file), "--apply",
        ],
    )
    assert result.exit_code == 2
    assert "--output and --apply" in result.output
    assert not out_file.exists()


def test_fix_output_writes_no_file_when_no_fixes(
    pg_url: str, apply_sql, tmp_path
) -> None:
    # A clean table → no fixes → no file written, clear stderr note.
    apply_sql(
        """
        CREATE TABLE public.fix_out_clean (id INT);
        ALTER TABLE public.fix_out_clean ENABLE ROW LEVEL SECURITY;
        ALTER TABLE public.fix_out_clean FORCE ROW LEVEL SECURITY;
        """
    )
    out_file = tmp_path / "migration.sql"
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["fix", "--database-url", pg_url, "--output", str(out_file)],
    )
    assert result.exit_code == 0, result.output
    assert "no auto-fixable" in result.output
    assert not out_file.exists()


def test_fix_output_bad_directory_errors_clearly(
    pg_url: str, apply_sql, tmp_path
) -> None:
    apply_sql(
        """
        CREATE TABLE public.fix_out_baddir (id INT);
        ALTER TABLE public.fix_out_baddir ENABLE ROW LEVEL SECURITY;
        """
    )
    # Parent directory does not exist → the write fails.
    out_file = tmp_path / "missing_dir" / "migration.sql"
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["fix", "--database-url", pg_url, "--output", str(out_file)],
    )
    assert result.exit_code == 2
    assert "cannot write fixes" in result.output


def test_fix_output_file_is_deterministic_and_honors_short_flag(
    pg_url: str, apply_sql, tmp_path
) -> None:
    # No timestamp in the header → regenerating against an
    # unchanged schema produces a byte-identical file. Also
    # exercises the `-o` short flag against `--output`.
    apply_sql(
        """
        CREATE TABLE public.fix_out_det (id INT);
        ALTER TABLE public.fix_out_det ENABLE ROW LEVEL SECURITY;
        """
    )
    runner = CliRunner()
    first = tmp_path / "first.sql"
    second = tmp_path / "second.sql"
    for path, flag in ((first, "--output"), (second, "-o")):
        result = runner.invoke(
            main,
            ["fix", "--database-url", pg_url, flag, str(path)],
        )
        assert result.exit_code == 0, result.output
    assert first.read_text(encoding="utf-8") == second.read_text(
        encoding="utf-8"
    )


def test_fix_dry_run_stdout_ends_without_a_trailing_blank_line(
    pg_url: str, apply_sql
) -> None:
    # The dry-run stdout is the rendered fix blocks plus a single
    # newline — no trailing blank line — so `pgrls fix >
    # migration.sql` produces a tidy file. Pins the deliberate
    # single-trailing-newline shape.
    apply_sql(
        """
        CREATE TABLE public.fix_tail (id INT);
        ALTER TABLE public.fix_tail ENABLE ROW LEVEL SECURITY;
        """
    )
    runner = CliRunner()
    result = runner.invoke(main, ["fix", "--database-url", pg_url])
    assert result.exit_code == 0, result.output
    assert result.stdout.endswith(";\n")
    assert not result.stdout.endswith(";\n\n")


def test_fix_rejects_malformed_allowlist_like_lint(
    pg_url: str, apply_sql, tmp_path
) -> None:
    # A malformed allowlist must fail `pgrls fix` exactly as it
    # fails `pgrls lint` — a clear tool error (exit 2), not a
    # silent "nothing exempt" that could emit (or --apply) more
    # SQL than the user intended. The fixers validate the
    # allowlist with the same strict parser the rules use.
    apply_sql(
        """
        CREATE TABLE public.fix_bad_allow (id INT);
        ALTER TABLE public.fix_bad_allow ENABLE ROW LEVEL SECURITY;
        """
    )
    cfg = tmp_path / "pgrls.toml"
    # Surrounding whitespace — a malformed SEC002 allowlist entry.
    cfg.write_text(
        "[lint.rules.SEC002]\n"
        'allowlist = [" public.fix_bad_allow "]\n'
    )
    runner = CliRunner()
    lint_result = runner.invoke(
        main, ["lint", "--database-url", pg_url, "--config", str(cfg)]
    )
    fix_result = runner.invoke(
        main, ["fix", "--database-url", pg_url, "--config", str(cfg)]
    )
    # Both reject it as a tool error (exit 2) and name the allowlist.
    assert lint_result.exit_code == 2, lint_result.output
    assert fix_result.exit_code == 2, fix_result.output
    assert "allowlist" in lint_result.output
    assert "allowlist" in fix_result.output


# ============================================================
# `pgrls fix --check` (CI gate) integration tests
# ============================================================


def test_fix_check_exits_one_when_fixable_violations_exist(
    pg_url: str, apply_sql
) -> None:
    # SEC002-fixable: RLS enabled, FORCE missing. `--check`
    # should exit 1 and list the offending (rule, location).
    apply_sql(
        """
        CREATE TABLE public.fix_check_a (id INT PRIMARY KEY);
        ALTER TABLE public.fix_check_a ENABLE ROW LEVEL SECURITY;
        CREATE POLICY p ON public.fix_check_a
            FOR SELECT TO postgres USING (id > 0);
        """
    )
    runner = CliRunner()
    result = runner.invoke(
        main, ["fix", "--database-url", pg_url, "--check"]
    )
    assert result.exit_code == 1, result.output
    assert "auto-fixable" in result.output
    assert "SEC002" in result.output
    assert "public.fix_check_a" in result.output
    # No SQL is emitted — only the summary + the (rule, location)
    # lines and the actionable next-step hint.
    assert "ALTER TABLE" not in result.output


def test_fix_check_exits_zero_on_clean_database(
    pg_url: str, apply_sql
) -> None:
    # A clean fixture: RLS+FORCE on, primary-key index covers
    # the predicate column, so no auto-fixer fires. `--check`
    # exits 0 with the existing "no auto-fixable" message.
    apply_sql(
        """
        CREATE TABLE public.fix_check_clean (id INT PRIMARY KEY);
        ALTER TABLE public.fix_check_clean ENABLE ROW LEVEL SECURITY;
        ALTER TABLE public.fix_check_clean FORCE ROW LEVEL SECURITY;
        CREATE POLICY p ON public.fix_check_clean
            FOR SELECT TO postgres USING (id > 0);
        """
    )
    runner = CliRunner()
    result = runner.invoke(
        main, ["fix", "--database-url", pg_url, "--check"]
    )
    assert result.exit_code == 0, result.output
    assert "no auto-fixable" in result.output


def test_fix_check_routes_violations_to_stdout_and_summary_to_stderr(
    pg_url: str, apply_sql
) -> None:
    # Pin the documented output split: per-fix (rule, location)
    # lines go to STDOUT (so `pgrls fix --check > violations.log`
    # captures them as a CI artefact); the summary count and the
    # next-step hint go to STDERR. The earlier tests inspect
    # `result.output`, which merges the streams and so cannot
    # tell the two apart.
    apply_sql(
        """
        CREATE TABLE public.fix_check_split (id INT PRIMARY KEY);
        ALTER TABLE public.fix_check_split ENABLE ROW LEVEL SECURITY;
        CREATE POLICY p ON public.fix_check_split
            FOR SELECT TO postgres USING (id > 0);
        """
    )
    runner = CliRunner()
    result = runner.invoke(
        main, ["fix", "--database-url", pg_url, "--check"]
    )
    assert result.exit_code == 1, result.output
    # Stdout — actionable, parseable violation listing.
    assert "SEC002" in result.stdout
    assert "public.fix_check_split" in result.stdout
    assert "auto-fixable" not in result.stdout
    assert "pgrls fix --apply" not in result.stdout
    # Stderr — diagnostic summary and next-step hint.
    assert "auto-fixable" in result.stderr
    assert "pgrls fix --apply" in result.stderr
    assert "SEC002" not in result.stderr


def test_fix_check_does_not_modify_database(
    pg_url: str, apply_sql
) -> None:
    # `--check` is a gate, not an apply path — the DB must be
    # byte-identical before and after the run.
    apply_sql(
        """
        CREATE TABLE public.fix_check_no_mut (id INT PRIMARY KEY);
        ALTER TABLE public.fix_check_no_mut ENABLE ROW LEVEL SECURITY;
        CREATE POLICY p ON public.fix_check_no_mut
            FOR SELECT TO postgres USING (id > 0);
        """
    )
    runner = CliRunner()
    result = runner.invoke(
        main, ["fix", "--database-url", pg_url, "--check"]
    )
    assert result.exit_code == 1, result.output
    # FORCE remains off — the SEC002 fix was NOT applied.
    import psycopg
    with psycopg.connect(pg_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT relforcerowsecurity FROM pg_catalog.pg_class "
                "WHERE oid = 'public.fix_check_no_mut'::regclass"
            )
            (force,) = cur.fetchone()
            assert force is False


def test_fix_check_rejects_apply() -> None:
    # `--check` and `--apply` are semantically opposed (gate vs.
    # mutation). The combination is a tool error (exit 2).
    runner = CliRunner()
    result = runner.invoke(
        main, ["fix", "--check", "--apply", "--database-url", "x"]
    )
    assert result.exit_code == 2
    assert "--check" in result.output
    assert "--apply" in result.output


def test_fix_check_rejects_output(tmp_path) -> None:
    # `--check` and `--output` are also exclusive — one gates,
    # the other writes a migration file.
    out = tmp_path / "m.sql"
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "fix", "--check", "--output", str(out),
            "--database-url", "x",
        ],
    )
    assert result.exit_code == 2
    assert "--check" in result.output
    assert "--output" in result.output


def test_fix_check_rejects_malformed_allowlist_as_tool_error(
    pg_url: str, apply_sql, tmp_path
) -> None:
    # A malformed allowlist must still surface as a tool error
    # (exit 2) under `--check` — not exit 1 (violations found).
    # The check branch sits *after* `generate_fixes`, so a fixer
    # raising on a bad allowlist propagates before `--check`
    # decides to gate.
    apply_sql(
        """
        CREATE TABLE public.fix_check_bad_allow (id INT);
        ALTER TABLE public.fix_check_bad_allow ENABLE ROW LEVEL SECURITY;
        """
    )
    cfg = tmp_path / "pgrls.toml"
    cfg.write_text(
        "[lint.rules.SEC002]\n"
        'allowlist = [" public.fix_check_bad_allow "]\n'
    )
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "fix", "--database-url", pg_url,
            "--config", str(cfg), "--check",
        ],
    )
    assert result.exit_code == 2, result.output
    assert "allowlist" in result.output


def test_fix_check_with_rule_filter_to_clean_subset_exits_zero(
    pg_url: str, apply_sql
) -> None:
    # Two fixable violations: SEC001 on table_a, SEC002 on table_b.
    # `--check --rule SEC020` filters to a rule that fires on
    # NEITHER table — `--check` then sees zero in-scope fixes and
    # exits 0 (clean), even though the DB has violations the
    # filter excluded. Confirms the filter narrows the gate.
    apply_sql(
        """
        CREATE TABLE public.fix_check_clean_filter_a (id INT);
        -- ^ SEC001 (RLS off) — fixable, but not SEC020.
        CREATE TABLE public.fix_check_clean_filter_b (id INT);
        ALTER TABLE public.fix_check_clean_filter_b ENABLE ROW LEVEL SECURITY;
        CREATE POLICY p ON public.fix_check_clean_filter_b
            FOR SELECT TO postgres USING (id > 0);
        -- ^ SEC002 (FORCE missing) — also not SEC020.
        """
    )
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "fix", "--database-url", pg_url,
            "--check", "--rule", "SEC020",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "no auto-fixable" in result.output


def test_fix_check_composes_with_rule_filter(
    pg_url: str, apply_sql
) -> None:
    # Two fixable violations, two different rules. `--check
    # --rule SEC001` gates on SEC001 only — even though SEC002
    # is also fixable, the filtered view reports just SEC001.
    apply_sql(
        """
        CREATE TABLE public.fix_check_filter_a (id INT);
        -- ^ SEC001 (RLS off)
        CREATE TABLE public.fix_check_filter_b (id INT);
        ALTER TABLE public.fix_check_filter_b ENABLE ROW LEVEL SECURITY;
        CREATE POLICY p ON public.fix_check_filter_b
            FOR SELECT TO postgres USING (id > 0);
        -- ^ SEC002 (FORCE missing)
        """
    )
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "fix", "--database-url", pg_url,
            "--check", "--rule", "SEC001",
        ],
    )
    assert result.exit_code == 1, result.output
    assert "SEC001" in result.output
    assert "public.fix_check_filter_a" in result.output
    # SEC002 is also fixable on the OTHER table, but --rule
    # filtered it out — it must not appear.
    assert "SEC002" not in result.output
    assert "public.fix_check_filter_b" not in result.output


def test_snapshot_output_write_error_exits_2(tmp_path) -> None:
    # `snapshot --output` to an unwritable path must exit 2 (clean
    # ToolError), not crash with an uncaught traceback (exit 1). The
    # write was the only --output writer not wrapped in try/except
    # OSError, unlike its 8 sibling commands. Regression.
    from unittest.mock import MagicMock, patch

    cm = MagicMock()
    cm.__enter__.return_value = MagicMock()
    cm.__exit__.return_value = False
    bad = tmp_path / "missing-dir" / "snap.json"  # parent does not exist
    with patch("pgrls.cli.psycopg.connect", return_value=cm), patch(
        "pgrls.cli.introspect", return_value=Schema(tables=())
    ):
        result = CliRunner().invoke(
            main,
            ["snapshot", "--database-url", "postgresql://x", "--output", str(bad)],
        )
    assert result.exit_code == 2, result.output
    assert "Cannot write" in result.output
    assert "Traceback" not in result.output
