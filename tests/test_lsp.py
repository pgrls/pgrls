"""Tests for the `pgrls lsp` Language Server (the optional `pgrls[lsp]` extra).

Most tests exercise the pure `diagnose(text)` core — no server, no protocol —
which is where the logic lives (buffer → Schema → rules → ranged diagnostics).
A few drive the pygls server's `didOpen`/`didChange`/`didClose` handlers with an
injected workspace to pin the glue, and a subprocess test pins the headline
safety property: importing `pgrls.cli` must NOT import `pygls`.
"""
from __future__ import annotations

import subprocess
import sys

import pytest

# The whole module needs the [lsp] extra. CI installs `--all-extras`; a
# core-only dev env skips rather than errors on collection.
pytest.importorskip("pygls")
pytest.importorskip("lsprotocol")

from lsprotocol import types as lsp  # noqa: E402
from pygls.workspace import Workspace  # noqa: E402

from pgrls.config import Config  # noqa: E402
from pgrls.lsp.diagnostics import _LineIndex, diagnose  # noqa: E402
from pgrls.lsp.server import _discover_config, create_server  # noqa: E402

_RLS_OFF = "CREATE TABLE public.users (id int, email text);"
_PUBLIC_POLICY = (
    "CREATE TABLE public.orders (id int);\n"
    "ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;\n"
    "CREATE POLICY open ON public.orders FOR SELECT TO public USING (true);"
)


def _codes(text: str) -> list[str]:
    return sorted(d.code for d in diagnose(text))


# --- diagnose: core behavior -----------------------------------------------


def test_rls_off_table_reports_sec001() -> None:
    diags = diagnose(_RLS_OFF)
    assert [d.code for d in diags] == ["SEC001"]
    d = diags[0]
    assert d.source == "pgrls"
    assert d.severity == lsp.DiagnosticSeverity.Error
    assert d.code_description.href.endswith("rule-sec001")


def test_enabling_rls_removes_sec001() -> None:
    # Behavioral delta: the same table, now with RLS + FORCE + a scoped policy,
    # no longer trips SEC001.
    safe = (
        "CREATE TABLE public.users (id int, tenant_id uuid NOT NULL);\n"
        "ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;\n"
        "ALTER TABLE public.users FORCE ROW LEVEL SECURITY;\n"
        "CREATE POLICY sel ON public.users FOR ALL TO authenticated\n"
        "  USING (tenant_id = (SELECT current_setting('app.t', true)::uuid))\n"
        "  WITH CHECK (tenant_id = (SELECT current_setting('app.t', true)::uuid));"
    )
    assert "SEC001" not in _codes(safe)


def test_range_points_at_the_defining_statement() -> None:
    diags = diagnose(_PUBLIC_POLICY)
    by_code = {d.code: d for d in diags}
    # SEC001/SEC002 land on the CREATE TABLE (line 0); the PUBLIC-policy
    # findings land on the CREATE POLICY (line 2).
    assert by_code["SEC002"].range.start.line == 0
    assert by_code["SEC003"].range.start.line == 2
    # The range spans the statement, not a zero-width point.
    r = by_code["SEC003"].range
    assert (r.end.line, r.end.character) > (r.start.line, r.start.character)


def test_severity_mapping() -> None:
    sev = {d.code: d.severity for d in diagnose(_PUBLIC_POLICY)}
    assert sev["SEC003"] == lsp.DiagnosticSeverity.Error  # error rule
    assert sev["SEC008"] == lsp.DiagnosticSeverity.Warning  # warning rule
    assert sev["SEC007"] == lsp.DiagnosticSeverity.Information  # info rule


def test_unparseable_buffer_is_silent() -> None:
    # A mid-keystroke buffer that doesn't parse must not error or crash — the
    # editor should just show no diagnostics until it parses again.
    assert diagnose("CREATE TABL nonsense (((") == []


def test_empty_buffer_is_silent() -> None:
    assert diagnose("") == []


def test_catalog_only_rules_are_skipped_like_sql_file() -> None:
    # SEC053 (foreign table in API) needs live catalog state; it is skipped on a
    # SQL buffer exactly as `pgrls lint --sql-file` skips it — so it can never
    # produce a diagnostic here even though the buffer names a foreign table.
    text = (
        "CREATE FOREIGN TABLE public.remote (id int) SERVER s;\n"
        "GRANT SELECT ON public.remote TO anon;"
    )
    assert "SEC053" not in _codes(text)


def test_alter_only_table_anchors_at_the_alter_statement() -> None:
    # A table defined only by ALTER in this buffer (a migration file) still
    # surfaces its findings, anchored at the ALTER statement (the fallback).
    stmt = "ALTER TABLE public.legacy ENABLE ROW LEVEL SECURITY"
    diags = diagnose(stmt + ";")
    assert diags  # SEC009 (RLS on, no policy) fires
    d = diags[0]
    assert d.range.start.line == 0 and d.range.start.character == 0
    assert d.range.end.character == len(stmt)  # spans the ALTER, not the `;`


def test_statement_without_trailing_semicolon_gets_full_range() -> None:
    # The common mid-keystroke / last-statement state: no `;` typed. pglast
    # reports stmt_len == 0 there; the range must span the statement, not
    # collapse to an invisible zero-width point.
    stmt = "CREATE TABLE public.users (id int)"
    d = diagnose(stmt)[0]
    assert (d.range.start.character, d.range.end.character) == (0, len(stmt))
    # And the last statement of a multi-statement buffer with no trailing `;`.
    diags = diagnose("CREATE TABLE public.a (id int);\nCREATE TABLE public.b (id int)")
    b = next(x for x in diags if x.code == "SEC001" and x.range.start.line == 1)
    assert (b.range.start.character, b.range.end.character) == (0, 30)


def test_leading_comment_is_excluded_from_the_range() -> None:
    # pglast's stmt_location includes a leading comment/license header; the
    # range should underline the CREATE, not the comment above it.
    for header in ("/* license */\n", "-- a comment\n"):
        d = diagnose(header + "CREATE TABLE public.t (id int);")[0]
        assert d.range.start.line == 1 and d.range.start.character == 0


def test_column_grant_finding_points_at_the_grant_statement() -> None:
    # SEC045's location is `schema.table.column` — a shape with no CREATE of its
    # own. The finding must underline the offending GRANT, not collapse to the
    # document start (which it did before column-grant spans were tracked).
    text = (
        "CREATE TABLE public.profiles (id int, email text, ssn text);\n"
        "GRANT SELECT (email, ssn) ON public.profiles TO anon;"
    )
    sec045 = [d for d in diagnose(text) if d.code == "SEC045"]
    assert sec045  # fires on the sensitive-column grant
    for d in sec045:
        assert d.range.start.line == 1  # the GRANT statement, not line 0
        assert d.range.start.character == 0


def test_column_grant_range_does_not_collide_with_a_same_named_policy() -> None:
    # A policy named the same as the granted column shares the flat
    # `schema.table.email` location string; the column finding must still land
    # on the GRANT, never on the unrelated CREATE POLICY.
    text = (
        "CREATE TABLE public.t (id int, email text);\n"
        "ALTER TABLE public.t ENABLE ROW LEVEL SECURITY;\n"
        "CREATE POLICY email ON public.t USING (true);\n"
        "GRANT SELECT (email) ON public.t TO anon;"
    )
    (d,) = [x for x in diagnose(text) if x.code == "SEC045"]
    assert d.range.start.line == 3  # the GRANT, not the CREATE POLICY on line 2


# --- config awareness (honors pgrls.toml, like the CLI) --------------------


def test_config_disable_suppresses_a_rule() -> None:
    text = _RLS_OFF
    assert _codes(text) == ["SEC001"]
    assert diagnose(text, config=Config(disable=["SEC001"])) == []


def test_config_allowlist_suppresses_a_finding() -> None:
    text = _RLS_OFF
    cfg = Config(rule_options={"SEC001": {"allowlist": ["public.users"]}})
    assert diagnose(text, config=cfg) == []


def test_config_severity_override_remaps_the_diagnostic_level() -> None:
    cfg = Config(severity_overrides={"SEC001": "warning"})
    (d,) = diagnose(_RLS_OFF, config=cfg)
    assert d.severity == lsp.DiagnosticSeverity.Warning


def test_discover_config_reads_pgrls_toml_from_workspace_root(tmp_path) -> None:
    (tmp_path / "pgrls.toml").write_text(
        "[lint]\ndisable = ['SEC001']\n", encoding="utf-8"
    )
    cfg = _discover_config(str(tmp_path))
    assert "SEC001" in cfg.disable
    # No file / no root → an unconfigured default, never an error.
    assert _discover_config(str(tmp_path / "nope")).disable == []
    assert _discover_config(None).disable == []


def test_discover_config_warns_on_malformed_toml_and_falls_back(tmp_path) -> None:
    # A present-but-invalid pgrls.toml must not crash the session: the CLI
    # hard-errors, so the LSP surfaces a one-time warning and lints with
    # defaults rather than silently dropping the user's disable / extra_rules /
    # severity_overrides (which would diverge from their CI gate with no signal).
    (tmp_path / "pgrls.toml").write_text("[lint]\ndisable = [oops\n")
    warnings: list = []

    class _LS:
        def window_show_message(self, params) -> None:
            warnings.append(params)

    cfg = _discover_config(str(tmp_path), _LS())
    assert cfg == Config()  # default, not a crash
    assert warnings and warnings[0].type == lsp.MessageType.Warning
    assert "pgrls.toml" in warnings[0].message


# --- _LineIndex: UTF-16 position conversion --------------------------------


def test_line_index_maps_offsets_to_line_and_character() -> None:
    text = "abc\ndef\nghi"
    idx = _LineIndex(text)
    assert (idx.position(0).line, idx.position(0).character) == (0, 0)
    assert (idx.position(4).line, idx.position(4).character) == (1, 0)  # 'd'
    assert (idx.position(6).line, idx.position(6).character) == (1, 2)  # 'f'


def test_line_index_counts_character_in_utf16_units() -> None:
    # A non-BMP char (😀 = 2 UTF-16 code units) before the offset must shift the
    # `character` by 2, per the LSP spec — a naive code-point count would say 1.
    text = "-- 😀\nX"
    idx = _LineIndex(text)
    # Offset of 'X' (line 1, col 0).
    x_offset = text.index("X")
    pos = idx.position(x_offset)
    assert (pos.line, pos.character) == (1, 0)
    # A position right after the emoji on line 0: "-- " is 3 units, 😀 is 2 → 5.
    after_emoji = text.index("\n")
    assert idx.position(after_emoji).character == 5


# --- server glue -----------------------------------------------------------


def _server_with_doc(uri: str, text: str):
    s = create_server()
    # The workspace is normally created during the LSP `initialize` handshake;
    # inject one so the handlers can read the document in a unit test.
    s.protocol._workspace = Workspace(None)
    s.workspace.put_text_document(
        lsp.TextDocumentItem(
            uri=uri, language_id="sql", version=1, text=text
        )
    )
    published: list = []
    s.text_document_publish_diagnostics = published.append  # type: ignore[method-assign]
    return s, published


def _fire(s, feature: str, params) -> None:
    # pygls stores each handler as a partial with `ls` pre-bound, so it is
    # invoked with just `params`.
    s.protocol.fm.features[feature](params)


def test_create_server_registers_the_document_handlers() -> None:
    s = create_server()
    feats = set(s.protocol.fm.features)
    assert {
        lsp.TEXT_DOCUMENT_DID_OPEN,
        lsp.TEXT_DOCUMENT_DID_CHANGE,
        lsp.TEXT_DOCUMENT_DID_SAVE,
        lsp.TEXT_DOCUMENT_DID_CLOSE,
    } <= feats
    assert s.name == "pgrls-lsp"


def test_did_open_publishes_diagnostics() -> None:
    uri = "file:///schema.sql"
    s, published = _server_with_doc(uri, _RLS_OFF)
    _fire(
        s,
        lsp.TEXT_DOCUMENT_DID_OPEN,
        lsp.DidOpenTextDocumentParams(
            text_document=lsp.TextDocumentItem(
                uri=uri, language_id="sql", version=1, text=""
            )
        ),
    )
    assert len(published) == 1
    p = published[0]
    assert p.uri == uri
    assert [d.code for d in p.diagnostics] == ["SEC001"]


def test_did_save_republishes_diagnostics() -> None:
    uri = "file:///schema.sql"
    s, published = _server_with_doc(uri, _RLS_OFF)
    _fire(
        s,
        lsp.TEXT_DOCUMENT_DID_SAVE,
        lsp.DidSaveTextDocumentParams(
            text_document=lsp.TextDocumentIdentifier(uri=uri)
        ),
    )
    assert [d.code for d in published[-1].diagnostics] == ["SEC001"]


def test_published_diagnostics_carry_the_document_version() -> None:
    # The version threads through so a client can discard diagnostics for a
    # superseded buffer (the stale-diagnostics race).
    uri = "file:///schema.sql"
    s, published = _server_with_doc(uri, _RLS_OFF)  # put with version=1
    _fire(
        s,
        lsp.TEXT_DOCUMENT_DID_OPEN,
        lsp.DidOpenTextDocumentParams(
            text_document=lsp.TextDocumentItem(
                uri=uri, language_id="sql", version=1, text=""
            )
        ),
    )
    assert published[-1].version == 1


def test_single_file_mode_uses_config_next_to_the_document(tmp_path) -> None:
    # No workspace folder (root_path is None) — the config beside the opened
    # file must still apply, matching the CLI's ./pgrls.toml lookup.
    (tmp_path / "pgrls.toml").write_text(
        "[lint]\ndisable = ['SEC001']\n", encoding="utf-8"
    )
    uri = (tmp_path / "schema.sql").as_uri()
    s, published = _server_with_doc(uri, _RLS_OFF)
    _fire(
        s,
        lsp.TEXT_DOCUMENT_DID_OPEN,
        lsp.DidOpenTextDocumentParams(
            text_document=lsp.TextDocumentItem(
                uri=uri, language_id="sql", version=1, text=""
            )
        ),
    )
    # SEC001 would fire on _RLS_OFF, but the adjacent config disables it.
    assert [d.code for d in published[-1].diagnostics] == []


def test_did_close_clears_diagnostics() -> None:
    uri = "file:///schema.sql"
    s, published = _server_with_doc(uri, _RLS_OFF)
    _fire(
        s,
        lsp.TEXT_DOCUMENT_DID_CLOSE,
        lsp.DidCloseTextDocumentParams(
            text_document=lsp.TextDocumentIdentifier(uri=uri)
        ),
    )
    assert published[-1].diagnostics == []


def test_did_change_relints_current_buffer() -> None:
    uri = "file:///schema.sql"
    s, published = _server_with_doc(uri, _RLS_OFF)
    # Simulate the editor having fixed the table (full-document sync).
    fixed = (
        "CREATE TABLE public.users (id int);\n"
        "ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;\n"
        "ALTER TABLE public.users FORCE ROW LEVEL SECURITY;\n"
        "CREATE POLICY p ON public.users FOR ALL TO authenticated\n"
        "  USING (id = (SELECT current_setting('app.u', true)::int))\n"
        "  WITH CHECK (id = (SELECT current_setting('app.u', true)::int));"
    )
    s.workspace.update_text_document(
        lsp.VersionedTextDocumentIdentifier(uri=uri, version=2),
        lsp.TextDocumentContentChangeWholeDocument(text=fixed),
    )
    _fire(
        s,
        lsp.TEXT_DOCUMENT_DID_CHANGE,
        lsp.DidChangeTextDocumentParams(
            text_document=lsp.VersionedTextDocumentIdentifier(
                uri=uri, version=2
            ),
            content_changes=[],
        ),
    )
    assert "SEC001" not in [d.code for d in published[-1].diagnostics]


# --- CLI wiring / lazy-import safety ----------------------------------------


def test_pgrls_lsp_subcommand_is_registered() -> None:
    from click.testing import CliRunner

    from pgrls.cli import main

    result = CliRunner().invoke(main, ["lsp", "--help"])
    assert result.exit_code == 0
    assert "Language Server" in result.output


def test_importing_cli_does_not_import_pygls() -> None:
    # The headline slim-install contract: the normal CLI path must not pull in
    # pygls (mirrors the pgrls[mcp] / fastmcp lazy-import test).
    code = (
        "import sys, pgrls.cli; "
        "assert 'pygls' not in sys.modules, 'pgrls.cli leaked pygls'; "
        "assert 'lsprotocol' not in sys.modules, 'pgrls.cli leaked lsprotocol'"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True
    )
    assert result.returncode == 0, result.stderr


def test_missing_lsp_extra_raises_clean_error(monkeypatch) -> None:
    # If pygls isn't installed, `pgrls lsp` must fail with a clear "install
    # pgrls[lsp]" message, not an ImportError traceback.
    import builtins

    real_import = builtins.__import__

    def _no_pygls(name, *args, **kwargs):
        if name == "pgrls.lsp.server" or name.startswith("pygls"):
            raise ImportError("No module named 'pygls'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _no_pygls)

    from click.testing import CliRunner

    from pgrls.cli import main

    result = CliRunner().invoke(main, ["lsp"])
    assert result.exit_code == 2
    assert "pgrls[lsp]" in result.output
