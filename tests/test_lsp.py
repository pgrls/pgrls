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

from pgrls.lsp.diagnostics import _LineIndex, diagnose  # noqa: E402
from pgrls.lsp.server import create_server  # noqa: E402

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


def test_finding_without_a_create_falls_back_to_document_start() -> None:
    # A buffer that only ALTERs a table (defined elsewhere) still surfaces the
    # finding — anchored at the AlterTable statement, not dropped.
    text = "ALTER TABLE public.legacy ENABLE ROW LEVEL SECURITY;"
    diags = diagnose(text)
    # SEC009 (RLS on, no policy) fires; it must have a valid range.
    assert diags
    for d in diags:
        assert d.range.start.line >= 0


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
