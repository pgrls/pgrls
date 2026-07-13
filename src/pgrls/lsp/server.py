"""The pygls Language Server that serves `pgrls.lsp.diagnostics.diagnose`.

This module imports `pygls` at module level, which is fine because it is only
ever imported by the lazy `pgrls lsp` CLI path (and the guarded tests) — the
normal `pgrls` CLI never imports it, mirroring the `pgrls mcp` / `fastmcp`
lazy-import contract.

The server is diagnostic-only: on `didOpen` / `didChange` / `didSave` it
re-lints the buffer and publishes diagnostics; on `didClose` it clears them. It
never reaches a database and never mutates anything — the offline
`schema_from_sql` path is the whole engine.
"""
from __future__ import annotations

from lsprotocol import types as lsp
from pygls.lsp.server import LanguageServer

from pgrls import __version__
from pgrls.lsp.diagnostics import diagnose


def create_server() -> LanguageServer:
    """Build the pgrls Language Server with its document handlers registered."""
    server = LanguageServer("pgrls-lsp", __version__)

    def _refresh(ls: LanguageServer, uri: str) -> None:
        doc = ls.workspace.get_text_document(uri)
        ls.text_document_publish_diagnostics(
            lsp.PublishDiagnosticsParams(
                uri=uri,
                version=doc.version,
                diagnostics=diagnose(doc.source),
            )
        )

    @server.feature(lsp.TEXT_DOCUMENT_DID_OPEN)
    def did_open(
        ls: LanguageServer, params: lsp.DidOpenTextDocumentParams
    ) -> None:
        _refresh(ls, params.text_document.uri)

    @server.feature(lsp.TEXT_DOCUMENT_DID_CHANGE)
    def did_change(
        ls: LanguageServer, params: lsp.DidChangeTextDocumentParams
    ) -> None:
        # pygls has already applied the incremental change to its in-memory
        # document, so `get_text_document(uri).source` is the current buffer.
        _refresh(ls, params.text_document.uri)

    @server.feature(lsp.TEXT_DOCUMENT_DID_SAVE)
    def did_save(
        ls: LanguageServer, params: lsp.DidSaveTextDocumentParams
    ) -> None:
        _refresh(ls, params.text_document.uri)

    @server.feature(lsp.TEXT_DOCUMENT_DID_CLOSE)
    def did_close(
        ls: LanguageServer, params: lsp.DidCloseTextDocumentParams
    ) -> None:
        # Clear diagnostics for a document the editor is no longer showing.
        ls.text_document_publish_diagnostics(
            lsp.PublishDiagnosticsParams(
                uri=params.text_document.uri, diagnostics=[]
            )
        )

    return server


def run_stdio() -> None:
    """Run the server over stdio — the `pgrls lsp` entrypoint."""
    create_server().start_io()
