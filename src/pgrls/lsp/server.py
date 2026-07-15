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

import os
from pathlib import Path

from lsprotocol import types as lsp
from pygls.lsp.server import LanguageServer
from pygls.workspace import TextDocument

from pgrls import __version__
from pgrls.config import Config, load_config
from pgrls.lsp.diagnostics import diagnose


def _discover_config(
    config_dir: str | None, ls: LanguageServer | None = None
) -> Config:
    """Load `pgrls.toml` from `config_dir`, or an unconfigured default.

    Mirrors the CLI, which reads `./pgrls.toml` from its working directory. A
    *missing* file is the normal unconfigured case → default `Config`, silently.
    A file that is *present but invalid* must not crash the editor session, but
    silently linting with defaults would drop the user's `disable` /
    `extra_rules` / `severity_overrides` and diverge from their CI gate — so
    surface it once as a warning (when a server is available) and fall back to
    the default.
    """
    if not config_dir:
        return Config()
    toml = Path(config_dir) / "pgrls.toml"
    if not toml.is_file():
        return Config()
    try:
        return load_config(toml)
    except Exception as exc:  # ConfigError, or any load-time failure
        if ls is not None:
            ls.window_show_message(
                lsp.ShowMessageParams(
                    type=lsp.MessageType.Warning,
                    message=(
                        f"pgrls: could not load {toml} ({exc}); linting with "
                        "default settings."
                    ),
                )
            )
        return Config()


def create_server() -> LanguageServer:
    """Build the pgrls Language Server with its document handlers registered."""
    server = LanguageServer("pgrls-lsp", __version__)
    # `pgrls.toml` is resolved once per config directory and cached — editing it
    # takes effect on the next server start (documented in the README).
    config_cache: dict[str, Config] = {}

    def _config(ls: LanguageServer, doc: TextDocument) -> Config:
        # The CLI reads `./pgrls.toml` from its working directory; the editor
        # analogue is the workspace root, or — when a lone file is opened with
        # no workspace folder (`root_path` is None) — the document's own
        # directory, so a project's config still applies in single-file mode.
        # Only a real `file:` document has a directory on disk; a virtual buffer
        # (`untitled:`, `inmemory:`, a notebook cell) has no project, so it must
        # not reach into the filesystem — fall back to the default config.
        root = getattr(ls.workspace, "root_path", None)
        doc_dir = (
            os.path.dirname(doc.path)
            if doc.path and doc.uri.startswith("file:")
            else None
        )
        config_dir = root or doc_dir
        key = config_dir or ""
        if key not in config_cache:
            config_cache[key] = _discover_config(config_dir, ls)
        return config_cache[key]

    def _refresh(ls: LanguageServer, uri: str) -> None:
        doc = ls.workspace.get_text_document(uri)
        ls.text_document_publish_diagnostics(
            lsp.PublishDiagnosticsParams(
                uri=uri,
                version=doc.version,
                diagnostics=diagnose(doc.source, config=_config(ls, doc)),
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
