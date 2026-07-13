"""The `pgrls lsp` Language Server (optional `pgrls[lsp]` extra).

`pgrls.lsp.diagnostics` is the pure, protocol-free core — `diagnose(text)`
turns a `.sql` buffer into LSP `Diagnostic`s by reusing the offline
`schema_from_sql` → rule-engine path (the same one `pgrls lint --sql-file`
uses) and mapping each finding to a precise source range. It imports
`lsprotocol` (a `pgrls[lsp]` dependency) but NOT `pygls`.

`pgrls.lsp.server` is the thin `pygls` server that wires `diagnose` to
`didOpen`/`didChange`/`didClose`. The `pgrls lsp` CLI subcommand imports it
lazily, so the normal `pgrls` CLI never imports `pygls`.
"""
