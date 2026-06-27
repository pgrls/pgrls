"""Optional Model Context Protocol (MCP) server for pgrls.

`pgrls mcp` exposes pgrls's static analysis — `lint`, `verify`, `explain`,
`list_rules` — to AI coding agents over MCP (stdio). The headline is offline
analysis of the raw DDL an agent just wrote: pass the `CREATE TABLE` /
`CREATE POLICY` SQL as `sql=` and pgrls lints + Z3-verifies it with NO
database.

This package is split so the only module that touches the FastMCP API is
`server`; all the schema-resolution / DDL-parsing logic lives in
`pgrls.schema_sources` (FastMCP-agnostic, unit-testable without the extra).

FastMCP is an OPTIONAL dependency (`pip install 'pgrls[mcp]'`). Importing
`pgrls.mcp.server` (which imports `fastmcp`) is deferred — `pgrls.cli` never
imports it on the normal CLI path, so a plain `pip install pgrls` stays slim.
The server is READ-ONLY / DIAGNOSTIC-ONLY: it never mutates a database and
never auto-applies SQL.
"""
from __future__ import annotations
