"""pgrls — framework-agnostic linter and testing toolkit for Postgres
Row-Level Security.

Top-level package surface intentionally exposes only `__version__`.
The Python API users build on lives in submodules:

* `from pgrls.model import Schema, Table, Policy` — kwargs-only
  construction recommended; positional order is not committed across
  releases.
* `from pgrls.violations import Violation, Severity`
  (Severity = "error" | "warning" | "info").
* `from pgrls.fixers import Fix, Fixer, default_fixers, generate_fixes`.
* `from pgrls.diff import Change, ChangeKind, Classification,
  diff_schemas` — semantic policy diff, v0.2+. Public Python API
  for diff result types and the top-level entry point;
  classification stays at `safe` / `breaking` / `requires_review` /
  `dangerous` (see `pgrls.diff.differ.Classification`).
* `from pgrls.testing import PgrlsTestClient` — pytest plugin for
  RLS isolation testing.

Other submodules (`pgrls.cli`, `pgrls.config`, `pgrls.formatters`,
`pgrls.introspect`, `pgrls.rules.*`, `pgrls.ast_utils`,
`pgrls.diff.formatters`, `pgrls.diff.ast_compare`) are internal:
import shapes and helper signatures may change between releases
without notice. Pin pgrls to a specific minor version if you build
on internals.
"""
from __future__ import annotations

__version__ = "0.5.3"

__all__ = ["__version__"]
