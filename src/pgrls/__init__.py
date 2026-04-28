"""pgrls — framework-agnostic linter and testing toolkit for Postgres
Row-Level Security.

Public Python API (stable in 0.x; bumps documented in CHANGELOG):

* `pgrls.__version__`
* `pgrls.model.Schema`, `Table`, `Policy` — kwargs-only construction
  recommended; positional order is not committed across releases
* `pgrls.violations.Violation`, `Severity` (`"error" | "warning" | "info"`)
* `pgrls.fixers.Fix`, `Fixer`, `default_fixers`, `generate_fixes`

Submodule paths (`pgrls.cli`, `pgrls.config`, `pgrls.formatters`,
`pgrls.introspect`, `pgrls.rules.*`, `pgrls.ast_utils`) are
internal — import shape and helper signatures may change between
releases without notice. Pin pgrls to a specific minor version if
you build on internals.
"""

__version__ = "0.0.7"

__all__ = ["__version__"]
