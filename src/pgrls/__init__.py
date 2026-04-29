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

Other submodules (`pgrls.cli`, `pgrls.config`, `pgrls.formatters`,
`pgrls.introspect`, `pgrls.rules.*`, `pgrls.ast_utils`) are internal:
import shapes and helper signatures may change between releases
without notice. Pin pgrls to a specific minor version if you build
on internals.
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
