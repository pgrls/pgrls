"""pgrls — framework-agnostic linter and testing toolkit for Postgres
Row-Level Security.

Top-level package surface exposes the diff API (v0.5.9+) plus the
package version. Everything else lives in submodules:

* ``from pgrls import diff_schemas, Change, ChangeKind, Classification``
  — semantic policy diff between two ``Schema`` snapshots
  (v0.2+ in ``pgrls.diff``, promoted to the top level in v0.5.9).
  ``pgrls.diff`` remains the canonical submodule; both import paths
  resolve to the same object identities, so ``isinstance(c, Change)``
  works regardless of which path the caller used.
* ``from pgrls.model import Schema, Table, Policy, Trigger`` —
  kwargs-only construction recommended; positional order is not
  committed across releases.
* ``from pgrls.violations import Violation, Severity``
  (Severity = "error" | "warning" | "info").
* ``from pgrls.fixers import Fix, Fixer, default_fixers, generate_fixes``.
* ``from pgrls.testing import PgrlsTestClient`` — pytest plugin for
  RLS isolation testing.

Other submodules (``pgrls.cli``, ``pgrls.config``, ``pgrls.formatters``,
``pgrls.introspect``, ``pgrls.rules.*``, ``pgrls.ast_utils``,
``pgrls.diff.formatters``, ``pgrls.diff.ast_compare``) are internal:
import shapes and helper signatures may change between releases
without notice. Pin pgrls to a specific minor version if you build
on internals.
"""
from __future__ import annotations

from pgrls.diff import (
    Change,
    ChangeKind,
    Classification,
    diff_schemas,
)

__version__ = "0.5.41"

__all__ = [
    "Change",
    "ChangeKind",
    "Classification",
    "__version__",
    "diff_schemas",
]
