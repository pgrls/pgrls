"""pgrls.diff — semantic policy diff between two RLS schemas.

Public exports (stable since v0.2):

* `Change`, `ChangeKind`, `Classification` — the diff result types.
* `diff_schemas` — top-level entry point.

As of v0.5.9 these four symbols are also re-exported from the
top-level `pgrls` package, so ``from pgrls import diff_schemas, Change``
and ``from pgrls.diff import diff_schemas, Change`` resolve to the
same objects (the top-level binding is a re-export, not a copy —
``isinstance``/equality checks across import paths work correctly).
`pgrls.diff` remains the canonical submodule for the diff API; the
re-exports are a convenience for callers who don't need any other
submodule surface.
"""
from __future__ import annotations

from pgrls.diff.differ import (
    Change,
    ChangeKind,
    Classification,
    diff_schemas,
)

__all__ = [
    "Change",
    "ChangeKind",
    "Classification",
    "diff_schemas",
]
