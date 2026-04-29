"""pgrls.diff — semantic policy diff between two RLS schemas.

Public exports for v0.2:

* `Change`, `ChangeKind`, `Classification` — the diff result types.
* `diff_schemas` — top-level entry point.

The Python API is documented but NOT promoted to the top-level
`pgrls` package surface in v0.2 (see the design spec's non-goals
section). v0.3 may promote.
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
