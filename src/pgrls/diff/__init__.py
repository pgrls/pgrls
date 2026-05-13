"""pgrls.diff — semantic policy diff between two RLS schemas.

Public exports (stable since v0.2):

* `Change`, `ChangeKind`, `Classification` — the diff result types.
* `diff_schemas` — top-level entry point.

The Python API is documented but not promoted to the top-level
`pgrls` package surface as of v0.5.7; consumers must import from
`pgrls.diff` explicitly. A future release may promote `Change`,
`ChangeKind`, `Classification`, and `diff_schemas` to the
top-level package.
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
