"""Trend analysis across a directory of `pgrls lint --format json` snapshots.

`pgrls history <dir>` consumes a directory of JSON files written by
`pgrls lint --format json` and emits a chronological trend: per-snapshot
totals by severity, plus the *delta* between consecutive snapshots —
which findings are NEW, which were FIXED. Designed for the question a
team asks after running pgrls on a long-lived database: "are we
gaining ground, or is the findings count creeping up?"

### Snapshot identity

The snapshot's timestamp is the JSON file's mtime — same approach
`pgrls diff` uses for snapshot ordering. Filename is preserved in the
output so the operator can correlate a row back to a build / CI run.
Files that don't parse as the pgrls JSON shape (a stray README, an
unrelated `*.json`) are skipped with a stderr warning rather than
failing the command — a `pgrls history snapshots/` over a slightly
contaminated directory still produces a useful report.

### Finding identity

A finding is keyed by `(rule_id, location)`. Two snapshots' findings
compare equal when both tuples match. `location` is `None` for a
schema-wide finding (e.g. SEC016, role-attribute scope); the pair
`(rule_id, None)` is a stable identity in its own right, so a SEC016
finding that persists across snapshots is correctly classified
PERSISTENT rather than NEW + FIXED on every comparison.

A snapshot may contain duplicate `(rule_id, location)` pairs (the
rule fires multiple times against the same target — rare but
possible for some rule shapes). Counts collapse to set semantics
for the new/fixed delta — the multiset distinction isn't useful at
trend granularity. The per-snapshot total still reflects raw
findings count.

### Output

Three formats:

* **text** — fixed-width aligned table for terminal reading; one row
  per snapshot with totals + delta. A trailing summary line names
  the net change over the full series.
* **json** — `{snapshots: [...], summary: {...}}` — machine-readable
  for downstream visualization (e.g. plotting a trend line). Stable
  shape, indented.
* **markdown** — GitHub-flavored Markdown table, paste-ready for a
  weekly engineering update or a PR comment.

### Why mtime, not a `generated_at` field

The JSON formatter's stable contract today carries findings and
summary counts but no timestamp. Adding one would be additive and
backward-compatible (consumers ignore unknown keys), but it would
force every `--format json` consumer to think about clock skew
between the linter host and CI runner clocks — a worse failure mode
than the operator already knows their snapshot directory's mtime
provenance. If `pgrls history` later grows a richer time-series
(per-rule trends, regression alerts) and needs a built-in
timestamp, the `generated_at` field is the right next step; for the
v0.6.10 baseline, mtime is enough.
"""
from __future__ import annotations

import json
import sys
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal


@dataclass(frozen=True)
class FindingKey:
    """The (rule_id, location) tuple that identifies a finding across
    snapshots. `location` may be None for schema-wide findings."""
    rule_id: str
    location: str | None


@dataclass(frozen=True)
class Snapshot:
    """One JSON file's worth of pgrls findings, with mtime."""
    path: Path
    timestamp: datetime
    findings: frozenset[FindingKey]
    raw_total: int
    counts: dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class SnapshotRow:
    """One row in the rendered trend table — a snapshot plus the
    delta vs. the prior snapshot in chronological order."""
    snapshot: Snapshot
    new_count: int
    fixed_count: int


HistoryFormat = Literal["text", "json", "markdown"]
HISTORY_FORMATS: tuple[HistoryFormat, ...] = ("text", "json", "markdown")


def _read_snapshot(path: Path) -> Snapshot | None:
    """Parse one JSON snapshot file. Returns None for unparseable
    files (logged to stderr); the caller skips them."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(
            f"pgrls history: skipping {path.name}: {exc}",
            file=sys.stderr,
        )
        return None
    if not isinstance(payload, dict):
        print(
            f"pgrls history: skipping {path.name}: "
            "top-level JSON is not an object",
            file=sys.stderr,
        )
        return None
    violations = payload.get("violations")
    if not isinstance(violations, list):
        print(
            f"pgrls history: skipping {path.name}: "
            "missing or non-list 'violations' field",
            file=sys.stderr,
        )
        return None
    keys: set[FindingKey] = set()
    counts: dict[str, int] = {"error": 0, "warning": 0, "info": 0}
    for v in violations:
        if not isinstance(v, dict):
            continue
        rule_id = v.get("rule_id")
        severity = v.get("severity")
        if not isinstance(rule_id, str):
            continue
        loc = v.get("location")
        loc_str = loc if (loc is None or isinstance(loc, str)) else None
        keys.add(FindingKey(rule_id=rule_id, location=loc_str))
        if isinstance(severity, str) and severity in counts:
            counts[severity] += 1
    mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
    return Snapshot(
        path=path,
        timestamp=mtime,
        findings=frozenset(keys),
        raw_total=len(violations),
        counts=counts,
    )


def load_snapshots(directory: Path) -> list[Snapshot]:
    """Read every `*.json` file in `directory`, sort chronologically
    by mtime. Unparseable files are skipped with a stderr warning;
    the caller still gets a result for the readable ones."""
    if not directory.exists():
        raise FileNotFoundError(
            f"pgrls history: directory not found: {directory}"
        )
    if not directory.is_dir():
        raise NotADirectoryError(
            f"pgrls history: {directory} is not a directory"
        )
    snapshots: list[Snapshot] = []
    for path in sorted(directory.glob("*.json")):
        snap = _read_snapshot(path)
        if snap is not None:
            snapshots.append(snap)
    snapshots.sort(key=lambda s: s.timestamp)
    return snapshots


def build_rows(snapshots: Iterable[Snapshot]) -> list[SnapshotRow]:
    """Compute the (NEW, FIXED) delta between each snapshot and the
    one before it in chronological order. The first snapshot has
    `new_count = len(findings)` (every finding is "new" with no prior
    baseline) and `fixed_count = 0`."""
    rows: list[SnapshotRow] = []
    prior: frozenset[FindingKey] = frozenset()
    first = True
    for snap in snapshots:
        if first:
            new = len(snap.findings)
            fixed = 0
            first = False
        else:
            new = len(snap.findings - prior)
            fixed = len(prior - snap.findings)
        rows.append(SnapshotRow(snapshot=snap, new_count=new, fixed_count=fixed))
        prior = snap.findings
    return rows


def render_text(rows: list[SnapshotRow]) -> str:
    """Fixed-width aligned table for terminal reading.

    Columns: TIMESTAMP, FILE, TOTAL, ERROR, WARN, INFO, NEW, FIXED.
    Trailing summary line names the net change over the full series.
    """
    if not rows:
        return "No snapshots found.\n"
    headers = (
        "TIMESTAMP",
        "FILE",
        "TOTAL",
        "ERROR",
        "WARN",
        "INFO",
        "NEW",
        "FIXED",
    )
    body = [
        (
            row.snapshot.timestamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
            row.snapshot.path.name,
            str(row.snapshot.raw_total),
            str(row.snapshot.counts.get("error", 0)),
            str(row.snapshot.counts.get("warning", 0)),
            str(row.snapshot.counts.get("info", 0)),
            str(row.new_count) if row.new_count else "-",
            str(row.fixed_count) if row.fixed_count else "-",
        )
        for row in rows
    ]
    widths = [
        max(len(headers[i]), max(len(r[i]) for r in body))
        for i in range(len(headers))
    ]
    header_line = "  ".join(
        h.ljust(widths[i]) for i, h in enumerate(headers)
    )
    out = [header_line]
    for r in body:
        out.append("  ".join(r[i].ljust(widths[i]) for i in range(len(r))))
    out.append("")
    out.append(_summary_line(rows))
    return "\n".join(out) + "\n"


def render_json(rows: list[SnapshotRow]) -> str:
    """Machine-readable shape: `{snapshots: [...], summary: {...}}`.

    Each snapshot carries `timestamp`, `file`, `total`, severity
    counts, and the new/fixed delta. Stable across the same major-
    zero series; new keys are additive.
    """
    payload = {
        "snapshots": [
            {
                "timestamp": row.snapshot.timestamp.strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                ),
                "file": row.snapshot.path.name,
                "total": row.snapshot.raw_total,
                "errors": row.snapshot.counts.get("error", 0),
                "warnings": row.snapshot.counts.get("warning", 0),
                "infos": row.snapshot.counts.get("info", 0),
                "new": row.new_count,
                "fixed": row.fixed_count,
            }
            for row in rows
        ],
        "summary": _summary_dict(rows),
    }
    return json.dumps(payload, indent=2) + "\n"


def render_markdown(rows: list[SnapshotRow]) -> str:
    """GitHub-flavored Markdown table; paste-ready for a weekly
    engineering update or a PR comment."""
    if not rows:
        return "## pgrls history\n\nNo snapshots found.\n"
    out = [
        "## pgrls history",
        "",
        "| Timestamp | File | Total | Error | Warn | Info | New | Fixed |",
        "|---|---|---:|---:|---:|---:|---:|---:|",
    ]
    for row in rows:
        out.append(
            "| {ts} | `{fn}` | {tot} | {err} | {warn} | {info} | {new} | {fix} |".format(
                ts=row.snapshot.timestamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
                fn=row.snapshot.path.name,
                tot=row.snapshot.raw_total,
                err=row.snapshot.counts.get("error", 0),
                warn=row.snapshot.counts.get("warning", 0),
                info=row.snapshot.counts.get("info", 0),
                new=row.new_count if row.new_count else "—",
                fix=row.fixed_count if row.fixed_count else "—",
            )
        )
    out.append("")
    out.append(f"**{_summary_line(rows)}**")
    return "\n".join(out) + "\n"


def _summary_dict(rows: list[SnapshotRow]) -> dict[str, int]:
    if not rows:
        return {
            "snapshots": 0,
            "first_total": 0,
            "last_total": 0,
            "net_change": 0,
            "total_new": 0,
            "total_fixed": 0,
        }
    first_total = rows[0].snapshot.raw_total
    last_total = rows[-1].snapshot.raw_total
    # NEW / FIXED across the full series — sum of per-snapshot
    # deltas (skipping the first snapshot's baseline "every finding
    # is new" count, which is bookkeeping noise, not new findings).
    total_new = sum(r.new_count for r in rows[1:])
    total_fixed = sum(r.fixed_count for r in rows[1:])
    return {
        "snapshots": len(rows),
        "first_total": first_total,
        "last_total": last_total,
        "net_change": last_total - first_total,
        "total_new": total_new,
        "total_fixed": total_fixed,
    }


def _summary_line(rows: list[SnapshotRow]) -> str:
    s = _summary_dict(rows)
    if s["snapshots"] == 0:
        return "No snapshots."
    if s["snapshots"] == 1:
        return (
            f"1 snapshot, {s['first_total']} finding"
            f"{'s' if s['first_total'] != 1 else ''}."
        )
    delta = s["net_change"]
    direction = "+" if delta > 0 else ""
    return (
        f"{s['snapshots']} snapshots, net change {direction}{delta} "
        f"({s['first_total']} → {s['last_total']}); "
        f"{s['total_new']} new, {s['total_fixed']} fixed."
    )


_RENDERERS = {
    "text": render_text,
    "json": render_json,
    "markdown": render_markdown,
}


def render(rows: list[SnapshotRow], output_format: HistoryFormat) -> str:
    return _RENDERERS[output_format](rows)
