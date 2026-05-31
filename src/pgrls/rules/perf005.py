"""PERF005 — RLS-protected table observed to sequentially scan in production.

`pgrls perf` ranks RLS tables by observed sequential scans; PERF005 brings
that signal into the lint gate so CI can fail on it next to every other
rule. It is **opt-in**: it does nothing on a normal `pgrls lint` run, firing
only when lint is given a runtime-stats artifact (`pgrls lint --perf
.pgrls-perf.json`, written by `pgrls perf --snapshot`). The CLI loads that
artifact and injects the parsed stats under the private `_perf` key — rules
can't read files themselves, so lint hands the parsed data in. Without it,
`check` returns nothing rather than guess.

A table is flagged when its snapshot stats clear the same thresholds
`pgrls perf` uses — large enough that a sequential scan matters, scanned
sequentially enough times to be steady-state cost, and doing most of its
scanning sequentially (see `pgrls.perf.under_seq_scan_pressure`, the shared
gate so rule and command never drift). The thresholds are tunable per-rule:
`[lint.rules.PERF005]` `min_rows` / `min_seq_scans` / `min_seq_pct`.

Severity: info — an RLS table that sequentially scans is a performance gap
to close (usually a missing or unused index on the policy predicate), not a
live security hole. Table-level counters count *every* sequential scan, not
only RLS-driven ones, so this points you where to look rather than proving
RLS is the cause; pair it with `pgrls perf` for the confirmed-vs-index-unused
breakdown. Allowlist a table's qualified name to accept it as intentional.
"""
from __future__ import annotations

from typing import Any

from pgrls.model import Schema
from pgrls.perf import PerfThresholds, TableStats, under_seq_scan_pressure
from pgrls.rules._allowlist import parse_table_ref_allowlist
from pgrls.violations import Severity, Violation


def _thresholds_from_options(options: dict[str, Any]) -> PerfThresholds:
    """Build thresholds from per-rule options, falling back to the defaults.

    A non-numeric / out-of-range value in the config falls back to the
    default for that field rather than raising — a typo shouldn't crash the
    whole lint run.
    """
    defaults = PerfThresholds()

    def _int(key: str, default: int) -> int:
        try:
            return int(options[key])
        except (KeyError, TypeError, ValueError):
            return default

    def _float(key: str, default: float) -> float:
        try:
            return float(options[key])
        except (KeyError, TypeError, ValueError):
            return default

    return PerfThresholds(
        min_live_tup=_int("min_rows", defaults.min_live_tup),
        min_seq_scans=_int("min_seq_scans", defaults.min_seq_scans),
        min_seq_pct=_float("min_seq_pct", defaults.min_seq_pct),
    )


class PERF005:
    id: str = "PERF005"
    severity: Severity = "info"
    title: str = "RLS table observed to sequentially scan in production"

    def check(
        self, schema: Schema, options: dict[str, Any]
    ) -> list[Violation]:
        perf = options.get("_perf")
        if not isinstance(perf, dict):
            # Opt-in: no runtime-stats artifact was wired in (lint run
            # without --perf). Stay silent.
            return []
        allowlist = parse_table_ref_allowlist("PERF005", options)
        thresholds = _thresholds_from_options(options)
        out: list[Violation] = []
        for table in schema.tables:
            if not table.rls_enabled:
                continue
            if (
                table.name in allowlist
                or table.qualified_name in allowlist
            ):
                continue
            ts = perf.get((table.schema, table.name))
            if not isinstance(ts, TableStats):
                continue
            if not under_seq_scan_pressure(ts, thresholds):
                continue
            out.append(
                Violation(
                    rule_id=self.id,
                    severity=self.severity,
                    title=self.title,
                    message=(
                        f"{table.qualified_name} (RLS-enabled) was "
                        f"sequentially scanned {ts.seq_scan:,} time(s), "
                        f"reading {ts.seq_tup_read:,} row(s) "
                        f"({ts.seq_scan_pct}% of its scans), per the runtime "
                        "stats snapshot — a likely missing or unused index "
                        "on the policy predicate. Run `pgrls perf` for the "
                        "confirmed-vs-index-unused breakdown, add the index, "
                        f"or allowlist {table.qualified_name!r} in "
                        "[lint.rules.PERF005]."
                    ),
                    location=table.qualified_name,
                )
            )
        return out
