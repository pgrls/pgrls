"""Tests for `pgrls history` — the snapshot-trend command."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from click.testing import CliRunner

from pgrls.cli import main
from pgrls.history import (
    FindingKey,
    HISTORY_FORMATS,
    Snapshot,
    SnapshotRow,
    build_rows,
    load_snapshots,
    render,
    render_json,
    render_markdown,
    render_text,
)


# Each fixture file's mtime drives chronological ordering. Tests
# explicitly `os.utime`-set the mtimes so insertion order in tmp_path
# can't accidentally pin a test.
def _write_snapshot(
    path: Path,
    violations: list[dict],
    *,
    mtime: datetime,
) -> None:
    payload = {
        "violations": violations,
        "summary": {
            "errors": sum(1 for v in violations if v.get("severity") == "error"),
            "warnings": sum(1 for v in violations if v.get("severity") == "warning"),
            "infos": sum(1 for v in violations if v.get("severity") == "info"),
            "total": len(violations),
        },
    }
    path.write_text(json.dumps(payload), encoding="utf-8")
    epoch = mtime.timestamp()
    import os
    os.utime(path, (epoch, epoch))


def _v(rule: str, loc: str | None = None, sev: str = "error") -> dict:
    return {
        "rule_id": rule,
        "severity": sev,
        "title": "t",
        "message": "m",
        "location": loc,
    }


# ──────────────────────────────────────────────────────────────────
# load_snapshots / build_rows
# ──────────────────────────────────────────────────────────────────


def test_load_snapshots_sorts_by_mtime(tmp_path: Path) -> None:
    a = tmp_path / "a.json"
    b = tmp_path / "b.json"
    c = tmp_path / "c.json"
    # Insertion order is a, b, c — but mtimes are c < a < b. Order
    # by mtime must win, not filename or insertion order.
    _write_snapshot(
        c, [_v("SEC001", "t1")],
        mtime=datetime(2026, 5, 1, tzinfo=timezone.utc),
    )
    _write_snapshot(
        a, [_v("SEC001", "t1"), _v("SEC002", "t2")],
        mtime=datetime(2026, 5, 10, tzinfo=timezone.utc),
    )
    _write_snapshot(
        b, [_v("SEC001", "t1")],
        mtime=datetime(2026, 5, 20, tzinfo=timezone.utc),
    )
    snaps = load_snapshots(tmp_path)
    assert [s.path.name for s in snaps] == ["c.json", "a.json", "b.json"]


def test_load_snapshots_skips_unparseable_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    good = tmp_path / "good.json"
    bad = tmp_path / "bad.json"
    _write_snapshot(
        good, [_v("SEC001", "t1")],
        mtime=datetime(2026, 5, 10, tzinfo=timezone.utc),
    )
    # Not valid JSON at all.
    bad.write_text("not json", encoding="utf-8")
    snaps = load_snapshots(tmp_path)
    assert [s.path.name for s in snaps] == ["good.json"]
    # Skipped file is logged to stderr — operator sees what happened.
    captured = capsys.readouterr()
    assert "bad.json" in captured.err


def test_load_snapshots_skips_non_pgrls_json(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # A valid JSON file that doesn't have the pgrls shape (e.g. a
    # stray package-lock.json fragment) is skipped with a clear
    # message — it must not crash the command.
    foreign = tmp_path / "package.json"
    foreign.write_text(json.dumps({"name": "x"}), encoding="utf-8")
    snaps = load_snapshots(tmp_path)
    assert snaps == []
    assert "package.json" in capsys.readouterr().err


def test_load_snapshots_errors_on_missing_directory(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_snapshots(tmp_path / "no_such_dir")


def test_build_rows_first_snapshot_baseline_is_all_new() -> None:
    # The first snapshot has no prior baseline, so every finding
    # counts as NEW and fixed_count is 0. Downstream summaries
    # exclude the first snapshot's new_count from the
    # "total_new across the series" tally to avoid double-counting.
    snap = Snapshot(
        path=Path("a.json"),
        timestamp=datetime(2026, 5, 1, tzinfo=timezone.utc),
        findings=frozenset({
            FindingKey("SEC001", "t1"),
            FindingKey("SEC002", "t2"),
        }),
        raw_total=2,
        counts={"error": 2, "warning": 0, "info": 0},
    )
    [row] = build_rows([snap])
    assert row.new_count == 2
    assert row.fixed_count == 0


def test_build_rows_computes_new_and_fixed_delta() -> None:
    snap_a = Snapshot(
        path=Path("a.json"),
        timestamp=datetime(2026, 5, 1, tzinfo=timezone.utc),
        findings=frozenset({
            FindingKey("SEC001", "t1"),
            FindingKey("SEC002", "t2"),
        }),
        raw_total=2,
        counts={"error": 2, "warning": 0, "info": 0},
    )
    # snap_b: SEC001 on t1 persists, SEC002 on t2 is fixed,
    # PERF001 on t3 is new.
    snap_b = Snapshot(
        path=Path("b.json"),
        timestamp=datetime(2026, 5, 10, tzinfo=timezone.utc),
        findings=frozenset({
            FindingKey("SEC001", "t1"),
            FindingKey("PERF001", "t3"),
        }),
        raw_total=2,
        counts={"error": 1, "warning": 1, "info": 0},
    )
    rows = build_rows([snap_a, snap_b])
    assert rows[1].new_count == 1
    assert rows[1].fixed_count == 1


def test_build_rows_treats_none_location_as_stable_identity() -> None:
    # SEC016 fires schema-wide (location=None); two snapshots both
    # carrying that finding must compare PERSISTENT, not NEW+FIXED
    # on every comparison.
    schema_wide = FindingKey("SEC016", None)
    snap_a = Snapshot(
        path=Path("a.json"),
        timestamp=datetime(2026, 5, 1, tzinfo=timezone.utc),
        findings=frozenset({schema_wide}),
        raw_total=1,
        counts={"error": 0, "warning": 1, "info": 0},
    )
    snap_b = Snapshot(
        path=Path("b.json"),
        timestamp=datetime(2026, 5, 10, tzinfo=timezone.utc),
        findings=frozenset({schema_wide}),
        raw_total=1,
        counts={"error": 0, "warning": 1, "info": 0},
    )
    rows = build_rows([snap_a, snap_b])
    assert rows[1].new_count == 0
    assert rows[1].fixed_count == 0


# ──────────────────────────────────────────────────────────────────
# Renderers
# ──────────────────────────────────────────────────────────────────


def _mkrow(
    name: str,
    total: int,
    errors: int = 0,
    warnings: int = 0,
    infos: int = 0,
    new: int = 0,
    fixed: int = 0,
    findings: frozenset[FindingKey] | None = None,
    when: datetime | None = None,
) -> SnapshotRow:
    return SnapshotRow(
        snapshot=Snapshot(
            path=Path(name),
            timestamp=when or datetime(2026, 5, 20, tzinfo=timezone.utc),
            findings=findings or frozenset(),
            raw_total=total,
            counts={"error": errors, "warning": warnings, "info": infos},
        ),
        new_count=new,
        fixed_count=fixed,
    )


def test_render_text_has_headers_rows_and_summary() -> None:
    rows = [_mkrow("a.json", total=4, errors=3, infos=1, new=4)]
    out = render_text(rows)
    assert "TIMESTAMP" in out and "NEW" in out and "FIXED" in out
    assert "a.json" in out
    assert "4" in out
    # Single-snapshot summary line uses singular "1 snapshot".
    assert "1 snapshot, 4 findings." in out


def test_render_text_empty_says_no_snapshots() -> None:
    assert "No snapshots found" in render_text([])


def test_render_text_dash_for_zero_new_and_fixed() -> None:
    # Zero new / fixed renders as `-` so the table doesn't bloat
    # with a sea of zeros for snapshots that didn't change.
    rows = [
        _mkrow("a.json", total=1, errors=1, new=1),
        _mkrow("b.json", total=1, errors=1, new=0, fixed=0,
               when=datetime(2026, 5, 21, tzinfo=timezone.utc)),
    ]
    out = render_text(rows)
    # The b.json row has new=0, fixed=0 → both should render `-`.
    last_line = [
        line for line in out.splitlines() if "b.json" in line
    ][0]
    parts = last_line.split()
    # NEW and FIXED are the last two columns.
    assert parts[-1] == "-"
    assert parts[-2] == "-"


def test_render_json_shape() -> None:
    rows = [
        _mkrow("a.json", total=2, errors=2, new=2,
               when=datetime(2026, 5, 1, tzinfo=timezone.utc)),
        _mkrow("b.json", total=1, errors=1, new=0, fixed=1,
               when=datetime(2026, 5, 10, tzinfo=timezone.utc)),
    ]
    payload = json.loads(render_json(rows))
    assert "snapshots" in payload and "summary" in payload
    assert len(payload["snapshots"]) == 2
    s = payload["snapshots"][1]
    assert s["file"] == "b.json"
    assert s["total"] == 1 and s["errors"] == 1
    assert s["new"] == 0 and s["fixed"] == 1
    assert payload["summary"]["snapshots"] == 2
    assert payload["summary"]["net_change"] == -1
    # The summary's `total_new` skips the first snapshot's
    # baseline-is-all-new count — only NEWs after a real baseline.
    assert payload["summary"]["total_new"] == 0
    assert payload["summary"]["total_fixed"] == 1


def test_render_markdown_table() -> None:
    rows = [_mkrow("a.json", total=2, errors=2, new=2)]
    out = render_markdown(rows)
    assert "## pgrls history" in out
    assert "| Timestamp | File | Total |" in out
    assert "| `a.json` |" in out
    # Empty new/fixed in markdown uses em-dash for visual airiness.
    rows_b = _mkrow(
        "b.json", total=2, errors=2, new=0, fixed=0,
        when=datetime(2026, 5, 21, tzinfo=timezone.utc),
    )
    out_two = render_markdown(rows + [rows_b])
    assert "| — | — |" in out_two


def test_render_markdown_empty_message() -> None:
    out = render_markdown([])
    assert "## pgrls history" in out
    assert "No snapshots" in out


def test_render_dispatch_table_covers_all_formats() -> None:
    rows = [_mkrow("a.json", total=1, errors=1, new=1)]
    for fmt in HISTORY_FORMATS:
        out = render(rows, fmt)  # type: ignore[arg-type]
        assert out.strip(), f"format {fmt} produced empty output"


# ──────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────


def test_history_cli_runs_against_snapshot_dir(tmp_path: Path) -> None:
    _write_snapshot(
        tmp_path / "a.json",
        [_v("SEC001", "t1"), _v("SEC002", "t2")],
        mtime=datetime(2026, 5, 1, tzinfo=timezone.utc),
    )
    _write_snapshot(
        tmp_path / "b.json",
        [_v("SEC001", "t1")],
        mtime=datetime(2026, 5, 10, tzinfo=timezone.utc),
    )
    result = CliRunner().invoke(main, ["history", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "a.json" in result.output
    assert "b.json" in result.output
    assert "2 snapshots" in result.output


def test_history_cli_json_format(tmp_path: Path) -> None:
    _write_snapshot(
        tmp_path / "only.json",
        [_v("SEC001", "t1")],
        mtime=datetime(2026, 5, 10, tzinfo=timezone.utc),
    )
    result = CliRunner().invoke(
        main, ["history", str(tmp_path), "--format", "json"]
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["snapshots"][0]["file"] == "only.json"


def test_history_cli_markdown_format(tmp_path: Path) -> None:
    _write_snapshot(
        tmp_path / "only.json",
        [_v("SEC001", "t1")],
        mtime=datetime(2026, 5, 10, tzinfo=timezone.utc),
    )
    result = CliRunner().invoke(
        main, ["history", str(tmp_path), "--format", "markdown"]
    )
    assert result.exit_code == 0, result.output
    assert "## pgrls history" in result.output


def test_history_cli_output_file_matches_stdout(tmp_path: Path) -> None:
    _write_snapshot(
        tmp_path / "a.json",
        [_v("SEC001", "t1")],
        mtime=datetime(2026, 5, 10, tzinfo=timezone.utc),
    )
    out_path = tmp_path / "trend.json"
    runner = CliRunner()
    args = ["history", str(tmp_path), "--format", "json"]
    stdout_res = runner.invoke(main, args)
    file_res = runner.invoke(main, [*args, "--output", str(out_path)])
    assert file_res.exit_code == 0, file_res.output
    assert file_res.output == ""  # --output suppresses stdout
    assert out_path.read_text(encoding="utf-8") == stdout_res.output


def test_history_cli_missing_directory_exits_cleanly(tmp_path: Path) -> None:
    result = CliRunner().invoke(
        main, ["history", str(tmp_path / "nope")]
    )
    # Missing dir is a tool error (exit 2), not a Python traceback.
    assert result.exit_code == 2
    assert "Traceback" not in result.output


def test_history_cli_empty_directory_renders_no_snapshots(
    tmp_path: Path,
) -> None:
    result = CliRunner().invoke(main, ["history", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "No snapshots" in result.output
