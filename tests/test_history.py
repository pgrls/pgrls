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
    render_html,
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


def test_read_snapshot_buckets_off_spec_severity_into_other(
    tmp_path: Path,
) -> None:
    # An external rule plugin may write a snapshot carrying a severity
    # pgrls doesn't model ("critical"/"blocker"). _read_snapshot must
    # bucket those under 'other' so error+warning+info+other reconciles
    # to raw_total — otherwise the three modeled columns silently
    # under-sum the total in every history view.
    _write_snapshot(
        tmp_path / "snap.json",
        [
            _v("SEC001", "public.a", sev="error"),
            _v("X001", "public.b", sev="critical"),
            _v("X002", "public.c", sev="blocker"),
        ],
        mtime=datetime(2026, 5, 1, tzinfo=timezone.utc),
    )
    snaps = load_snapshots(tmp_path)
    assert len(snaps) == 1
    counts = snaps[0].counts
    assert counts["error"] == 1
    assert counts["other"] == 2
    assert (
        counts["error"]
        + counts["warning"]
        + counts["info"]
        + counts["other"]
        == snaps[0].raw_total
        == 3
    )


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


def _history_md_data_rows(out: str) -> list[str]:
    return [
        ln
        for ln in out.splitlines()
        if ln.startswith("|") and "---" not in ln and "| Timestamp |" not in ln
    ]


def test_render_markdown_pipe_in_filename_does_not_corrupt_table() -> None:
    # A `|` in a snapshot filename must be escaped inside the backtick
    # code span so it doesn't add a phantom GFM column. Regression for
    # audit finding #20.
    rows = [_mkrow("we|rd.json", total=2, errors=2, new=2)]
    out = render_markdown(rows)
    data_rows = _history_md_data_rows(out)
    assert len(data_rows) == 1
    row = data_rows[0]
    assert "we\\|rd.json" in row
    # 8 columns → 9 unescaped pipe delimiters.
    assert row.replace("\\|", "").count("|") == 9


def test_render_markdown_newline_in_filename_does_not_split_row() -> None:
    # Regression for #20: a `\n` in the filename would end the GFM row
    # early. `safe_location` rewrites it to the two-char `\n` text.
    rows = [_mkrow("we\nrd.json", total=2, errors=2, new=2)]
    out = render_markdown(rows)
    data_rows = _history_md_data_rows(out)
    assert len(data_rows) == 1
    assert "we\\nrd.json" in data_rows[0]


def test_render_text_newline_in_filename_does_not_split_row() -> None:
    # The history text table interpolates the snapshot filename too;
    # a `\n` (POSIX filenames allow any byte but `/` and NUL) would
    # split the fixed-width row. Same class as audit finding #23.
    rows = [_mkrow("we\nrd.json", total=2, errors=2, new=2)]
    out = render_text(rows)
    data_lines = [ln for ln in out.splitlines() if "rd.json" in ln]
    assert len(data_lines) == 1
    assert "we\\nrd.json" in data_lines[0]


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


# ──────────────────────────────────────────────────────────────────
# HTML format
# ──────────────────────────────────────────────────────────────────


def test_render_html_is_self_contained_document() -> None:
    rows = build_rows([
        Snapshot(
            path=Path("a.json"),
            timestamp=datetime(2026, 5, 10, tzinfo=timezone.utc),
            findings=frozenset({FindingKey("SEC001", "public.t1")}),
            raw_total=1,
            counts={"error": 1, "warning": 0, "info": 0},
        ),
    ])
    out = render_html(rows)
    assert out.startswith("<!DOCTYPE html>")
    assert '<html lang="en">' in out
    assert "</html>" in out
    # Embedded style block — no external CSS/JS, so the page
    # opens offline and renders identically in `wkhtmltopdf`-style
    # tools (same constraint pgrls report --format html honours).
    assert "<style>" in out and "</style>" in out
    assert "<link" not in out
    assert "<script" not in out


def test_render_html_carries_iso_utc_timestamp() -> None:
    rows = build_rows([
        Snapshot(
            path=Path("a.json"),
            timestamp=datetime(2026, 5, 10, tzinfo=timezone.utc),
            findings=frozenset(),
            raw_total=0,
            counts={"error": 0, "warning": 0, "info": 0},
        ),
    ])
    out = render_html(rows)
    import re
    assert re.search(
        r"\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])"
        r"T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\dZ",
        out,
    )


def test_render_html_accepts_injected_generated_at() -> None:
    rows = build_rows([
        Snapshot(
            path=Path("a.json"),
            timestamp=datetime(2026, 5, 10, tzinfo=timezone.utc),
            findings=frozenset(),
            raw_total=0,
            counts={"error": 0, "warning": 0, "info": 0},
        ),
    ])
    fixed = datetime(2026, 1, 15, 10, 30, 45, tzinfo=timezone.utc)
    out = render_html(rows, generated_at=fixed)
    assert "2026-01-15T10:30:45Z" in out


def test_render_html_rejects_naive_generated_at() -> None:
    # Mirrors pgrls report --format html: naive datetimes silently
    # become wrong-by-host-timezone audit timestamps, so the
    # renderer refuses at the boundary.
    import pytest
    rows: list[SnapshotRow] = []
    with pytest.raises(ValueError, match="timezone-aware"):
        render_html(rows, generated_at=datetime(2026, 1, 15, 10, 30))


def test_render_html_normalizes_non_utc_generated_at_to_utc() -> None:
    from datetime import timedelta
    cet = timezone(timedelta(hours=1))
    rows = build_rows([
        Snapshot(
            path=Path("a.json"),
            timestamp=datetime(2026, 5, 10, tzinfo=timezone.utc),
            findings=frozenset(),
            raw_total=0,
            counts={"error": 0, "warning": 0, "info": 0},
        ),
    ])
    out = render_html(
        rows, generated_at=datetime(2026, 1, 15, 11, 30, 45, tzinfo=cet)
    )
    assert "2026-01-15T10:30:45Z" in out  # CET 11:30 → UTC 10:30


def test_render_html_table_carries_per_snapshot_rows() -> None:
    rows = build_rows([
        Snapshot(
            path=Path("2026-05-15.json"),
            timestamp=datetime(2026, 5, 15, 8, tzinfo=timezone.utc),
            findings=frozenset({
                FindingKey("SEC001", "public.t1"),
                FindingKey("SEC002", "public.t2"),
            }),
            raw_total=2,
            counts={"error": 2, "warning": 0, "info": 0},
        ),
        Snapshot(
            path=Path("2026-05-20.json"),
            timestamp=datetime(2026, 5, 20, 8, tzinfo=timezone.utc),
            findings=frozenset({FindingKey("SEC001", "public.t1")}),
            raw_total=1,
            counts={"error": 1, "warning": 0, "info": 0},
        ),
    ])
    out = render_html(rows)
    # Both filenames render (rendered as `<code>filename</code>`
    # mirroring the report formatter's identifier shape).
    assert "<code>2026-05-15.json</code>" in out
    assert "<code>2026-05-20.json</code>" in out
    # Both timestamps render in ISO-Z form.
    assert "2026-05-15T08:00:00Z" in out
    assert "2026-05-20T08:00:00Z" in out
    # NEW/FIXED highlight by colour when non-zero — the
    # `new` and `fixed` CSS classes carry the visual weight.
    # 2nd snapshot fixed 1 (SEC002) and added 0.
    assert "td class=\"num fixed\">1<" in out


def test_render_html_summary_band_shows_net_change_for_multi_snapshot() -> None:
    rows = build_rows([
        Snapshot(
            path=Path("a.json"),
            timestamp=datetime(2026, 5, 10, tzinfo=timezone.utc),
            findings=frozenset({FindingKey("SEC001", "t1"), FindingKey("SEC002", "t2")}),
            raw_total=2,
            counts={"error": 2, "warning": 0, "info": 0},
        ),
        Snapshot(
            path=Path("b.json"),
            timestamp=datetime(2026, 5, 20, tzinfo=timezone.utc),
            findings=frozenset(),
            raw_total=0,
            counts={"error": 0, "warning": 0, "info": 0},
        ),
    ])
    out = render_html(rows)
    # Summary band renders 2 → 0 with a green "net -2" badge.
    assert "<strong>2</strong>" in out
    assert "<strong>0</strong>" in out
    assert "net-good" in out  # net change is negative → good
    assert "net -2" in out


def test_render_html_summary_band_shows_negative_growth_as_bad() -> None:
    rows = build_rows([
        Snapshot(
            path=Path("a.json"),
            timestamp=datetime(2026, 5, 10, tzinfo=timezone.utc),
            findings=frozenset(),
            raw_total=0,
            counts={"error": 0, "warning": 0, "info": 0},
        ),
        Snapshot(
            path=Path("b.json"),
            timestamp=datetime(2026, 5, 20, tzinfo=timezone.utc),
            findings=frozenset({FindingKey("SEC001", "t1")}),
            raw_total=1,
            counts={"error": 1, "warning": 0, "info": 0},
        ),
    ])
    out = render_html(rows)
    assert "net-bad" in out  # finding count grew → bad
    assert "net +1" in out


def test_render_html_empty_rows_renders_placeholder() -> None:
    out = render_html([])
    assert "<!DOCTYPE html>" in out
    assert "No snapshots" in out
    assert "No snapshots in this directory" in out


def test_render_html_escapes_special_chars_in_filename() -> None:
    # A directory could (rarely) contain a filename with `<`, `>`,
    # `&` — Postgres backups dumped from scripts that templated the
    # filename without sanitization. Escape to keep the layout
    # intact and prevent script-injection if the HTML is opened in
    # a browser from an untrusted source.
    rows = build_rows([
        Snapshot(
            path=Path('weird<name>&.json'),
            timestamp=datetime(2026, 5, 10, tzinfo=timezone.utc),
            findings=frozenset(),
            raw_total=0,
            counts={"error": 0, "warning": 0, "info": 0},
        ),
    ])
    out = render_html(rows)
    assert "weird&lt;name&gt;&amp;.json" in out
    # The literal `<name>` must not appear as a tag.
    assert "<name>" not in out


def test_render_html_is_registered_format() -> None:
    assert "html" in HISTORY_FORMATS
    rows = build_rows([
        Snapshot(
            path=Path("a.json"),
            timestamp=datetime(2026, 5, 10, tzinfo=timezone.utc),
            findings=frozenset(),
            raw_total=0,
            counts={"error": 0, "warning": 0, "info": 0},
        ),
    ])
    out = render(rows, "html")
    assert out.startswith("<!DOCTYPE html>")


def test_history_cli_html_format(tmp_path: Path) -> None:
    _write_snapshot(
        tmp_path / "only.json",
        [_v("SEC001", "t1")],
        mtime=datetime(2026, 5, 10, tzinfo=timezone.utc),
    )
    result = CliRunner().invoke(
        main, ["history", str(tmp_path), "--format", "html"]
    )
    assert result.exit_code == 0, result.output
    assert "<!DOCTYPE html>" in result.output
    assert "pgrls history" in result.output
