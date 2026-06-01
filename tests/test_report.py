"""Unit tests for `pgrls report` — the RLS posture summary."""
from __future__ import annotations

import json

from click.testing import CliRunner

from pgrls.cli import main
from pgrls.model import Policy, Schema, Table
from pgrls.report import (
    build_report,
    render_html,
    render_json,
    render_markdown,
    render_text,
)


def _policy(permissive: bool = True, name: str = "p") -> Policy:
    return Policy(
        name=name,
        command="SELECT",
        permissive=permissive,
        roles=("public",),
        using_sql="true",
        with_check_sql=None,
    )


def _table(
    name: str,
    *,
    rls: bool,
    force: bool,
    policies: tuple[Policy, ...] = (),
) -> Table:
    return Table(
        schema="public",
        name=name,
        rls_enabled=rls,
        force_rls=force,
        policies=policies,
    )


def test_status_precedence() -> None:
    schema = Schema(
        tables=(
            # RLS off, but has policies → still "rls-off" (dormant).
            _table("off", rls=False, force=True, policies=(_policy(),)),
            _table("nopol", rls=True, force=True, policies=()),
            _table("unforced", rls=True, force=False, policies=(_policy(),)),
            _table("good", rls=True, force=True, policies=(_policy(),)),
        )
    )
    statuses = {t.qualified_name: t.status for t in build_report(schema).tables}
    assert statuses["public.off"] == "rls-off"
    assert statuses["public.nopol"] == "no-policies"
    assert statuses["public.unforced"] == "not-forced"
    assert statuses["public.good"] == "protected"


def test_partition_child_covered_by_rls_parent() -> None:
    # Postgres doesn't propagate relrowsecurity to partition children,
    # but queries through the parent apply its policies — so a child of
    # an RLS-enabled parent is "covered-by-parent", not "rls-off"
    # (mirrors how SEC001 skips such children).
    parent = _table("events", rls=True, force=True, policies=(_policy(),))
    child = Table(
        schema="public",
        name="events_2026",
        rls_enabled=False,
        force_rls=False,
        policies=(),
        partition_of=("public", "events"),
    )
    rep = build_report(Schema(tables=(parent, child)))
    statuses = {t.qualified_name: t.status for t in rep.tables}
    assert statuses["public.events"] == "protected"
    assert statuses["public.events_2026"] == "covered-by-parent"
    assert rep.summary["status_covered_by_parent"] == 1


def test_partition_child_rls_off_when_parent_has_no_rls() -> None:
    # No RLS-enabled ancestor → the child is genuinely "rls-off".
    parent = _table("events", rls=False, force=False)
    child = Table(
        schema="public",
        name="events_2026",
        rls_enabled=False,
        force_rls=False,
        policies=(),
        partition_of=("public", "events"),
    )
    statuses = {
        t.qualified_name: t.status
        for t in build_report(Schema(tables=(parent, child))).tables
    }
    assert statuses["public.events_2026"] == "rls-off"


def test_restrictive_only_forced_is_no_policies_not_protected() -> None:
    # RLS on + FORCE but only RESTRICTIVE policies → no permissive policy
    # grants visibility, so it's default-deny, NOT the green "protected".
    schema = Schema(
        tables=(
            _table(
                "locked",
                rls=True,
                force=True,
                policies=(_policy(permissive=False),),
            ),
        )
    )
    [t] = build_report(schema).tables
    assert t.permissive_count == 0
    assert t.restrictive_count == 1
    assert t.status == "no-policies"


def test_permissive_restrictive_counts() -> None:
    schema = Schema(
        tables=(
            _table(
                "t",
                rls=True,
                force=True,
                policies=(
                    _policy(True, "a"),
                    _policy(False, "b"),
                    _policy(True, "c"),
                ),
            ),
        )
    )
    [t] = build_report(schema).tables
    assert t.policy_count == 3
    assert t.permissive_count == 2
    assert t.restrictive_count == 1


def test_summary_aggregates() -> None:
    schema = Schema(
        tables=(
            _table("off", rls=False, force=False),
            _table("good", rls=True, force=True, policies=(_policy(),)),
        )
    )
    s = build_report(schema).summary
    assert s["tables"] == 2
    assert s["rls_enabled"] == 1
    assert s["forced"] == 1
    assert s["with_policies"] == 1
    assert s["status_rls_off"] == 1
    assert s["status_protected"] == 1


def test_tables_sorted_by_qualified_name() -> None:
    schema = Schema(
        tables=(
            _table("z", rls=True, force=True, policies=(_policy(),)),
            _table("a", rls=True, force=True, policies=(_policy(),)),
        )
    )
    names = [t.qualified_name for t in build_report(schema).tables]
    assert names == ["public.a", "public.z"]


def test_render_text_has_headers_rows_and_summary() -> None:
    schema = Schema(
        tables=(_table("good", rls=True, force=True, policies=(_policy(),)),)
    )
    out = render_text(build_report(schema))
    assert "TABLE" in out and "STATUS" in out and "POLICIES" in out
    assert "public.good" in out
    assert "protected" in out
    assert "1 table: 1 protected." in out  # pluralized, non-zero only


def test_render_text_empty_schema() -> None:
    assert "No tables found" in render_text(build_report(Schema(tables=())))


def test_render_json_shape() -> None:
    schema = Schema(
        tables=(_table("good", rls=True, force=True, policies=(_policy(),)),)
    )
    payload = json.loads(render_json(build_report(schema)))
    assert payload["summary"]["tables"] == 1
    row = payload["tables"][0]
    assert row["table"] == "public.good"
    assert row["status"] == "protected"
    assert row["rls_enabled"] is True
    assert row["force_rls"] is True
    assert row["policies"] == 1


def test_render_markdown_table() -> None:
    schema = Schema(
        tables=(_table("good", rls=True, force=True, policies=(_policy(),)),)
    )
    out = render_markdown(build_report(schema))
    assert "# RLS posture" in out
    assert "| Table | Status | RLS | FORCE | Policies |" in out
    assert "| public.good | protected | yes | yes | 1 |" in out


def _report_data_rows(out: str) -> list[str]:
    """The data rows of a `render_markdown` pipe-table (drop heading,
    blank lines, summary line, and the header + separator rows)."""
    return [
        ln
        for ln in out.splitlines()
        if ln.startswith("|") and "---" not in ln and "| Table |" not in ln
    ]


def test_render_markdown_pipe_in_name_does_not_corrupt_table() -> None:
    # A `|` inside a quoted Postgres identifier must be escaped so it
    # doesn't add a phantom column to the GFM row. Regression for
    # audit finding #15.
    schema = Schema(
        tables=(_table("we|rd", rls=True, force=True, policies=(_policy(),)),)
    )
    out = render_markdown(build_report(schema))
    data_rows = _report_data_rows(out)
    assert len(data_rows) == 1
    row = data_rows[0]
    # The literal pipe is backslash-escaped, not a cell separator.
    assert "we\\|rd" in row
    # Exactly 5 columns → 6 unescaped pipe delimiters (leading,
    # trailing, and 4 interior). Count pipes that are NOT escaped.
    assert row.replace("\\|", "").count("|") == 6


def test_render_markdown_newline_in_name_does_not_split_row() -> None:
    # A `\n` inside a quoted identifier would otherwise end the GFM
    # row early and push the rest onto a new line. `safe_location`
    # rewrites it to the two-char `\n` text. Regression for #15.
    schema = Schema(
        tables=(_table("we\nrd", rls=True, force=True, policies=(_policy(),)),)
    )
    out = render_markdown(build_report(schema))
    data_rows = _report_data_rows(out)
    assert len(data_rows) == 1
    # The visible escape text appears; no raw newline inside the row.
    assert "we\\nrd" in data_rows[0]


def test_render_text_newline_in_name_does_not_split_row() -> None:
    # The fixed-width text table must stay one line per table even
    # when a name carries a newline, or column alignment and any
    # line-anchored CI grep break. Regression for audit finding #23.
    schema = Schema(
        tables=(_table("we\nrd", rls=True, force=True, policies=(_policy(),)),)
    )
    out = render_text(build_report(schema))
    # The data row carries the visible `\n` escape, not a raw newline.
    data_lines = [ln for ln in out.splitlines() if "we" in ln]
    assert len(data_lines) == 1
    assert "we\\nrd" in data_lines[0]
    assert "protected" in data_lines[0]


def test_render_text_pipe_in_name_is_left_literal() -> None:
    # The text table has no pipe-delimiter semantics, so a `|` in a
    # name passes through unescaped (only newline / control / zero-
    # width chars are rewritten). Confirms `safe_location` is a no-op
    # on pipes for the text path. Regression for #23.
    schema = Schema(
        tables=(_table("we|rd", rls=True, force=True, policies=(_policy(),)),)
    )
    out = render_text(build_report(schema))
    assert "public.we|rd" in out


# ──────────────────────────────────────────────────────────────────
# HTML format
# ──────────────────────────────────────────────────────────────────


def test_render_html_is_self_contained_document() -> None:
    schema = Schema(
        tables=(_table("good", rls=True, force=True, policies=(_policy(),)),)
    )
    out = render_html(build_report(schema))
    # Doctype + html/head/body skeleton
    assert out.startswith("<!DOCTYPE html>")
    assert "<html lang=\"en\">" in out
    assert "</html>" in out
    # Embedded style block — no external CSS/JS, so the page opens
    # offline and renders identically in `wkhtmltopdf`-style tools.
    assert "<style>" in out and "</style>" in out
    assert "<link" not in out
    assert "<script" not in out


def test_render_html_table_carries_rows() -> None:
    schema = Schema(
        tables=(
            _table("good", rls=True, force=True, policies=(_policy(),)),
            _table("off", rls=False, force=False),
        )
    )
    out = render_html(build_report(schema))
    # Rows render with the row-class encoding their status — a CSS
    # consumer (or a downstream tool that extends the stylesheet)
    # can target them.
    assert 'class="row-protected"' in out
    assert 'class="row-rls-off"' in out
    # Both qualified names appear; both yes/no toggles render.
    assert "<code>public.good</code>" in out
    assert "<code>public.off</code>" in out


def test_render_html_summary_pills_show_nonzero_statuses_only() -> None:
    schema = Schema(
        tables=(
            _table("good", rls=True, force=True, policies=(_policy(),)),
            _table("off1", rls=False, force=False),
            _table("off2", rls=False, force=False),
        )
    )
    out = render_html(build_report(schema))
    # Two chip spans render — one per status with a non-zero count.
    # Assert on the full chip pattern (not just the word) so the
    # `.status-not-forced` CSS class can't accidentally satisfy a
    # `"not forced" in out` match.
    assert '<span class="pill status-protected">' in out
    assert '<span class="pill status-rls-off">' in out
    assert '<span class="pill status-not-forced">' not in out
    assert '<span class="pill status-no-policies">' not in out


def test_render_html_escapes_special_chars_in_table_name() -> None:
    # Postgres quoted identifiers permit `<`, `>`, `&`, `"` —
    # leaving them unescaped would break the page layout (or worse,
    # allow stored-XSS via a malicious table name in an audit
    # report opened from email).
    schema = Schema(
        tables=(
            _table('weird<name>&"', rls=True, force=True, policies=(_policy(),)),
        )
    )
    out = render_html(build_report(schema))
    # Raw special chars MUST NOT appear inside the rendered table
    # cell. Find the row content (after the row open tag) and check.
    assert "weird&lt;name&gt;&amp;&quot;" in out
    # …and the literal `<name>` must not appear as a tag.
    assert "<name>" not in out


def test_render_html_empty_schema_renders_placeholder() -> None:
    out = render_html(build_report(Schema(tables=())))
    # Valid HTML page, no rows; an explicit empty-state message
    # rather than a blank `<tbody>` that could look like a CSS bug.
    assert "<!DOCTYPE html>" in out
    # Total tables is interpolated as `<strong>0</strong> tables` —
    # the `<strong>` tags split the visible substring, so the
    # rendered form is what we pin.
    assert "<strong>0</strong> tables scanned." in out
    assert "No tables found" in out
    assert '<span class="pill status-empty">no tables</span>' in out


def test_render_html_carries_iso_utc_timestamp() -> None:
    schema = Schema(
        tables=(_table("good", rls=True, force=True, policies=(_policy(),)),)
    )
    out = render_html(build_report(schema))
    import re
    # Generated-at timestamp is ISO-8601 UTC with `Z` suffix so an
    # auditor reading the printed page can pin "when was this run?".
    # The regex is intentionally tight on the digit ranges so a
    # malformed `9999-99-99T99:99:99Z` value doesn't pass.
    assert re.search(
        r"\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])"
        r"T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\dZ",
        out,
    ), "expected a well-formed ISO-8601 UTC timestamp"


def test_render_html_accepts_injected_generated_at() -> None:
    # Snapshot-friendly: an explicit `generated_at` makes the output
    # deterministic across CI runs. Pins the contract that the
    # injected value is rendered verbatim (modulo sub-second drop
    # and UTC normalization).
    from datetime import datetime, timezone
    schema = Schema(
        tables=(_table("good", rls=True, force=True, policies=(_policy(),)),)
    )
    fixed = datetime(2026, 1, 15, 10, 30, 45, tzinfo=timezone.utc)
    out = render_html(build_report(schema), generated_at=fixed)
    assert "2026-01-15T10:30:45Z" in out


def test_render_html_normalizes_non_utc_generated_at_to_utc() -> None:
    # An explicit non-UTC `generated_at` is converted to UTC before
    # serialisation so the auditor never reads a non-Z-suffixed
    # timestamp out of the page.
    from datetime import datetime, timedelta, timezone
    schema = Schema(
        tables=(_table("good", rls=True, force=True, policies=(_policy(),)),)
    )
    cet = timezone(timedelta(hours=1))
    out = render_html(
        build_report(schema),
        generated_at=datetime(2026, 1, 15, 11, 30, 45, tzinfo=cet),
    )
    assert "2026-01-15T10:30:45Z" in out  # CET 11:30 → UTC 10:30


def test_render_html_rejects_naive_generated_at() -> None:
    # A naive datetime (no tzinfo) would be silently coerced through
    # the host's LOCAL timezone by `.astimezone(utc)` — producing a
    # wrong audit timestamp that depends on which CI runner generated
    # the report. The function refuses such input at the boundary
    # rather than emitting wrong data.
    import pytest
    from datetime import datetime
    schema = Schema(
        tables=(_table("good", rls=True, force=True, policies=(_policy(),)),)
    )
    with pytest.raises(ValueError, match="timezone-aware"):
        render_html(
            build_report(schema),
            generated_at=datetime(2026, 1, 15, 10, 30),
        )


def test_render_html_row_class_per_status() -> None:
    # Every status emits its CSS row class so a downstream
    # stylesheet (or a future feature like "highlight bad rows in
    # the printed audit") can target each status individually.
    parent = _table("evt", rls=True, force=True, policies=(_policy(),))
    child = Table(
        schema="public",
        name="evt_2026",
        rls_enabled=False,
        force_rls=False,
        policies=(),
        partition_of=("public", "evt"),
    )
    schema = Schema(
        tables=(
            parent,
            child,
            _table("nopol", rls=True, force=True, policies=()),
            _table("unforced", rls=True, force=False, policies=(_policy(),)),
            _table("off", rls=False, force=False),
        )
    )
    out = render_html(build_report(schema))
    for cls in (
        "row-protected",
        "row-not-forced",
        "row-no-policies",
        "row-covered-by-parent",
        "row-rls-off",
    ):
        assert f'class="{cls}"' in out, f"missing row class {cls}"


def test_render_html_is_registered_format() -> None:
    # Sanity: CLI dispatch table picks up `html`.
    from pgrls.report import REPORT_FORMATS, render
    assert "html" in REPORT_FORMATS
    schema = Schema(
        tables=(_table("good", rls=True, force=True, policies=(_policy(),)),)
    )
    out = render(build_report(schema), "html")
    assert out.startswith("<!DOCTYPE html>")


def test_report_cli_help() -> None:
    result = CliRunner().invoke(main, ["report", "--help"])
    assert result.exit_code == 0
    assert "RLS posture" in result.output


def test_report_cli_errors_without_database_url() -> None:
    # No --database-url and DATABASE_URL forced empty → ToolError exit 2.
    result = CliRunner().invoke(
        main, ["report"], env={"DATABASE_URL": ""}
    )
    assert result.exit_code == 2
    assert "No database connection" in result.output


# A conninfo that fails instantly at the psycopg layer (a Unix socket
# in a directory that cannot exist) — no DNS/TCP timeout, deterministic.
_BAD_SOCKET_URL = "postgresql://u@/db?host=/nonexistent_pgrls_socket_dir"


def test_report_cli_database_error_exits_2_cleanly() -> None:
    # A connection failing at the psycopg layer surfaces as a ToolError
    # (exit 2) with a "Database error" prefix, not a raw traceback.
    # Pins `report`'s `except psycopg.Error` branch.
    result = CliRunner().invoke(
        main, ["report", "--database-url", _BAD_SOCKET_URL]
    )
    assert result.exit_code == 2, result.output
    assert "Database error" in result.output
    assert "Traceback" not in result.output


def test_report_cli_unknown_schema_exits_2_cleanly(pg_url: str) -> None:
    # An unknown schema makes `introspect` raise ValueError; `report`
    # converts it to a ToolError (exit 2). Pins the `except ValueError`
    # branch alongside the psycopg one.
    result = CliRunner().invoke(
        main,
        ["report", "--database-url", pg_url, "--schemas", "no_such_schema"],
    )
    assert result.exit_code == 2, result.output
    assert "no_such_schema" in result.output
    assert "Traceback" not in result.output


def test_report_cli_bad_toml_exits_2_cleanly(tmp_path) -> None:
    # A malformed config file is a ConfigError surfaced as a ToolError
    # (exit 2) before any DB connection — the clean-error contract
    # `pgrls lint` / `fix` also follow. Pins `report`'s `except
    # ConfigError` branch.
    cfg = tmp_path / "pgrls.toml"
    cfg.write_text("[database\n")  # malformed TOML
    result = CliRunner().invoke(main, ["report", "--config", str(cfg)])
    assert result.exit_code == 2, result.output
    assert "Traceback" not in result.output


def test_report_output_writes_file_matching_stdout(
    pg_url: str, apply_sql, tmp_path
) -> None:
    # --output writes byte-for-byte what stdout would have shown, and
    # suppresses stdout — same contract as `lint --output`.
    apply_sql("CREATE TABLE public.t (id INT);")
    runner = CliRunner()
    args = ["report", "--database-url", pg_url, "--format", "json"]
    stdout_res = runner.invoke(main, args)
    assert stdout_res.exit_code == 0, stdout_res.output

    out = tmp_path / "posture.json"
    file_res = runner.invoke(main, [*args, "--output", str(out)])
    assert file_res.exit_code == 0, file_res.output
    assert file_res.output == ""  # --output suppresses stdout
    assert out.read_text(encoding="utf-8") == stdout_res.output
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert any(t["table"] == "public.t" for t in payload["tables"])


def test_report_output_unwritable_path_errors(
    pg_url: str, apply_sql, tmp_path
) -> None:
    # A path whose parent dir is missing → OSError surfaced as a clean
    # ToolError (exit 2), not a traceback. Mirrors `pgrls init`.
    apply_sql("CREATE TABLE public.t (id INT);")
    out = tmp_path / "missing_dir" / "posture.json"
    result = CliRunner().invoke(
        main, ["report", "--database-url", pg_url, "--output", str(out)]
    )
    assert result.exit_code == 2
    assert "Cannot write" in result.output
