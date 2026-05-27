"""HTML formatter for `pgrls lint`.

Designed for the same reading context the report/history/diff HTML
formatters serve: archive a lint result as a standalone artefact,
print to PDF, email to a stakeholder who doesn't run pgrls. Distinct
from `pr-comment` (which produces Markdown + embedded HTML
`<details>` blocks suitable for pasting into a GitHub PR comment) —
this formatter renders a full, self-contained HTML5 document with
embedded CSS, no `<link>` / `<script>` external assets.

Each violation renders as one row with a severity-coloured pill,
the rule ID (linked to its `docs/RULES.md` anchor), location, and
message. A summary band on top carries the per-severity counts as
coloured chips so the at-a-glance read of "is this clean?" doesn't
require parsing the table.

Visual fingerprint matches every other pgrls HTML formatter
(`report`, `history`, `diff`, `explain`) — same colour palette,
same dark-mode block, same ISO-Z timestamp.

Stable between releases of the same major-zero series; new columns
are a breaking change for consumers that parse the table.

Rule-link convention: `docs/RULES.md#rule-<lower>` for lint rules
(`SEC###` / `PERF###` / `HYG###` / `VIEW###`), `AGENTS.md#diff-rules`
for `DIFF_*`. Mirrors `formatters.markdown._rule_link` and
`formatters.pr_comment._rule_link`. A URL bump must land in all four
places simultaneously.
"""
from __future__ import annotations

import html
from collections import Counter
from datetime import datetime, timezone

from pgrls.formatters._common import (
    EMPTY_OR_ZERO_WIDTH_SENTINEL,
    safe_location,
)
from pgrls.violations import ALL_SEVERITIES, Severity, Violation

_SEVERITY_EMOJI: dict[Severity, str] = {
    "error": "❌",
    "warning": "⚠️",
    "info": "ℹ️",
}

_SEVERITY_COLOR: dict[Severity, str] = {
    "error": "#cf222e",    # red
    "warning": "#9a6700",  # amber
    "info": "#0969da",     # blue
}

# Same convention `pr_comment._rule_link` uses — keep synchronized.
_INFORMATION_URI = "https://github.com/pgrls/pgrls"


def _rule_link(rule_id: str) -> str:
    """Per-rule deep link. `DIFF_*` rules go to AGENTS.md#diff-rules;
    lint rule IDs point at `docs/RULES.md#rule-<lower>`."""
    if rule_id.startswith("DIFF_"):
        return (
            f"{_INFORMATION_URI}/blob/main/AGENTS.md#diff-rules"
        )
    return (
        f"{_INFORMATION_URI}/blob/main/docs/RULES.md#rule-"
        f"{rule_id.lower()}"
    )


def _safe_location_html(location: str | None) -> str:
    """Render `Violation.location` as escaped HTML text.

    `None` → `(schema-wide)` sentinel for rules like SEC016 that
    fire schema-wide. Zero-width-only locations fall back to the
    `(empty-or-zero-width)` sentinel that `pr_comment._safe_chip`
    and `markdown._location_cell` both use.
    """
    if not location:
        return html.escape("(schema-wide)")
    clean = safe_location(location)
    if not clean:
        return html.escape(EMPTY_OR_ZERO_WIDTH_SENTINEL)
    return html.escape(clean)


def format_html(
    violations: list[Violation],
    *,
    generated_at: datetime | None = None,
) -> str:
    """Render lint violations as a standalone HTML page.

    `generated_at` is optional and defaults to `datetime.now(utc)`.
    Pass an explicit timezone-aware datetime for deterministic
    snapshot tests; a naive datetime raises `ValueError` — same
    contract every other pgrls HTML formatter honours, to prevent
    a silent local-timezone-coercion footgun.

    Empty violations: a green "no findings" banner instead of an
    empty table.
    """
    if generated_at is None:
        generated_at = datetime.now(timezone.utc)
    elif generated_at.tzinfo is None:
        raise ValueError(
            "format_html: generated_at must be timezone-aware; "
            "a naive datetime would be interpreted as local time, "
            "producing a wrong audit timestamp depending on the "
            "host. Pass `datetime.now(timezone.utc)` or attach an "
            "explicit tzinfo."
        )
    now = (
        generated_at
        .astimezone(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )

    counts: Counter[Severity] = Counter(v.severity for v in violations)
    total = len(violations)

    # Summary band: green "no findings" banner or per-severity chips.
    if total == 0:
        band_html = (
            '<p class="summary net-good">'
            "✅ No findings.</p>"
        )
    else:
        chips: list[str] = []
        for sev in ALL_SEVERITIES:
            n = counts.get(sev, 0)
            if n:
                chips.append(
                    f'<span class="pill sev-{sev}">'
                    f'{_SEVERITY_EMOJI[sev]} <strong>{n}</strong>'
                    f"&nbsp;{sev}{'s' if n != 1 else ''}</span>"
                )
        # Catch any unknown-severity entries (e.g. from extra-rules
        # passing an unexpected string). Append last with neutral
        # bullet so the count isn't silently lost.
        for sev, n in counts.items():
            if sev in _SEVERITY_EMOJI:
                continue
            chips.append(
                f'<span class="pill sev-other">'
                f"• <strong>{n}</strong>&nbsp;{html.escape(str(sev))}</span>"
            )
        chips_html = "\n      ".join(chips)
        noun = "finding" if total == 1 else "findings"
        band_html = (
            f'<p class="summary"><strong>{total}</strong> {noun}:</p>\n'
            f'    <div class="pills">\n      {chips_html}\n    </div>'
        )

    # Table body
    if total == 0:
        rows_html = (
            '<tr><td colspan="4" class="empty">'
            "No violations to display."
            "</td></tr>"
        )
    else:
        row_lines: list[str] = []
        for v in violations:
            sev = v.severity
            sev_emoji = _SEVERITY_EMOJI.get(sev, "•")
            sev_cls = sev if sev in _SEVERITY_EMOJI else "other"
            rule_link = _rule_link(v.rule_id)
            rule_id_e = html.escape(v.rule_id)
            title_e = html.escape(v.title)
            sev_e = html.escape(str(sev))
            loc_e = _safe_location_html(v.location)
            # Newlines in message → <br>; html.escape first so any
            # `<` / `>` in the message can't inject tags.
            message = html.escape(v.message).replace(
                "\n", "<br>"
            ).replace("\r", "")
            row_lines.append(
                f'      <tr class="row-{sev_cls}">'
                f'<td><span class="pill sev-{sev_cls}">'
                f"{sev_emoji} {sev_e}</span></td>"
                f'<td><a href="{rule_link}"><code>{rule_id_e}</code></a>'
                f"<br><small>{title_e}</small></td>"
                f"<td><code>{loc_e}</code></td>"
                f"<td>{message}</td>"
                "</tr>"
            )
        rows_html = "\n".join(row_lines)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>pgrls lint</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI",
         Roboto, "Helvetica Neue", Arial, sans-serif;
         margin: 2rem auto; max-width: 72rem; padding: 0 1rem;
         color: #1f2328; background: #ffffff; }}
  @media (prefers-color-scheme: dark) {{
    body {{ color: #e6edf3; background: #0d1117; }}
    table {{ border-color: #30363d; }}
    th {{ background: #161b22; }}
    tr td {{ background: #0d1117; }}
    tr:nth-child(even) td {{ background: #161b22; }}
    code {{ background: #161b22; }}
  }}
  header {{ margin-bottom: 1.5rem; }}
  h1 {{ font-size: 1.5rem; margin: 0 0 .25rem 0; }}
  .meta {{ color: #57606a; font-size: .85rem; }}
  .summary {{ margin: 1rem 0 .5rem; font-size: 1rem; }}
  .net-good {{ color: {_SEVERITY_COLOR["info"]}; }}
  .pills {{ display: flex; flex-wrap: wrap; gap: .5rem;
            margin: 0 0 1.5rem 0; }}
  .pill {{ display: inline-block; padding: .15rem .55rem;
           border-radius: 999px; font-size: .85rem;
           border: 1px solid currentColor; }}
  .sev-error   {{ color: {_SEVERITY_COLOR["error"]}; }}
  .sev-warning {{ color: {_SEVERITY_COLOR["warning"]}; }}
  .sev-info    {{ color: {_SEVERITY_COLOR["info"]}; }}
  .sev-other   {{ color: #57606a; }}
  table {{ width: 100%; border-collapse: collapse;
           border: 1px solid #d0d7de; }}
  thead th {{ text-align: left; padding: .5rem .75rem;
              background: #f6f8fa; border-bottom: 1px solid #d0d7de;
              font-weight: 600; white-space: nowrap; }}
  tbody td {{ padding: .5rem .75rem; border-bottom: 1px solid #d0d7de;
              vertical-align: top; }}
  tbody tr:last-child td {{ border-bottom: 0; }}
  tbody td small {{ color: #57606a; font-size: .85em; }}
  code {{ background: #f6f8fa; padding: .1rem .35rem;
          border-radius: 4px; font: .9em ui-monospace, Menlo, monospace; }}
  .empty {{ text-align: center; color: #57606a; padding: 1.5rem; }}
  footer {{ margin-top: 2rem; color: #57606a; font-size: .8rem; }}
</style>
</head>
<body>
  <header>
    <h1>pgrls lint</h1>
    <p class="meta">Generated by <code>pgrls lint --format html</code> · {html.escape(now)}</p>
    {band_html}
  </header>
  <table>
    <thead>
      <tr>
        <th>Severity</th>
        <th>Rule</th>
        <th>Location</th>
        <th>Message</th>
      </tr>
    </thead>
    <tbody>
{rows_html}
    </tbody>
  </table>
  <footer>pgrls — Postgres Row-Level Security linter · <a href="https://github.com/pgrls/pgrls">github.com/pgrls/pgrls</a></footer>
</body>
</html>
"""
