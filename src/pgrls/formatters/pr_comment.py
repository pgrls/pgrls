"""GitHub PR comment formatter for `pgrls lint`.

Designed for the specific reading context of a pull-request review
thread: a reviewer who has not run pgrls themselves wants to know
at a glance (a) is this PR safe, (b) what classes of finding are
present, (c) where exactly each finding lands. Optimised for that
scan-then-drill-in pattern, not for stack-rank parsing.

Differences from the existing `markdown` formatter:

- **Grouped by rule, not by violation.** A policy with 13 SEC003
  hits would otherwise produce 13 nearly-identical pipe-table rows.
  Here it produces one collapsible block with 13 inline-code
  locations, which scans much faster.
- **`<details>` summaries default collapsed.** A PR comment with
  hundreds of findings stays compact at the top of the thread; the
  reviewer expands what they care about.
- **Severity emoji + bold rule ID** in the summary line so the
  collapsed view conveys severity without expanding.
- **Example message + rule-reference link** inside each block so a
  reviewer can act without leaving the PR — no need to run
  `pgrls explain` separately.

Render-environment: GitHub Markdown (GFM), which supports inline
HTML `<details>` and `<summary>` elements. Other Markdown renderers
that don't support those (e.g., DEV.to, some wiki engines) degrade
to showing the summary line + inline content unwrapped, which is
still readable — degradation is graceful.

Stable between releases of the same major-zero series; new top-
level sections are additive. The link convention (`docs/RULES.md#rule-<id>`
for lint rules, `AGENTS.md#diff-rules` for `DIFF_*`) is shared
with `markdown._rule_link` and `sarif._help_uri_for` — keep them
synchronised.
"""
from __future__ import annotations

from collections import Counter, defaultdict

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

# Used by the per-rule reference link. Mirrors `markdown._INFORMATION_URI`
# and `sarif._INFORMATION_URI` deliberately — a URL bump must happen
# in all three places simultaneously or the PR-comment links would
# drift relative to the SARIF helpUri / markdown rule link.
_INFORMATION_URI = "https://github.com/pgrls/pgrls"


def format_pr_comment(violations: list[Violation]) -> str:
    if not violations:
        return "## pgrls findings\n\n✅ No issues found.\n"

    # Counts per severity for the top-line summary.
    sev_counts: Counter[Severity] = Counter(v.severity for v in violations)
    sev_parts: list[str] = []
    for sev in ALL_SEVERITIES:
        n = sev_counts.get(sev, 0)
        if n:
            sev_parts.append(
                f"{_SEVERITY_EMOJI[sev]} {n} {sev}"
                f"{'s' if n != 1 else ''}"
            )
    summary_severities = " · ".join(sev_parts)
    total = len(violations)
    rule_count = len({v.rule_id for v in violations})

    # Group violations by rule_id, preserving insertion order so the
    # per-rule sections appear in the same order pgrls emitted them
    # (which is — for the default text formatter — severity then
    # rule_id). That ordering already feels right; just preserve it.
    by_rule: dict[str, list[Violation]] = defaultdict(list)
    for v in violations:
        by_rule[v.rule_id].append(v)

    blocks: list[str] = []
    for rule_id, group in by_rule.items():
        blocks.append(_rule_block(rule_id, group))

    body = "\n\n".join(blocks)
    return (
        "## pgrls findings\n"
        "\n"
        f"**{total} finding{'s' if total != 1 else ''}** across "
        f"**{rule_count} rule{'s' if rule_count != 1 else ''}** — "
        f"{summary_severities}.\n"
        "\n"
        f"{body}\n"
    )


def _rule_block(rule_id: str, group: list[Violation]) -> str:
    """Render one collapsible block for all findings of a rule.

    Group has length ≥ 1. All entries share `rule_id`, `severity`,
    and `title`; only `message` and `location` vary. The block
    surfaces the count, the title, the locations, one example
    message, and a per-rule reference link.
    """
    first = group[0]
    severity = first.severity
    emoji = _SEVERITY_EMOJI[severity]
    title = first.title or rule_id
    count = len(group)

    # Summary line — visible when the block is collapsed.
    count_suffix = f" (×{count})" if count > 1 else ""
    summary = (
        f"{emoji} <strong>{rule_id}</strong> — {_html_escape(title)}"
        f"{count_suffix}"
    )

    # Locations — one inline-code chip per finding. Use a non-
    # breaking space-equivalent (mid-dot) to separate so a
    # very-wide finding set still wraps cleanly inside the
    # comment's max-width.
    location_chips = " · ".join(
        f"`{_safe_chip(v.location)}`" for v in group
    )

    # One example message — usually the first. Long messages
    # (the rule docstring + a fix hint) carry the explanation; a
    # reviewer who needs the per-location detail expands the
    # block. We pick the first to be deterministic.
    example_msg = _html_escape(first.message)

    link = _rule_link(rule_id)

    return (
        f"<details>\n"
        f"<summary>{summary}</summary>\n"
        f"\n"
        f"**Locations:** {location_chips}\n"
        f"\n"
        f"{example_msg}\n"
        f"\n"
        f"{link}\n"
        f"</details>"
    )


def _safe_chip(location: str | None) -> str:
    """Render a single Violation.location for inline-code display.

    Mirrors `markdown._location_cell` semantics but for the inline-
    code context (no pipe-table escaping needed). Empty / zero-width
    locations fall back to the schema-wide sentinel so the chip
    isn't an empty backtick pair.
    """
    if not location:
        return "(schema-wide)"
    clean = safe_location(location)
    if not clean:
        return EMPTY_OR_ZERO_WIDTH_SENTINEL
    # GFM inline code can't contain a backtick of the same run
    # length, but pgrls Violation.location is rarely backtick-heavy.
    # If it ever is, escape by doubling. (Same conservative escape
    # as the markdown formatter.)
    return clean.replace("`", "``")


def _rule_link(rule_id: str) -> str:
    """Build the per-rule deep link.

    Mirrors `markdown._rule_link` and `sarif._help_uri_for`. Lint
    rule IDs (`SEC###`, `PERF###`, `HYG###`, `VIEW###`) point at
    the per-rule anchor in `docs/RULES.md`; `DIFF_*` rule IDs point
    at the shared `#diff-rules` anchor in `AGENTS.md`.
    """
    if rule_id.startswith("DIFF_"):
        return (
            f"[Reference →]({_INFORMATION_URI}/blob/main/"
            "AGENTS.md#diff-rules)"
        )
    return (
        f"[Reference →]({_INFORMATION_URI}/blob/main/docs/"
        f"RULES.md#rule-{rule_id.lower()})"
    )


def _html_escape(text: str) -> str:
    """Escape `<` and `>` for safe embedding in a `<details>` block.

    `&` does NOT need escaping inside a `<details>` body (GFM
    permits literal `&` in markdown), but `<` and `>` would be
    interpreted as HTML tags. Pgrls violation messages today are
    plain ASCII English, but a future rule could carry a SQL
    fragment with `<`/`>` operators — render-safe escaping prevents
    a comment from rendering as half-broken HTML.
    """
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(
        ">", "&gt;"
    )
