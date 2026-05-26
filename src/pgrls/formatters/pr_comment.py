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
    gfm_inline_code,
    safe_location,
)
from pgrls.violations import ALL_SEVERITIES, Severity, Violation

_SEVERITY_EMOJI: dict[Severity, str] = {
    "error": "❌",
    "warning": "⚠️",
    "info": "ℹ️",
}

# Fallback shown when a Violation arrives with a severity outside the
# `Severity` Literal (e.g. via `# type: ignore[arg-type]` in extra-
# rules user code, or a future fourth severity that lands before the
# emoji map is updated). Neutral bullet so the rule block still
# renders rather than crashing with KeyError.
_UNKNOWN_SEVERITY_EMOJI = "•"

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

    `rule_id` is rendered verbatim in the summary line — pgrls's
    `Violation.rule_id` contract is that IDs arrive in canonical
    case (`SEC###`, `PERF###`, `HYG###`, `VIEW###`, `DIFF_*`), so
    no display-time normalization is applied. An empty / `None`
    `title` falls back to `rule_id` so the summary never collapses
    to a dangling em-dash.
    """
    first = group[0]
    severity = first.severity
    emoji = _SEVERITY_EMOJI.get(severity, _UNKNOWN_SEVERITY_EMOJI)
    title = first.title or rule_id
    count = len(group)

    # Summary line — visible when the block is collapsed.
    count_suffix = f" (×{count})" if count > 1 else ""
    summary = (
        f"{emoji} <strong>{rule_id}</strong> — {_html_escape(title)}"
        f"{count_suffix}"
    )

    # Locations — one inline-code chip per finding. Findings
    # within a group preserve insertion order; we deliberately do
    # NOT deduplicate, so multiple findings on the same location
    # (rare but possible — a rule that fires twice on different
    # facets of one object) each get their own chip. Separator is
    # `, ` rather than a mid-dot so the browser can wrap a wide
    # finding set on a narrow PR-comment column.
    location_chips = ", ".join(_safe_chip(v.location) for v in group)

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
    """Render a single `Violation.location` as a GFM inline-code chip.

    Returns the full backtick-wrapped span (including delimiters),
    so the caller composes chips directly with `", ".join(...)`
    rather than wrapping after the fact. Mirrors
    `markdown._location_cell` for the table-cell context — both
    delegate the backtick-run arithmetic to `gfm_inline_code` so
    identical input yields identical output across formatters.

    Empty / `None` locations render as `(schema-wide)`; a location
    that collapses to `""` after `safe_location` (e.g. all zero-
    width chars) renders as `EMPTY_OR_ZERO_WIDTH_SENTINEL` so a
    reviewer sees there WAS something at that location, just
    nothing displayable.
    """
    if not location:
        return gfm_inline_code("(schema-wide)")
    clean = safe_location(location)
    if not clean:
        return gfm_inline_code(EMPTY_OR_ZERO_WIDTH_SENTINEL)
    return gfm_inline_code(clean)


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
    """Escape `&`, `<`, and `>` for safe embedding in a `<details>` block.

    A bare `&` inside an HTML element is a character-reference
    introducer — GitHub's GFM renderer will parse `&amp;`, `&lt;`,
    or any other named entity even when the source intends a
    literal ampersand. So `&` MUST be escaped first (before the
    `<`/`>` pass introduces additional `&` characters), otherwise
    the rendered output would silently rewrite literal `&amp;`
    text into the `&` character it represents.

    `<` and `>` would be interpreted as HTML tags. Pgrls violation
    messages today are plain ASCII English, but a future rule
    could carry a SQL fragment with `<`/`>` operators, or a future
    extra rule could emit `</details>` in a message and accidentally
    close the surrounding details block — render-safe escaping
    prevents both classes of bug.

    Order matters: `&` first so the subsequent `<` → `&lt;` and
    `>` → `&gt;` rewrites don't get re-escaped.
    """
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(
        ">", "&gt;"
    )
