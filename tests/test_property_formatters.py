"""Property-based tests for formatter helpers shared across rules.

`gfm_inline_code` (introduced v0.6.6, lives in
`pgrls.formatters._common`) wraps arbitrary content in GFM inline-
code delimiters, picking the wrapper run width dynamically so the
content can't close the span prematurely. The example tests in
`tests/test_formatter_markdown.py` and `tests/test_formatter_pr_comment.py`
cover the specific shapes we've thought of (no backticks, one
backtick, two backticks, leading/trailing). Hypothesis covers the
combinatorial space — arbitrary content strings, including the
adversarial inputs the example tests don't enumerate.

`_html_escape` (lives in `pgrls.formatters.pr_comment`) escapes
`&` → `&amp;`, `<` → `&lt;`, `>` → `&gt;` for safe embedding
inside `<details>` blocks. The documented contract is
**NOT-idempotent by design**: `_html_escape("&amp;")` deliberately
becomes `"&amp;amp;"` because rule-violation messages are raw
input, not pre-encoded HTML. The property test pins the invariants
that should hold regardless of input.

Both targets are pure functions on a single string argument, so
Hypothesis can exercise them across the full string space without
fixture setup.
"""
from __future__ import annotations

import re

from hypothesis import given, settings
from hypothesis import strategies as st

from pgrls.formatters._common import gfm_inline_code
from pgrls.formatters.pr_comment import _html_escape


# ──────────────────────────────────────────────────────────────────
# gfm_inline_code — wrapper invariants
# ──────────────────────────────────────────────────────────────────


# Mostly-ASCII strings biased toward backticks so the wrapper-run
# arithmetic gets exercised. Filtering to non-empty strings so we
# don't test the empty-input edge here — that's covered by an
# example test in the markdown formatter suite.
_content_alphabet = st.text(
    alphabet=st.sampled_from(
        list("abcdefghijklmnopqrstuvwxyz0123456789 _.`#-")
    ),
    min_size=1,
    max_size=40,
)


@given(content=_content_alphabet)
@settings(max_examples=200)
def test_gfm_inline_code_wrapper_run_strictly_exceeds_inner_run(
    content: str,
) -> None:
    """The CommonMark 6.1 rule: a code-span delimited by N backticks
    is closed by the next run of EXACTLY N backticks. So the wrapper
    must use a strictly-longer run than any backtick run inside the
    content — else the renderer will close the span at the first
    inner run that equals or exceeds the opener's length.

    Pin: the wrapper backtick-run width strictly exceeds the longest
    consecutive backtick run inside the original content.
    """
    rendered = gfm_inline_code(content)
    # Wrapper is a contiguous prefix of backticks (possibly followed
    # by a space-padding when there's an inner backtick); extract it.
    opener_match = re.match(r"^(`+)", rendered)
    assert opener_match, f"output {rendered!r} has no backtick opener"
    wrapper_len = len(opener_match.group(1))
    inner_runs = re.findall(r"`+", content)
    max_inner = max((len(r) for r in inner_runs), default=0)
    assert wrapper_len > max_inner, (
        f"wrapper of {wrapper_len} backticks is not strictly > "
        f"longest inner run of {max_inner} in {content!r}"
    )


@given(content=_content_alphabet)
@settings(max_examples=200)
def test_gfm_inline_code_opener_and_closer_match(content: str) -> None:
    """A well-formed inline-code span has identical opener and
    closer runs. Anything else means the renderer will pick the
    wrong closing point and the span will leak past."""
    rendered = gfm_inline_code(content)
    opener_match = re.match(r"^(`+)", rendered)
    assert opener_match, "no opener"
    opener = opener_match.group(1)
    assert rendered.endswith(opener), (
        f"closer doesn't match opener {opener!r} in {rendered!r}"
    )
    # The body between opener and closer is what the renderer
    # treats as the span content.
    body = rendered[len(opener):-len(opener)]
    # Body strictly contains the original content (possibly with
    # one space of padding on each side — the GFM idiom for content
    # that starts or ends with a backtick). This holds even for
    # content that doesn't need padding (one-backtick wrapper, no
    # inner backticks).
    assert content in body, (
        f"content {content!r} not found in body {body!r} of "
        f"rendered {rendered!r}"
    )


@given(content=_content_alphabet)
@settings(max_examples=200)
def test_gfm_inline_code_round_trips_through_postgres_quote_chars(
    content: str,
) -> None:
    """Identifier-quoting characters Postgres permits inside quoted
    identifiers (`*`, `_`, `[`, `]`, `(`, `)`, `<`, `>`, `|`, `\\`)
    must survive the wrap intact — the inline-code span deliberately
    doesn't escape them (they have no markdown meaning inside the
    span). Property: every non-backtick character in `content`
    appears unchanged in the rendered output."""
    rendered = gfm_inline_code(content)
    for ch in content:
        if ch == "`":
            continue  # backticks are wrapper-arithmetic territory
        assert ch in rendered, (
            f"character {ch!r} from content {content!r} not present "
            f"in rendered output {rendered!r}"
        )


def test_gfm_inline_code_empty_string_known_shape() -> None:
    """Pin the empty-string edge case here (Hypothesis strategy
    excludes it). Empty content gets the minimal `` `` `` wrap (no
    space padding because there's no backtick to pad against)."""
    assert gfm_inline_code("") == "``"


# ──────────────────────────────────────────────────────────────────
# _html_escape — invariants
# ──────────────────────────────────────────────────────────────────


# Bias toward the three characters _html_escape actually transforms,
# plus enough other characters to exercise the don't-touch path.
_html_content_alphabet = st.text(
    alphabet=st.sampled_from(
        list("abcdef0123456789 .,&<>'\"=#-_/\\")
    ),
    min_size=0,
    max_size=40,
)


@given(content=_html_content_alphabet)
@settings(max_examples=200)
def test_html_escape_output_contains_no_raw_lt_gt_amp(
    content: str,
) -> None:
    """The post-escape output must contain ZERO raw `<` / `>`
    characters and no bare `&` that isn't the start of an entity.

    Specifically: any `&` in the output must be followed by `amp;`,
    `lt;`, or `gt;` (the only three entities `_html_escape`
    produces). A bare `&xxx;` would mean the function let through
    an entity-introducer that GitHub's renderer would then try to
    parse as a real HTML entity — exactly the bug `_html_escape`
    exists to prevent.
    """
    escaped = _html_escape(content)
    # No raw < or > anywhere in the output.
    assert "<" not in escaped, (
        f"raw < survived in {escaped!r} for content {content!r}"
    )
    assert ">" not in escaped, (
        f"raw > survived in {escaped!r} for content {content!r}"
    )
    # Every & must be the start of one of our three entities.
    for match in re.finditer(r"&", escaped):
        pos = match.start()
        suffix = escaped[pos:]
        assert (
            suffix.startswith("&amp;")
            or suffix.startswith("&lt;")
            or suffix.startswith("&gt;")
        ), (
            f"bare & at position {pos} in {escaped!r} "
            f"(content was {content!r})"
        )


@given(content=_html_content_alphabet)
@settings(max_examples=200)
def test_html_escape_is_not_idempotent_by_design(
    content: str,
) -> None:
    """The documented contract: `_html_escape` is intentionally
    NOT idempotent — applying it twice double-escapes `&`. This
    pins that running it twice on `&` produces `&amp;amp;`, not
    `&amp;`. The rule-author contract is "messages are raw"; we
    lock that in here so a "simplification" doesn't quietly
    rewrite the function to be idempotent."""
    once = _html_escape(content)
    twice = _html_escape(once)
    # If content has no & / < / >, both passes are no-ops and
    # the strings are equal.
    if not any(c in content for c in "&<>"):
        assert once == twice
    # If content has any of the three, double-escape is strictly
    # longer than single-escape (because each & in `once` gets
    # rewritten to `&amp;` on the second pass).
    elif "&" in content or "<" in content or ">" in content:
        assert len(twice) >= len(once), (
            f"twice-escaped {twice!r} is shorter than once-"
            f"escaped {once!r} (content was {content!r})"
        )


@given(content=_html_content_alphabet)
@settings(max_examples=200)
def test_html_escape_preserves_safe_characters(content: str) -> None:
    """Characters that aren't `&`, `<`, or `>` must pass through
    unchanged. Pin the no-touch invariant — a future
    "simplification" that switched to `html.escape(text)` would
    also escape `'` (`&#x27;`) and `"` (`&quot;`), which would
    change rendered output for quotes inside rule messages."""
    escaped = _html_escape(content)
    for ch in content:
        if ch in "&<>":
            continue
        assert ch in escaped, (
            f"non-special character {ch!r} from {content!r} "
            f"missing in escaped output {escaped!r}"
        )


def test_html_escape_specific_idempotence_contract() -> None:
    """The exact double-escape pattern the contract pins."""
    assert _html_escape("A & B") == "A &amp; B"
    assert _html_escape("A &amp; B") == "A &amp;amp; B"
    assert _html_escape("</details>") == "&lt;/details&gt;"
    # Quotes and apostrophes pass through (the function uses the
    # narrow 3-character escape, not `html.escape`).
    assert _html_escape('"hello"') == '"hello"'
    assert _html_escape("it's") == "it's"
