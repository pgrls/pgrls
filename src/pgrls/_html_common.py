"""Shared helpers for the standalone-HTML formatters.

`pgrls lint --format html` (`formatters.html`), `pgrls report
--format html` (`report`), `pgrls history --format html` (`history`),
and `pgrls diff --format html` (`diff.formatters`) each render a
self-contained HTML document carrying a generation timestamp. All four
honour the same `generated_at` contract:

* `None` → `datetime.now(timezone.utc)`;
* a timezone-aware datetime → normalised to UTC;
* a *naive* datetime → `ValueError`, because interpreting it as local
  time would stamp a wrong audit time depending on the host.

That contract was copy-pasted verbatim across the four formatters
(only the function-name prefix in the error differed). It lives here
now so the contract has one definition. The per-formatter CSS is
deliberately *not* centralised — the five HTML renderers have
intentionally divergent stylesheets (status pills vs severity pills
vs trend deltas vs predicate blocks) and unifying them would change
byte-for-byte output that snapshot tests pin.

`pgrls explain --format html` (`cli`) renders no timestamp, so it
doesn't use these helpers.
"""
from __future__ import annotations

from datetime import datetime, timezone


def resolve_generated_at(
    generated_at: datetime | None,
    *,
    caller_name: str,
) -> datetime:
    """Resolve the `generated_at` argument the HTML formatters accept.

    `None` defaults to `datetime.now(timezone.utc)`. A naive datetime
    raises `ValueError` (a silent local-time coercion would produce a
    wrong audit timestamp depending on the host). `caller_name` is the
    public function name, used as the error-message prefix so the
    message reads identically to the hand-written one each formatter
    used to carry.
    """
    if generated_at is None:
        return datetime.now(timezone.utc)
    if generated_at.tzinfo is None:
        raise ValueError(
            f"{caller_name}: generated_at must be timezone-aware; "
            "a naive datetime would be interpreted as local time, "
            "producing a wrong audit timestamp depending on the "
            "host. Pass `datetime.now(timezone.utc)` or attach an "
            "explicit tzinfo."
        )
    return generated_at


def to_iso_z(generated_at: datetime) -> str:
    """Render a tz-aware datetime as an ISO-8601 UTC string with a
    `Z` suffix and second precision — e.g. `2026-05-27T16:00:00Z`.

    Mirrors the chain every HTML formatter used inline:
    `.astimezone(utc).replace(microsecond=0).isoformat()` with the
    `+00:00` offset rewritten to `Z`.
    """
    return (
        generated_at
        .astimezone(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
