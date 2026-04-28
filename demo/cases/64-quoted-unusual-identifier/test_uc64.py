"""Use case 64: Quoted/unusual identifier — CLEAN."""
from __future__ import annotations


def test_uc64_quoted_mixed_case_identifier_handled_cleanly(
    lint_output: str,
    lint,
    all_rule_ids,
) -> None:
    # `app."MixedCase Table"` — Postgres preserves the case
    # and the embedded space inside `pg_class.relname`. The
    # introspector reads it as `MixedCase Table` (no quotes).
    # The lint output and allowlist match by plain string, so
    # this round-trips cleanly. No rule should fire on the
    # well-configured policy.
    line = "app.MixedCase Table"
    # The qualified location pgrls emits.
    for rule_id in all_rule_ids:
        composed = f"{rule_id}  {line}"
        assert composed not in lint_output, (
            f"{rule_id} unexpectedly fired on {line!r}"
        )


