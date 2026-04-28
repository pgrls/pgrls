"""Use case 70: json emits only known rule ids."""
from __future__ import annotations


def test_uc70_json_emits_only_known_rule_ids(
    demo_db: str,
    lint_json,
    all_rule_ids,
) -> None:
    # Every violation's rule_id should be in the shipping catalog.
    # Catches accidental rule typos or string-formatting bugs that
    # would emit something unparseable to a downstream consumer.
    parsed = lint_json()
    rule_ids_in_output = {v["rule_id"] for v in parsed["violations"]}
    unknown = rule_ids_in_output - set(all_rule_ids)
    assert not unknown, (
        f"Unknown rule IDs in JSON output: {sorted(unknown)}"
    )


