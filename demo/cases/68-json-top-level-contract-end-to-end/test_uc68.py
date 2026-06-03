"""Use case 68: json top level contract end to end."""
from __future__ import annotations


def test_uc68_json_top_level_contract_end_to_end(
    demo_db: str,
    lint,
    lint_json,
) -> None:
    # Pin the public CI contract from a real lint run, not just
    # from the unit tests. CI consumers hard-code these keys.
    parsed = lint_json()
    assert set(parsed.keys()) == {"violations", "summary"}
    assert set(parsed["summary"].keys()) == {
        "errors", "warnings", "infos", "others", "total",
    }
    if parsed["violations"]:
        assert set(parsed["violations"][0].keys()) == {
            "rule_id", "severity", "title", "message", "location",
        }


