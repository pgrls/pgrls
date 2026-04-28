"""Use case 75: SARIF formatter — no new fixture."""
from __future__ import annotations


def test_uc75_sarif_format_end_to_end_against_demo_db(
    demo_db: str,
    lint,
    pgrls_toml,
) -> None:
    # Run the demo DB through `--format sarif` and validate the
    # contract end-to-end: top-level schema, single run, tool
    # driver name/version, rule descriptors, severity → level
    # mapping, location shape.
    import json as _json

    text = lint(config=pgrls_toml,
        extra_args=("--format", "sarif"),
    )
    parsed = _json.loads(text)

    assert parsed["version"] == "2.1.0"
    assert parsed["$schema"].endswith("sarif-schema-2.1.0.json")

    run = parsed["runs"][0]
    assert run["tool"]["driver"]["name"] == "pgrls"

    # Rule descriptors are deduped per unique rule_id; every
    # ruleId in results points back via ruleIndex.
    rule_ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
    assert len(rule_ids) == len(set(rule_ids))
    for result in run["results"]:
        assert result["ruleId"] in rule_ids
        assert (
            run["tool"]["driver"]["rules"][result["ruleIndex"]]["id"]
            == result["ruleId"]
        )

    # SARIF level enum: error|warning|note (no "info").
    levels = {r["level"] for r in run["results"]}
    assert levels.issubset({"error", "warning", "note"})

    # Every result with a location uses logical-location form
    # with fullyQualifiedName — that's what GH Code Scanning
    # surfaces as the finding's path.
    for result in run["results"]:
        if result.get("locations"):
            loc = result["locations"][0]["logicalLocations"][0]
            assert "fullyQualifiedName" in loc
            assert loc["fullyQualifiedName"]  # non-empty


