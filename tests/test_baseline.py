"""Unit tests for the baseline file (`pgrls lint --baseline`)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from pgrls.baseline import (
    BASELINE_VERSION,
    BaselineError,
    finding_key,
    load_baseline,
    partition,
    stale_keys,
    write_baseline,
)
from pgrls.violations import Violation


def _v(rule_id: str, location: str | None) -> Violation:
    return Violation(
        rule_id=rule_id,
        severity="warning",
        title=f"{rule_id} title",
        message=f"{rule_id} message",
        location=location,
    )


# --- write / load round-trip ---------------------------------------------


def test_write_baseline_returns_count(tmp_path: Path) -> None:
    path = tmp_path / "b.json"
    n = write_baseline(
        path,
        [_v("SEC001", "public.a"), _v("SEC005", "public.t.p")],
        tool_version="0.0.0",
    )
    assert n == 2
    assert path.exists()


def test_write_baseline_round_trips_through_load(tmp_path: Path) -> None:
    path = tmp_path / "b.json"
    write_baseline(
        path,
        [_v("SEC001", "public.a"), _v("SEC005", "public.t.p")],
        tool_version="0.0.0",
    )
    assert load_baseline(path) == {
        ("SEC001", "public.a"),
        ("SEC005", "public.t.p"),
    }


def test_write_baseline_records_version_and_generator(
    tmp_path: Path,
) -> None:
    path = tmp_path / "b.json"
    write_baseline(path, [_v("SEC001", "public.a")], tool_version="9.9.9")
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["version"] == BASELINE_VERSION
    assert payload["generated_by"] == "pgrls 9.9.9"


def test_write_baseline_is_deterministic(tmp_path: Path) -> None:
    # `findings` is sorted, so two writes of the same violations in
    # different order produce byte-identical files.
    a, b = tmp_path / "a.json", tmp_path / "b.json"
    write_baseline(
        a,
        [_v("SEC005", "public.t.p"), _v("SEC001", "public.a")],
        tool_version="1.0",
    )
    write_baseline(
        b,
        [_v("SEC001", "public.a"), _v("SEC005", "public.t.p")],
        tool_version="1.0",
    )
    assert a.read_text(encoding="utf-8") == b.read_text(encoding="utf-8")


def test_write_baseline_handles_none_location(tmp_path: Path) -> None:
    path = tmp_path / "b.json"
    write_baseline(path, [_v("SEC001", None)], tool_version="1.0")
    assert load_baseline(path) == {("SEC001", None)}


def test_write_baseline_empty(tmp_path: Path) -> None:
    path = tmp_path / "b.json"
    assert write_baseline(path, [], tool_version="1.0") == 0
    assert load_baseline(path) == set()


def test_write_baseline_bad_directory_raises(tmp_path: Path) -> None:
    path = tmp_path / "nonexistent" / "b.json"
    with pytest.raises(BaselineError, match="cannot write baseline"):
        write_baseline(
            path, [_v("SEC001", "public.a")], tool_version="1.0"
        )


# --- load errors ---------------------------------------------------------


def test_load_baseline_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(BaselineError, match="cannot read baseline"):
        load_baseline(tmp_path / "nope.json")


def test_load_baseline_rejects_bad_json(tmp_path: Path) -> None:
    path = tmp_path / "b.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(BaselineError, match="not valid JSON"):
        load_baseline(path)


def test_load_baseline_rejects_non_object(tmp_path: Path) -> None:
    path = tmp_path / "b.json"
    path.write_text("[]", encoding="utf-8")
    with pytest.raises(BaselineError, match="must be a JSON object"):
        load_baseline(path)


def test_load_baseline_rejects_wrong_version(tmp_path: Path) -> None:
    path = tmp_path / "b.json"
    path.write_text(
        json.dumps({"version": 999, "findings": []}), encoding="utf-8"
    )
    with pytest.raises(BaselineError, match="version"):
        load_baseline(path)


def test_load_baseline_rejects_non_list_findings(tmp_path: Path) -> None:
    path = tmp_path / "b.json"
    path.write_text(
        json.dumps({"version": BASELINE_VERSION, "findings": "x"}),
        encoding="utf-8",
    )
    with pytest.raises(BaselineError, match="findings"):
        load_baseline(path)


def test_load_baseline_rejects_malformed_finding(tmp_path: Path) -> None:
    path = tmp_path / "b.json"
    path.write_text(
        json.dumps(
            {"version": BASELINE_VERSION, "findings": [{"rule_id": 5}]}
        ),
        encoding="utf-8",
    )
    with pytest.raises(BaselineError, match="rule_id"):
        load_baseline(path)


# --- partition -----------------------------------------------------------


def test_partition_splits_new_and_baselined() -> None:
    violations = [
        _v("SEC001", "public.a"),
        _v("SEC005", "public.t.p"),
        _v("SEC002", "public.b"),
    ]
    baseline = {("SEC001", "public.a"), ("SEC002", "public.b")}
    new, baselined = partition(violations, baseline)
    assert [v.rule_id for v in new] == ["SEC005"]
    assert sorted(v.rule_id for v in baselined) == ["SEC001", "SEC002"]


def test_partition_empty_baseline_keeps_all_new() -> None:
    violations = [_v("SEC001", "public.a")]
    new, baselined = partition(violations, set())
    assert new == violations
    assert baselined == []


def test_partition_preserves_order() -> None:
    violations = [
        _v("SEC005", "p1"),
        _v("SEC005", "p2"),
        _v("SEC005", "p3"),
    ]
    new, _ = partition(violations, {("SEC005", "p2")})
    assert [v.location for v in new] == ["p1", "p3"]


def test_finding_key() -> None:
    assert finding_key(_v("SEC001", "public.a")) == ("SEC001", "public.a")
    assert finding_key(_v("SEC001", None)) == ("SEC001", None)


def test_stale_keys_finds_unmatched_baseline_entries() -> None:
    # `public.gone.p` is in the baseline but no current finding
    # matches it — the issue was fixed (or the policy renamed).
    violations = [_v("SEC001", "public.a")]
    baseline = {("SEC001", "public.a"), ("SEC005", "public.gone.p")}
    assert stale_keys(violations, baseline) == {
        ("SEC005", "public.gone.p")
    }


def test_stale_keys_empty_when_all_baseline_entries_match() -> None:
    violations = [_v("SEC001", "public.a")]
    assert stale_keys(violations, {("SEC001", "public.a")}) == set()
