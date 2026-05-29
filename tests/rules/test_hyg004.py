"""Unit tests for HYG004 — policy has no behavioral test."""
from __future__ import annotations

from pgrls.coverage import CoverageData, ExercisedTuple
from pgrls.model import Policy, Schema, Table
from pgrls.rules.hyg004 import HYG004


def _policy(name: str, command: str, roles: tuple[str, ...]) -> Policy:
    return Policy(
        name=name,
        command=command,  # type: ignore[arg-type]
        permissive=True,
        roles=roles,
        using_sql="true",
        with_check_sql=None,
    )


def _schema(*policies: Policy) -> Schema:
    return Schema(
        tables=(
            Table(
                schema="public",
                name="invoices",
                rls_enabled=True,
                force_rls=True,
                policies=policies,
            ),
        )
    )


def _data(*tuples: ExercisedTuple) -> CoverageData:
    return CoverageData(exercised=frozenset(tuples))


def test_inert_without_coverage_data() -> None:
    # No `_coverage` in options → rule stays silent (opt-in).
    schema = _schema(_policy("p", "SELECT", ("authenticated",)))
    assert HYG004().check(schema, {}) == []
    # A non-CoverageData value is ignored too (defensive).
    assert HYG004().check(schema, {"_coverage": "nonsense"}) == []


def test_flags_only_uncovered_policies() -> None:
    schema = _schema(
        _policy("sel", "SELECT", ("authenticated",)),
        _policy("del", "DELETE", ("admin",)),
    )
    data = _data(ExercisedTuple(None, "invoices", "authenticated", "SELECT"))
    findings = HYG004().check(schema, {"_coverage": data})
    assert [f.location for f in findings] == ["public.invoices.del"]
    assert findings[0].rule_id == "HYG004"
    assert findings[0].severity == "info"


def test_all_covered_yields_nothing() -> None:
    schema = _schema(_policy("sel", "SELECT", ("authenticated",)))
    data = _data(ExercisedTuple(None, "invoices", "authenticated", "SELECT"))
    assert HYG004().check(schema, {"_coverage": data}) == []


def test_allowlist_suppresses_uncovered_policy() -> None:
    schema = _schema(_policy("del", "DELETE", ("admin",)))
    data = _data(ExercisedTuple(None, "invoices", "authenticated", "SELECT"))
    findings = HYG004().check(
        schema,
        {"_coverage": data, "allowlist": ["public.invoices.del"]},
    )
    assert findings == []
