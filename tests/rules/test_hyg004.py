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


def test_unqualified_coverage_does_not_falsely_clear_other_tenant() -> None:
    # Multi-tenant guard: same-named tables in two schemas, a test that
    # exercised only tenant_a.events via an unqualified query (schema=None).
    # HYG004 must still flag tenant_b.events.isolation as untested — not
    # silently clear it (the over-credit that the 0.7.0 bug produced).
    def pol() -> Policy:
        return _policy("isolation", "SELECT", ("app_user",))

    schema = Schema(
        tables=(
            Table("tenant_a", "events", True, True, (pol(),)),  # type: ignore[arg-type]
            Table("tenant_b", "events", True, True, (pol(),)),  # type: ignore[arg-type]
        )
    )
    data = _data(ExercisedTuple(None, "events", "app_user", "SELECT"))
    locations = {f.location for f in HYG004().check(schema, {"_coverage": data})}
    assert locations == {
        "tenant_a.events.isolation",
        "tenant_b.events.isolation",
    }


def test_allowlist_suppresses_uncovered_policy() -> None:
    schema = _schema(_policy("del", "DELETE", ("admin",)))
    data = _data(ExercisedTuple(None, "invoices", "authenticated", "SELECT"))
    findings = HYG004().check(
        schema,
        {"_coverage": data, "allowlist": ["public.invoices.del"]},
    )
    assert findings == []
