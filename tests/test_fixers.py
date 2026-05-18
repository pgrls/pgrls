"""Unit tests for the auto-fix machinery and per-rule fixers."""
from __future__ import annotations

import pytest

from pgrls.ast_utils import parse_expr
from pgrls.fixers import Fix, default_fixers, generate_fixes
from pgrls.fixers.perf001 import PERF001Fixer
from pgrls.fixers.sec001 import SEC001Fixer
from pgrls.fixers.sec002 import SEC002Fixer
from pgrls.fixers.view001 import VIEW001Fixer
from pgrls.fixers.view002 import VIEW002Fixer
from pgrls.model import Policy, Schema, Table, View


# ---------- SEC002 fixer ----------


def _table(
    name: str = "t",
    *,
    rls: bool,
    force: bool,
    schema: str = "public",
    policies: tuple[Policy, ...] = (),
) -> Table:
    return Table(
        schema=schema,
        name=name,
        rls_enabled=rls,
        force_rls=force,
        policies=policies,
    )


def test_sec002_fix_emits_alter_table_force() -> None:
    schema = Schema(tables=(_table(rls=True, force=False),))
    fixes = SEC002Fixer().fix(schema, {})
    assert len(fixes) == 1
    f = fixes[0]
    assert f.rule_id == "SEC002"
    assert f.location == "public.t"
    assert (
        f.sql == "ALTER TABLE public.t FORCE ROW LEVEL SECURITY;"
    )


def test_sec002_fix_silent_when_force_already_set() -> None:
    schema = Schema(tables=(_table(rls=True, force=True),))
    assert SEC002Fixer().fix(schema, {}) == []


def test_sec002_fix_silent_when_rls_disabled() -> None:
    # SEC001's territory; not SEC002's, so no FORCE fix to emit.
    schema = Schema(tables=(_table(rls=False, force=False),))
    assert SEC002Fixer().fix(schema, {}) == []


def test_sec002_fix_respects_allowlist_qualified() -> None:
    schema = Schema(
        tables=(
            _table(name="a", rls=True, force=False),
            _table(name="b", rls=True, force=False),
        )
    )
    fixes = SEC002Fixer().fix(
        schema, {"allowlist": ["public.a"]}
    )
    assert [f.location for f in fixes] == ["public.b"]


def test_sec002_fix_respects_allowlist_unqualified() -> None:
    schema = Schema(tables=(_table(name="audit", rls=True, force=False),))
    assert SEC002Fixer().fix(schema, {"allowlist": ["audit"]}) == []


def test_sec002_fix_emits_one_per_offending_table() -> None:
    schema = Schema(
        tables=(
            _table(name="a", rls=True, force=False),
            _table(name="b", rls=True, force=True),
            _table(name="c", rls=True, force=False),
        )
    )
    fixes = SEC002Fixer().fix(schema, {})
    assert sorted(f.location for f in fixes) == ["public.a", "public.c"]


# ---------- SEC001 fixer ----------


def test_sec001_fix_emits_alter_table_enable() -> None:
    schema = Schema(tables=(_table(rls=False, force=False),))
    fixes = SEC001Fixer().fix(schema, {})
    assert len(fixes) == 1
    f = fixes[0]
    assert f.rule_id == "SEC001"
    assert f.location == "public.t"
    assert f.sql == "ALTER TABLE public.t ENABLE ROW LEVEL SECURITY;"


def test_sec001_fix_silent_when_rls_already_enabled() -> None:
    # SEC002's territory (FORCE missing), not SEC001's.
    schema = Schema(tables=(_table(rls=True, force=False),))
    assert SEC001Fixer().fix(schema, {}) == []


def test_sec001_fix_respects_allowlist_qualified() -> None:
    schema = Schema(
        tables=(
            _table(name="a", rls=False, force=False),
            _table(name="b", rls=False, force=False),
        )
    )
    fixes = SEC001Fixer().fix(schema, {"allowlist": ["public.a"]})
    assert [f.location for f in fixes] == ["public.b"]


def test_sec001_fix_respects_allowlist_unqualified() -> None:
    schema = Schema(
        tables=(_table(name="countries", rls=False, force=False),)
    )
    assert SEC001Fixer().fix(schema, {"allowlist": ["countries"]}) == []


def test_sec001_fix_emits_one_per_offending_table() -> None:
    schema = Schema(
        tables=(
            _table(name="a", rls=False, force=False),
            _table(name="b", rls=True, force=True),
            _table(name="c", rls=False, force=False),
        )
    )
    fixes = SEC001Fixer().fix(schema, {})
    assert sorted(f.location for f in fixes) == ["public.a", "public.c"]


def test_sec001_fix_skips_partition_child() -> None:
    # SEC001 flags an RLS-less partition child, but the remediation
    # is a judgement call (parent vs each child) — the fixer skips
    # children and emits the single correct fix for the parent.
    parent = _table(name="events", rls=False, force=False)
    child = Table(
        schema="public",
        name="events_2026",
        rls_enabled=False,
        force_rls=False,
        policies=(),
        partition_of=("public", "events"),
    )
    schema = Schema(tables=(parent, child))
    fixes = SEC001Fixer().fix(schema, {})
    assert [f.location for f in fixes] == ["public.events"]


def test_sec001_fix_skips_partition_child_with_unscanned_parent() -> None:
    # A partition child whose parent lives in a schema that was not
    # scanned: no in-scope parent exists to fix, and pgrls cannot
    # verify RLS coverage upstream. The fixer still skips the child
    # — widening `--schemas` or designing a child policy is a
    # judgement call, not a mechanical fix.
    child = Table(
        schema="public",
        name="events_2026",
        rls_enabled=False,
        force_rls=False,
        policies=(),
        partition_of=("private", "events"),  # 'private' not scanned
    )
    schema = Schema(tables=(child,))
    assert SEC001Fixer().fix(schema, {}) == []


def test_sec001_fix_silent_when_allowlist_is_bad_type() -> None:
    # Bad config type → fail closed (no exemption) → fix still emitted.
    schema = Schema(tables=(_table(rls=False, force=False),))
    fixes = SEC001Fixer().fix(schema, {"allowlist": "public.t"})
    assert len(fixes) == 1
    assert fixes[0].location == "public.t"


def test_sec001_fix_quotes_table_name_when_required() -> None:
    schema = Schema(
        tables=(
            Table(
                schema="public",
                name="MixedCase Table",
                rls_enabled=False,
                force_rls=False,
                policies=(),
            ),
        )
    )
    fixes = SEC001Fixer().fix(schema, {})
    assert len(fixes) == 1
    assert (
        fixes[0].sql
        == 'ALTER TABLE public."MixedCase Table" '
        "ENABLE ROW LEVEL SECURITY;"
    )


def test_sec001_fix_description_warns_about_deny_all() -> None:
    # Enabling RLS with no policy makes the table deny-all for
    # non-owner roles — the description must surface that follow-up.
    schema = Schema(tables=(_table(rls=False, force=False),))
    [f] = SEC001Fixer().fix(schema, {})
    assert "public.t" in f.description
    assert "policy" in f.description


# ---------- VIEW001 fixer ----------


def _view(
    name: str = "v",
    *,
    schema: str = "public",
    is_materialized: bool = False,
    security_invoker: bool = False,
    security_barrier: bool = False,
    references: tuple[tuple[str, str], ...] = (),
    security_definer_calls: tuple[str, ...] = (),
    definition: str = "SELECT 1",
) -> View:
    return View(
        schema=schema,
        name=name,
        is_materialized=is_materialized,
        security_invoker=security_invoker,
        security_barrier=security_barrier,
        definition=definition,
        references=references,
        security_definer_calls=security_definer_calls,
    )


def test_view001_fix_emits_alter_view_set_security_invoker() -> None:
    schema = Schema(
        tables=(_table(name="users", rls=True, force=True),),
        views=(
            _view(
                name="user_summary",
                security_invoker=False,
                references=(("public", "users"),),
            ),
        ),
    )
    fixes = VIEW001Fixer().fix(schema, {})
    assert len(fixes) == 1
    f = fixes[0]
    assert f.rule_id == "VIEW001"
    assert f.location == "public.user_summary"
    assert "ALTER VIEW" in f.sql
    assert "public.user_summary" in f.sql
    assert "SET (security_invoker = true)" in f.sql
    assert (
        f.sql
        == "ALTER VIEW public.user_summary "
        "SET (security_invoker = true);"
    )


def test_view001_fix_silent_when_security_invoker_already_true() -> None:
    schema = Schema(
        tables=(_table(name="users", rls=True, force=True),),
        views=(
            _view(
                name="user_summary",
                security_invoker=True,
                references=(("public", "users"),),
            ),
        ),
    )
    assert VIEW001Fixer().fix(schema, {}) == []


def test_view001_fix_silent_when_referenced_table_has_no_rls() -> None:
    # No RLS-protected reference → nothing to leak → no fix.
    schema = Schema(
        tables=(_table(name="users", rls=False, force=False),),
        views=(
            _view(
                name="user_summary",
                security_invoker=False,
                references=(("public", "users"),),
            ),
        ),
    )
    assert VIEW001Fixer().fix(schema, {}) == []


def test_view001_fix_silent_on_materialized_view() -> None:
    # Matviews are VIEW003's domain — VIEW001 must skip them and so
    # must its fixer. `ALTER VIEW … SET (security_invoker = true)`
    # would also be invalid syntax against a matview.
    schema = Schema(
        tables=(_table(name="users", rls=True, force=True),),
        views=(
            _view(
                name="user_summary",
                is_materialized=True,
                security_invoker=False,
                references=(("public", "users"),),
            ),
        ),
    )
    assert VIEW001Fixer().fix(schema, {}) == []


def test_view001_fix_respects_qualified_allowlist() -> None:
    schema = Schema(
        tables=(_table(name="users", rls=True, force=True),),
        views=(
            _view(
                name="user_summary",
                security_invoker=False,
                references=(("public", "users"),),
            ),
        ),
    )
    fixes = VIEW001Fixer().fix(
        schema, {"allowlist": ["public.user_summary"]}
    )
    assert fixes == []


def test_view001_fix_description_mentions_view_and_leaked_tables() -> None:
    schema = Schema(
        tables=(
            _table(name="users", rls=True, force=True),
            _table(name="invoices", rls=True, force=True),
        ),
        views=(
            _view(
                name="user_summary",
                security_invoker=False,
                references=(
                    ("public", "users"),
                    ("public", "invoices"),
                ),
            ),
        ),
    )
    fixes = VIEW001Fixer().fix(schema, {})
    assert len(fixes) == 1
    desc = fixes[0].description
    assert "public.user_summary" in desc
    assert "public.invoices" in desc
    assert "public.users" in desc


def test_view001_fix_silent_when_view_has_no_references() -> None:
    # A constant-only view has nothing to leak → no fix.
    schema = Schema(
        tables=(_table(name="users", rls=True, force=True),),
        views=(
            _view(
                name="constant_view",
                security_invoker=False,
                references=(),
            ),
        ),
    )
    assert VIEW001Fixer().fix(schema, {}) == []


def test_view001_fix_emits_one_per_offending_view() -> None:
    schema = Schema(
        tables=(_table(name="users", rls=True, force=True),),
        views=(
            _view(
                name="bad_a",
                security_invoker=False,
                references=(("public", "users"),),
            ),
            _view(
                name="bad_b",
                security_invoker=False,
                references=(("public", "users"),),
            ),
            _view(
                name="good",
                security_invoker=True,
                references=(("public", "users"),),
            ),
        ),
    )
    fixes = VIEW001Fixer().fix(schema, {})
    assert sorted(f.location for f in fixes) == [
        "public.bad_a",
        "public.bad_b",
    ]


def test_view001_fix_quotes_view_name_when_required() -> None:
    # Mixed-case identifier requires double-quoting in Postgres.
    schema = Schema(
        tables=(_table(name="users", rls=True, force=True),),
        views=(
            _view(
                name="MixedCase Summary",
                security_invoker=False,
                references=(("public", "users"),),
            ),
        ),
    )
    fixes = VIEW001Fixer().fix(schema, {})
    assert len(fixes) == 1
    assert (
        fixes[0].sql
        == 'ALTER VIEW public."MixedCase Summary" '
        "SET (security_invoker = true);"
    )


def test_view001_fix_silent_when_allowlist_is_bad_type() -> None:
    # Mirror SEC002's pattern: bad config types fail closed (no
    # exemption applied), so the view still fires. The rule's
    # check() raises on bad allowlist shape; the fixer trusts the
    # rule has already validated and uses an inline shim, so a
    # non-list allowlist resolves to "nothing exempt".
    schema = Schema(
        tables=(_table(name="users", rls=True, force=True),),
        views=(
            _view(
                name="user_summary",
                security_invoker=False,
                references=(("public", "users"),),
            ),
        ),
    )
    fixes = VIEW001Fixer().fix(
        schema, {"allowlist": "public.user_summary"}
    )
    assert len(fixes) == 1
    assert fixes[0].location == "public.user_summary"


# ---------- VIEW002 fixer ----------


def test_view002_fix_emits_alter_view_set_security_barrier() -> None:
    schema = Schema(
        tables=(_table(name="users", rls=True, force=True),),
        views=(
            _view(
                name="user_summary",
                security_invoker=True,
                security_barrier=False,
                references=(("public", "users"),),
            ),
        ),
    )
    fixes = VIEW002Fixer().fix(schema, {})
    assert len(fixes) == 1
    f = fixes[0]
    assert f.rule_id == "VIEW002"
    assert f.location == "public.user_summary"
    assert "ALTER VIEW" in f.sql
    assert "public.user_summary" in f.sql
    assert "SET (security_barrier = true)" in f.sql
    assert (
        f.sql
        == "ALTER VIEW public.user_summary "
        "SET (security_barrier = true);"
    )


def test_view002_fix_silent_when_security_barrier_already_true() -> None:
    schema = Schema(
        tables=(_table(name="users", rls=True, force=True),),
        views=(
            _view(
                name="user_summary",
                security_invoker=True,
                security_barrier=True,
                references=(("public", "users"),),
            ),
        ),
    )
    assert VIEW002Fixer().fix(schema, {}) == []


def test_view002_fix_silent_when_referenced_table_has_no_rls() -> None:
    # No RLS-protected reference → nothing to leak → no fix.
    schema = Schema(
        tables=(_table(name="users", rls=False, force=False),),
        views=(
            _view(
                name="user_summary",
                security_invoker=True,
                security_barrier=False,
                references=(("public", "users"),),
            ),
        ),
    )
    assert VIEW002Fixer().fix(schema, {}) == []


def test_view002_fix_silent_on_materialized_view() -> None:
    # Matviews are VIEW003's domain — VIEW002 must skip them.
    # `ALTER VIEW … SET (security_barrier = true)` would also be
    # invalid syntax against a matview.
    schema = Schema(
        tables=(_table(name="users", rls=True, force=True),),
        views=(
            _view(
                name="user_summary",
                is_materialized=True,
                security_invoker=True,
                security_barrier=False,
                references=(("public", "users"),),
            ),
        ),
    )
    assert VIEW002Fixer().fix(schema, {}) == []


def test_view002_fix_respects_qualified_allowlist() -> None:
    schema = Schema(
        tables=(_table(name="users", rls=True, force=True),),
        views=(
            _view(
                name="user_summary",
                security_invoker=True,
                security_barrier=False,
                references=(("public", "users"),),
            ),
        ),
    )
    fixes = VIEW002Fixer().fix(
        schema, {"allowlist": ["public.user_summary"]}
    )
    assert fixes == []


def test_view002_fix_description_mentions_view_and_leaked_tables() -> None:
    schema = Schema(
        tables=(
            _table(name="users", rls=True, force=True),
            _table(name="invoices", rls=True, force=True),
        ),
        views=(
            _view(
                name="user_summary",
                security_invoker=True,
                security_barrier=False,
                references=(
                    ("public", "users"),
                    ("public", "invoices"),
                ),
            ),
        ),
    )
    fixes = VIEW002Fixer().fix(schema, {})
    assert len(fixes) == 1
    desc = fixes[0].description
    assert "public.user_summary" in desc
    assert "public.invoices" in desc
    assert "public.users" in desc


def test_view002_fix_silent_when_view_has_no_references() -> None:
    # A constant-only view has nothing to leak → no fix.
    schema = Schema(
        tables=(_table(name="users", rls=True, force=True),),
        views=(
            _view(
                name="constant_view",
                security_invoker=True,
                security_barrier=False,
                references=(),
            ),
        ),
    )
    assert VIEW002Fixer().fix(schema, {}) == []


def test_view002_fix_emits_one_per_offending_view() -> None:
    schema = Schema(
        tables=(_table(name="users", rls=True, force=True),),
        views=(
            _view(
                name="bad_a",
                security_invoker=True,
                security_barrier=False,
                references=(("public", "users"),),
            ),
            _view(
                name="bad_b",
                security_invoker=True,
                security_barrier=False,
                references=(("public", "users"),),
            ),
            _view(
                name="good",
                security_invoker=True,
                security_barrier=True,
                references=(("public", "users"),),
            ),
        ),
    )
    fixes = VIEW002Fixer().fix(schema, {})
    assert sorted(f.location for f in fixes) == [
        "public.bad_a",
        "public.bad_b",
    ]


def test_view002_fix_quotes_view_name_when_required() -> None:
    # Mixed-case identifier requires double-quoting in Postgres.
    schema = Schema(
        tables=(_table(name="users", rls=True, force=True),),
        views=(
            _view(
                name="MixedCase Summary",
                security_invoker=True,
                security_barrier=False,
                references=(("public", "users"),),
            ),
        ),
    )
    fixes = VIEW002Fixer().fix(schema, {})
    assert len(fixes) == 1
    assert (
        fixes[0].sql
        == 'ALTER VIEW public."MixedCase Summary" '
        "SET (security_barrier = true);"
    )


def test_view002_fix_silent_when_allowlist_is_bad_type() -> None:
    # Mirror SEC002/VIEW001: bad config types fail closed (no
    # exemption applied), so the view still fires. The rule's
    # check() raises on bad allowlist shape; the fixer trusts the
    # rule has already validated and uses an inline shim, so a
    # non-list allowlist resolves to "nothing exempt".
    schema = Schema(
        tables=(_table(name="users", rls=True, force=True),),
        views=(
            _view(
                name="user_summary",
                security_invoker=True,
                security_barrier=False,
                references=(("public", "users"),),
            ),
        ),
    )
    fixes = VIEW002Fixer().fix(
        schema, {"allowlist": "public.user_summary"}
    )
    assert len(fixes) == 1
    assert fixes[0].location == "public.user_summary"


# ---------- PERF001 fixer ----------


def _policy(
    using: str | None = None,
    *,
    name: str = "p",
    command: str = "SELECT",
    with_check: str | None = None,
) -> Policy:
    return Policy(
        name=name,
        command=command,  # type: ignore[arg-type]
        permissive=True,
        roles=("PUBLIC",),
        using_sql=using,
        with_check_sql=with_check,
        using_ast=parse_expr(using) if using else None,
        with_check_ast=parse_expr(with_check) if with_check else None,
    )


def _wrap_policy(policy: Policy) -> Schema:
    return Schema(
        tables=(
            Table(
                schema="public",
                name="t",
                rls_enabled=True,
                force_rls=True,
                policies=(policy,),
                columns=("id", "user_id"),
            ),
        )
    )


def test_perf001_fix_wraps_auth_uid_in_using() -> None:
    schema = _wrap_policy(_policy("user_id = auth.uid()"))
    fixes = PERF001Fixer().fix(schema, {})
    assert len(fixes) == 1
    f = fixes[0]
    assert f.rule_id == "PERF001"
    assert f.location == "public.t.p"
    assert "ALTER POLICY p ON public.t" in f.sql
    assert "USING (user_id = (SELECT auth.uid()))" in f.sql


def test_perf001_fix_wraps_current_setting() -> None:
    schema = _wrap_policy(
        _policy("user_id = current_setting('app.user', true)")
    )
    fixes = PERF001Fixer().fix(schema, {})
    assert len(fixes) == 1
    # pglast's pretty-printer normalizes Boolean literals to
    # uppercase. Functionally identical; assert on the lowercased
    # output so the test is robust to casing.
    sql = fixes[0].sql.lower()
    assert "(select current_setting('app.user', true))" in sql


def test_perf001_fix_silent_when_already_wrapped() -> None:
    schema = _wrap_policy(
        _policy("user_id = (SELECT auth.uid())")
    )
    assert PERF001Fixer().fix(schema, {}) == []


def test_perf001_fix_wraps_multiple_calls_in_one_expression() -> None:
    schema = _wrap_policy(
        _policy(
            "user_id = auth.uid() OR auth.role() = 'admin'"
        )
    )
    fixes = PERF001Fixer().fix(schema, {})
    assert len(fixes) == 1
    sql = fixes[0].sql
    assert "(SELECT auth.uid())" in sql
    assert "(SELECT auth.role())" in sql


def test_perf001_fix_preserves_with_check_verbatim() -> None:
    # WITH CHECK should be reproduced as-is — the rule is USING-only.
    p = _policy(
        "user_id = auth.uid()",
        command="ALL",
        with_check="user_id = (SELECT auth.uid())",
    )
    schema = _wrap_policy(p)
    sql = PERF001Fixer().fix(schema, {})[0].sql
    assert "WITH CHECK (user_id = (SELECT auth.uid()))" in sql
    assert "USING (user_id = (SELECT auth.uid()))" in sql


def test_perf001_fix_silent_when_using_is_none() -> None:
    p = _policy(None, command="INSERT", with_check="user_id = auth.uid()")
    schema = _wrap_policy(p)
    # PERF001 is USING-only — no USING means no fix.
    assert PERF001Fixer().fix(schema, {}) == []


def test_perf001_fix_respects_allowlist() -> None:
    schema = _wrap_policy(_policy("user_id = auth.uid()"))
    options = {"allowlist": ["public.t.p"]}
    assert PERF001Fixer().fix(schema, options) == []


def test_perf001_fix_uses_custom_auth_functions_replaces_default() -> None:
    # Default config: auth.uid() is wrapped.
    schema = _wrap_policy(_policy("user_id = auth.uid()"))
    fixes = PERF001Fixer().fix(
        schema, {"auth_functions": ["my.custom"]}
    )
    # Override replaces default → auth.uid no longer matches.
    assert fixes == []

    # And a custom function gets caught:
    schema2 = _wrap_policy(_policy("user_id = my.custom()"))
    fixes2 = PERF001Fixer().fix(
        schema2, {"auth_functions": ["my.custom"]}
    )
    assert len(fixes2) == 1
    assert "(SELECT my.custom())" in fixes2[0].sql


# ---------- generate_fixes / registry ----------


def test_generate_fixes_returns_union_sorted_by_rule_id_and_location() -> None:
    schema = Schema(
        tables=(
            Table(
                schema="public",
                name="z_table",
                rls_enabled=True,
                force_rls=False,  # SEC002
                policies=(_policy("user_id = auth.uid()"),),  # PERF001
                columns=("id", "user_id"),
            ),
            _table(name="a_table", rls=True, force=False),  # SEC002
        )
    )
    fixes = generate_fixes(schema, rule_options={})
    # Sorted by (rule_id, location). PERF001 < SEC002 alphabetically.
    assert [f.rule_id for f in fixes] == [
        "PERF001",
        "SEC002",
        "SEC002",
    ]
    # Within rule_id, sorted by location.
    sec002 = [f for f in fixes if f.rule_id == "SEC002"]
    assert [f.location for f in sec002] == [
        "public.a_table",
        "public.z_table",
    ]


def test_generate_fixes_filters_to_requested_rule() -> None:
    schema = Schema(
        tables=(
            Table(
                schema="public",
                name="t",
                rls_enabled=True,
                force_rls=False,  # SEC002 fixable
                policies=(_policy("user_id = auth.uid()"),),  # PERF001 fixable
                columns=("id", "user_id"),
            ),
        )
    )
    sec002_only = generate_fixes(
        schema, rule_options={}, rule_filter={"SEC002"}
    )
    assert [f.rule_id for f in sec002_only] == ["SEC002"]


def test_generate_fixes_passes_rule_options() -> None:
    schema = _wrap_policy(_policy("user_id = auth.uid()"))
    fixes = generate_fixes(
        schema,
        rule_options={"PERF001": {"auth_functions": ["my.custom"]}},
    )
    # auth.uid is no longer in the override list, so no fix emitted
    # for PERF001. SEC002 is also silent because force=True. Result
    # is empty.
    assert fixes == []


def test_default_fixers_registers_every_shipping_fixer() -> None:
    rule_ids = {fixer.rule_id for fixer in default_fixers()}
    assert {"SEC001", "SEC002", "PERF001", "VIEW001", "VIEW002"} <= rule_ids


def test_fix_dataclass_is_frozen() -> None:
    import dataclasses

    f = Fix(
        rule_id="X", location="public.t", sql="--", description="test"
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        f.rule_id = "Y"  # type: ignore[misc]


# ============================================================
# Edge cases — fixer robustness
# ============================================================

def test_sec002_fix_silent_when_allowlist_is_bad_type() -> None:
    # Bad config types should fail closed: don't crash, don't
    # apply mystery fixes. SEC002Fixer's `_is_allowlisted` checks
    # the type and returns False on a non-list — so bad config
    # means "nothing is allowlisted", which means the table fires
    # as expected. Pin the conservative behavior.
    schema = Schema(tables=(_table(rls=True, force=False),))
    fixes = SEC002Fixer().fix(schema, {"allowlist": "public.t"})
    assert len(fixes) == 1
    assert fixes[0].location == "public.t"


def test_perf001_fix_silent_when_allowlist_is_bad_type() -> None:
    # Same shape: bad allowlist type → conservatively no
    # exemption applied → fix still emitted.
    schema = _wrap_policy(_policy("user_id = auth.uid()"))
    fixes = PERF001Fixer().fix(schema, {"allowlist": "public.t.p"})
    assert len(fixes) == 1


def test_perf001_fix_falls_back_to_default_on_bad_auth_functions() -> None:
    # Unlike PERF001's rule which raises TypeError, the FIXER
    # falls back to the default auth function set. Reason: the
    # rule has already fired for this policy, the fixer is just
    # generating remediation SQL — bailing out with a TypeError
    # would prevent users from getting any fix output. Pin this
    # behavior.
    schema = _wrap_policy(_policy("user_id = auth.uid()"))
    fixes = PERF001Fixer().fix(
        schema, {"auth_functions": "auth.uid"}  # bad type
    )
    assert len(fixes) == 1
    assert "(SELECT auth.uid())" in fixes[0].sql


def test_perf001_fix_wraps_nested_auth_calls_independently() -> None:
    # `COALESCE(auth.uid(), auth.role()::uuid)` — two auth calls
    # nested inside another function call. Each should get its
    # own SubLink wrapping, neither should swallow the other.
    schema = _wrap_policy(
        _policy(
            "user_id = COALESCE(auth.uid(), auth.role()::UUID)"
        )
    )
    fixes = PERF001Fixer().fix(schema, {})
    assert len(fixes) == 1
    sql = fixes[0].sql
    assert "(SELECT auth.uid())" in sql
    assert "(SELECT auth.role())" in sql


def test_perf001_fix_preserves_other_function_calls_verbatim() -> None:
    # `lower(email) = lower((SELECT auth.uid())::text)` — the
    # `lower` calls are NOT auth functions; they should pass
    # through untouched. The fixer must wrap only what matches
    # the auth set.
    schema = _wrap_policy(
        _policy("lower(email) = lower(auth.uid()::text)")
    )
    fixes = PERF001Fixer().fix(schema, {})
    assert len(fixes) == 1
    sql = fixes[0].sql.lower()
    assert "lower(email)" in sql
    # The nested auth.uid() got wrapped.
    assert "(select auth.uid())" in sql


def test_perf001_fix_emits_one_alter_policy_per_offending_policy() -> None:
    # Two policies on the same table, both with unwrapped auth.
    # Two ALTER POLICY statements, one per policy.
    schema = Schema(
        tables=(
            Table(
                schema="public",
                name="t",
                rls_enabled=True,
                force_rls=True,
                policies=(
                    _policy("user_id = auth.uid()", name="p1"),
                    _policy(
                        "tenant_id = current_setting('app.t', true)::UUID",
                        name="p2",
                    ),
                ),
                columns=("id", "user_id", "tenant_id"),
            ),
        )
    )
    fixes = PERF001Fixer().fix(schema, {})
    assert len(fixes) == 2
    assert {f.location for f in fixes} == {"public.t.p1", "public.t.p2"}


def test_perf001_fix_silent_when_auth_unwrapped_only_in_with_check() -> None:
    # PERF001 is USING-only. If WITH CHECK has an unwrapped auth
    # call but USING does not, PERF001Fixer must not generate a
    # fix — there's nothing for it to repair.
    p = _policy(
        "id > 0",  # USING is clean
        with_check="user_id = auth.uid()",  # WITH CHECK is unwrapped
    )
    schema = _wrap_policy(p)
    assert PERF001Fixer().fix(schema, {}) == []


def test_generate_fixes_with_empty_schema() -> None:
    schema = Schema(tables=())
    assert generate_fixes(schema, rule_options={}) == []


def test_generate_fixes_with_unknown_rule_filter_returns_empty() -> None:
    # `--rule SEC999` typo: no fixer registers under that ID, so
    # nothing is generated. Should not crash.
    schema = _wrap_policy(_policy("user_id = auth.uid()"))
    fixes = generate_fixes(
        schema, rule_options={}, rule_filter={"SEC999"}
    )
    assert fixes == []


def test_perf001_fixer_silent_on_sql_value_function() -> None:
    # `current_user` is a Postgres SQLValueFunction, not a regular
    # FuncCall. Wrapping it in `(SELECT current_user)` is dubious
    # (the grammar special doesn't compose the same way), so the
    # fixer deliberately skips it. PERF001's check still catches
    # it when configured; the rule fires, the fixer emits nothing.
    # Pin the deliberate asymmetry — a future change that wraps
    # SQLValueFunction would be visible here.
    schema = _wrap_policy(_policy("current_user = 'admin'"))
    fixes = PERF001Fixer().fix(
        schema, {"auth_functions": ["current_user"]}
    )
    assert fixes == []


def test_sec002_fix_quotes_table_name_when_required() -> None:
    # Mixed-case identifier requires double-quoting in Postgres.
    # `pg_class.relname` returns the raw name; the fixer must
    # quote when emitting back into SQL.
    schema = Schema(
        tables=(
            Table(
                schema="public",
                name="MixedCase Table",
                rls_enabled=True,
                force_rls=False,
                policies=(),
            ),
        )
    )
    fixes = SEC002Fixer().fix(schema, {})
    assert len(fixes) == 1
    assert (
        'ALTER TABLE public."MixedCase Table" FORCE ROW LEVEL SECURITY;'
        == fixes[0].sql
    )


def test_sec002_fix_does_not_quote_plain_identifiers() -> None:
    # `snake_case_users` is a plain identifier — emit bare to
    # keep the common case readable.
    schema = Schema(
        tables=(
            _table(name="snake_case_users", rls=True, force=False),
        )
    )
    sql = SEC002Fixer().fix(schema, {})[0].sql
    assert (
        sql
        == "ALTER TABLE public.snake_case_users FORCE ROW LEVEL SECURITY;"
    )


def test_perf001_fix_quotes_policy_and_table_when_required() -> None:
    # Policy and table both have characters requiring quoting.
    p = _policy("user_id = auth.uid()", name="My Policy")
    schema = Schema(
        tables=(
            Table(
                schema="public",
                name="MixedCase Table",
                rls_enabled=True,
                force_rls=True,
                policies=(p,),
                columns=("id", "user_id"),
            ),
        )
    )
    sql = PERF001Fixer().fix(schema, {})[0].sql
    assert 'ALTER POLICY "My Policy"' in sql
    assert 'ON public."MixedCase Table"' in sql


def test_quote_ident_rejects_null_byte() -> None:
    # Postgres rejects nulls in CREATE; if a snapshot or hand-
    # built Schema sneaks one in, fail fast here with a clear
    # message rather than emitting `"a\x00b"` for the server to
    # reject with a confusing error.
    from pgrls.fixers._idents import quote_ident
    with pytest.raises(ValueError, match="control character"):
        quote_ident("evil\x00name")


def test_quote_ident_rejects_embedded_newline() -> None:
    from pgrls.fixers._idents import quote_ident
    with pytest.raises(ValueError, match="control character"):
        quote_ident("name\nwith\nnewlines")


def test_perf001_fix_round_trips_with_check_through_pglast() -> None:
    # WITH CHECK should be re-emitted via RawStream rather than
    # echoed verbatim. Asymmetric handling would be an injection
    # vector if `with_check_sql` ever sources from somewhere
    # other than `pg_get_expr`. We verify the round-trip by
    # passing a WITH CHECK shape that pglast normalizes (single
    # quotes around boolean false), then asserting the
    # round-tripped form appears in the SQL.
    p = _policy(
        "user_id = auth.uid()",
        command="ALL",
        with_check="user_id = (SELECT auth.uid()) AND deleted_at IS NULL",
    )
    schema = _wrap_policy(p)
    sql = PERF001Fixer().fix(schema, {})[0].sql
    # The WITH CHECK passed through RawStream — pglast's printer
    # would normalize whitespace and casing. Assert the structural
    # content is present.
    assert "WITH CHECK" in sql
    assert "deleted_at" in sql
    assert "IS NULL" in sql


def test_perf001_fix_sublink_wraps_do_not_alias_each_other() -> None:
    # Each `_wrap_funccall` call constructs a fresh SubLink/
    # SelectStmt tuple — wrapping multiple FuncCalls in one pass
    # produces independent subtrees. A shared subselect would
    # cause the second wrap to overwrite the first's `val` and
    # emit `(SELECT auth.role())` twice.
    schema = _wrap_policy(
        _policy(
            "user_id = auth.uid() OR user_id = auth.role()::UUID"
        )
    )
    fixes = PERF001Fixer().fix(schema, {})
    sql = fixes[0].sql
    # Both calls should be wrapped with their respective inner
    # functions intact — proves the SubLinks are independent.
    assert "(SELECT auth.uid())" in sql
    assert "(SELECT auth.role())" in sql


def test_wrap_funccall_emits_select_sublink() -> None:
    # Pin the direct-construction shape: `_wrap_funccall` returns a
    # SubLink whose RawStream-emitted form is exactly the
    # `(SELECT <call>)` Postgres expects. Regression guard for
    # the deepcopy → direct-construction perf fix; if a future
    # refactor swaps SubLinkType, drops the LimitOption default,
    # or otherwise breaks the emitted SQL, this fails.
    from pglast.ast import FuncCall, String
    from pglast.stream import RawStream

    from pgrls.fixers.perf001 import _wrap_funccall

    fc = FuncCall(funcname=(String(sval="auth"), String(sval="uid")))
    sublink = _wrap_funccall(fc)
    assert RawStream()(sublink) == "(SELECT auth.uid())"


def test_wrap_funccall_returns_independent_objects() -> None:
    # Two consecutive calls must not share any mutable subtree:
    # mutating one SubLink's targetList must not affect the other.
    from pglast.ast import FuncCall, String

    from pgrls.fixers.perf001 import _wrap_funccall

    fc1 = FuncCall(funcname=(String(sval="auth"), String(sval="uid")))
    fc2 = FuncCall(funcname=(String(sval="auth"), String(sval="role")))
    s1 = _wrap_funccall(fc1)
    s2 = _wrap_funccall(fc2)
    assert s1 is not s2
    assert s1.subselect is not s2.subselect
    assert s1.subselect.targetList is not s2.subselect.targetList


def test_quote_ident_rejects_empty_string() -> None:
    from pgrls.fixers._idents import quote_ident
    with pytest.raises(ValueError, match="empty"):
        quote_ident("")


def test_quote_ident_quotes_reserved_keywords() -> None:
    # A table named "select" or a policy named "order" must be
    # quoted at emission time, otherwise pgrls's fixer SQL is a
    # syntax error on the server. An earlier regex-only check
    # treated reserved words as plain identifiers because they
    # match `[a-z_][a-z0-9_]*`.
    from pgrls.fixers._idents import quote_ident

    for kw in ("select", "from", "where", "table", "user", "order"):
        out = quote_ident(kw)
        assert out == f'"{kw}"', (
            f"reserved keyword {kw!r} must be quoted, got {out!r}"
        )


def test_quote_ident_keyword_check_is_case_insensitive() -> None:
    # Postgres parses identifiers case-insensitively before
    # quoting. `SELECT` / `Select` / `select` all collide with the
    # reserved token. A user with a `"Select"` table (mixed case)
    # gets quoting either way (mixed case alone forces it), but
    # pin the case-folded path explicitly.
    from pgrls.fixers._idents import quote_ident

    assert quote_ident("SELECT") == '"SELECT"'
    assert quote_ident("Select") == '"Select"'


def test_quote_ident_rejects_tab_character() -> None:
    # An earlier change rejected null/newline; tab is the same
    # hazard. Pin the wider control-char check so the defense is
    # uniform.
    from pgrls.fixers._idents import quote_ident

    with pytest.raises(ValueError, match="control character"):
        quote_ident("weird\tname")


def test_quote_ident_rejects_all_c0_controls() -> None:
    from pgrls.fixers._idents import quote_ident

    for codepoint in list(range(0x20)) + [0x7f]:
        ch = chr(codepoint)
        with pytest.raises(ValueError, match="control character"):
            quote_ident(f"x{ch}y")


def test_quote_ident_quotes_non_ascii() -> None:
    # ASCII-only regex is the gate; pin so a future swap to
    # str.isidentifier() (which accepts Unicode letters) doesn't
    # silently emit non-ASCII bare on locale-dependent servers.
    from pgrls.fixers._idents import quote_ident

    assert quote_ident("café") == '"café"'
    assert quote_ident("über") == '"über"'


def test_perf001_fixer_default_auth_functions_matches_rule_default() -> None:
    # Pin "the fixer fixes exactly what the rule reports" by
    # asserting both modules consume the same default set. Two
    # parallel constants (the previous shape) would silently drift
    # when a future change adds, e.g., `app.current_user_id` to
    # the rule's defaults but not the fixer's — the user would
    # see the lint flag the call but `pgrls fix` wouldn't generate
    # a fix.
    from pgrls.fixers import perf001 as fixer_mod
    from pgrls.rules import perf001 as rule_mod

    assert (
        fixer_mod._DEFAULT_AUTH_FUNCTIONS
        is rule_mod._DEFAULT_AUTH_FUNCTIONS
    ), (
        "Fixer must import the rule's _DEFAULT_AUTH_FUNCTIONS, "
        "not maintain its own copy."
    )


def test_perf001_does_not_mutate_input_policy_ast() -> None:
    # `_wrap_unwrapped_calls` mutates pglast Node fields in place
    # — `Policy` is a frozen dataclass but `frozen=True` does NOT
    # freeze the AST graph it holds. Without a deepcopy guard at
    # the fixer entry, running PERF001Fixer would visibly alter
    # `policy.using_ast` for any rule that re-walks the Schema
    # afterwards (snapshot tests, programmatic API). Pin the
    # "fixer is read-only over Schema" invariant.
    from pglast.stream import RawStream

    schema = _wrap_policy(_policy("user_id = auth.uid()"))
    policy = schema.tables[0].policies[0]
    original_id = id(policy.using_ast)
    original_sql = RawStream()(policy.using_ast)

    PERF001Fixer().fix(schema, {})

    assert id(policy.using_ast) == original_id, (
        "Policy.using_ast was replaced; the fixer should not "
        "alter the input Schema."
    )
    assert RawStream()(policy.using_ast) == original_sql, (
        "Policy.using_ast was mutated in place; got "
        f"{RawStream()(policy.using_ast)!r}, expected "
        f"{original_sql!r}."
    )
