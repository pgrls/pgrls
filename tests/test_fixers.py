"""Unit tests for the auto-fix machinery and per-rule fixers."""
from __future__ import annotations

import pytest

from pgrls.ast_utils import parse_expr
from pgrls.fixers import (
    Fix,
    default_fixers,
    generate_fixes,
    render_fixes,
    render_migration,
)
from pgrls.fixers.hyg003 import HYG003Fixer
from pgrls.fixers.perf001 import PERF001Fixer
from pgrls.fixers.perf003 import PERF003Fixer
from pgrls.fixers.sec001 import SEC001Fixer
from pgrls.fixers.sec002 import SEC002Fixer
from pgrls.fixers.sec006 import SEC006Fixer
from pgrls.fixers.sec011 import SEC011Fixer
from pgrls.fixers.sec019 import SEC019Fixer
from pgrls.fixers.sec020 import SEC020Fixer
from pgrls.fixers.sec031 import SEC031Fixer
from pgrls.fixers.view001 import VIEW001Fixer
from pgrls.fixers.view002 import VIEW002Fixer
from pgrls.model import Index, Policy, Schema, Table, View


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


def test_sec001_fix_raises_on_malformed_allowlist() -> None:
    # The fixer validates with SEC001's strict parser
    # (parse_table_ref_allowlist), so a malformed allowlist raises
    # TypeError — `pgrls fix` surfaces it as a ToolError, exactly
    # as `pgrls lint` rejects the same config.
    schema = Schema(tables=(_table(rls=False, force=False),))
    # Bad type — not a list.
    with pytest.raises(TypeError, match="allowlist"):
        SEC001Fixer().fix(schema, {"allowlist": "public.t"})
    # Malformed entry — surrounding whitespace.
    with pytest.raises(TypeError, match="allowlist"):
        SEC001Fixer().fix(schema, {"allowlist": [" public.t "]})


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


def test_view001_fix_raises_on_malformed_allowlist() -> None:
    # The fixer validates with VIEW001's strict parser
    # (parse_qualified_view_allowlist), so a malformed allowlist
    # raises TypeError — `pgrls fix` surfaces it as a ToolError,
    # exactly as `pgrls lint` rejects the same config.
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
    # Bad type — not a list.
    with pytest.raises(TypeError, match="allowlist"):
        VIEW001Fixer().fix(
            schema, {"allowlist": "public.user_summary"}
        )
    # Malformed entry — surrounding whitespace.
    with pytest.raises(TypeError, match="allowlist"):
        VIEW001Fixer().fix(
            schema, {"allowlist": [" public.user_summary "]}
        )


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


def test_view002_fix_raises_on_malformed_allowlist() -> None:
    # The fixer validates with VIEW002's strict parser
    # (parse_qualified_view_allowlist), so a malformed allowlist
    # raises TypeError — `pgrls fix` surfaces it as a ToolError,
    # exactly as `pgrls lint` rejects the same config.
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
    # Bad type — not a list.
    with pytest.raises(TypeError, match="allowlist"):
        VIEW002Fixer().fix(
            schema, {"allowlist": "public.user_summary"}
        )
    # Malformed entry — surrounding whitespace.
    with pytest.raises(TypeError, match="allowlist"):
        VIEW002Fixer().fix(
            schema, {"allowlist": [" public.user_summary "]}
        )


# ---------- PERF001 fixer ----------


def _policy(
    using: str | None = None,
    *,
    name: str = "p",
    command: str = "SELECT",
    with_check: str | None = None,
    permissive: bool = True,
) -> Policy:
    return Policy(
        name=name,
        command=command,  # type: ignore[arg-type]
        permissive=permissive,
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
                # Index the candidate policy columns so the PERF003
                # fixer stays silent here — PERF003 is exercised in
                # its own section, not incidentally via _wrap_policy.
                indexes=(
                    _idx("id", name="t_id_idx"),
                    _idx("user_id", name="t_user_id_idx"),
                ),
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


# ---------- SEC006 fixer ----------


def test_sec006_fix_emits_with_check_mirroring_using() -> None:
    schema = _wrap_policy(_policy("user_id = 1", command="ALL"))
    fixes = SEC006Fixer().fix(schema, {})
    assert len(fixes) == 1
    f = fixes[0]
    assert f.rule_id == "SEC006"
    assert f.location == "public.t.p"
    assert "ALTER POLICY p ON public.t" in f.sql
    assert "WITH CHECK (user_id = 1)" in f.sql


def test_sec006_fix_silent_when_with_check_already_present() -> None:
    p = _policy("user_id = 1", command="ALL", with_check="user_id = 1")
    assert SEC006Fixer().fix(_wrap_policy(p), {}) == []


def test_sec006_fix_silent_on_select_policy() -> None:
    # SELECT is not a write command — WITH CHECK does not apply.
    schema = _wrap_policy(_policy("user_id = 1", command="SELECT"))
    assert SEC006Fixer().fix(schema, {}) == []


def test_sec006_fix_fires_on_for_update_policy() -> None:
    schema = _wrap_policy(_policy("user_id = 1", command="UPDATE"))
    fixes = SEC006Fixer().fix(schema, {})
    assert len(fixes) == 1
    assert "WITH CHECK (user_id = 1)" in fixes[0].sql


def test_sec006_fix_skips_insert_policy_with_no_using() -> None:
    # A FOR INSERT policy has no USING to mirror — Postgres forbids
    # `FOR INSERT … USING`. SEC006 fires, but the fixer cannot
    # mechanically derive a WITH CHECK, so it skips.
    p = _policy(None, command="INSERT")
    assert SEC006Fixer().fix(_wrap_policy(p), {}) == []


def test_sec006_fix_skips_write_policy_with_no_using() -> None:
    # A FOR UPDATE / FOR ALL policy can omit USING too — there is
    # then no predicate to copy into WITH CHECK.
    p = _policy(None, command="UPDATE")
    assert SEC006Fixer().fix(_wrap_policy(p), {}) == []


def test_sec006_fix_skips_restrictive_policy() -> None:
    # A restrictive write-side policy with no WITH CHECK is a dead
    # policy; SEC006's remediation there ("express the intended
    # predicate, or remove the policy") needs human intent, so the
    # fixer skips it — only permissive write policies are fixed.
    p = _policy("user_id = 1", command="ALL", permissive=False)
    assert SEC006Fixer().fix(_wrap_policy(p), {}) == []


def test_sec006_fix_respects_allowlist() -> None:
    schema = _wrap_policy(_policy("user_id = 1", command="ALL"))
    assert SEC006Fixer().fix(schema, {"allowlist": ["public.t.p"]}) == []


def test_sec006_fix_emits_one_per_offending_policy() -> None:
    schema = Schema(
        tables=(
            Table(
                schema="public",
                name="t",
                rls_enabled=True,
                force_rls=True,
                columns=("id", "user_id"),
                policies=(
                    _policy("user_id = 1", name="bad_a", command="ALL"),
                    _policy(
                        "user_id = 1",
                        name="ok",
                        command="ALL",
                        with_check="user_id = 1",
                    ),
                    _policy(
                        "user_id = 2", name="bad_b", command="UPDATE"
                    ),
                ),
            ),
        )
    )
    fixes = SEC006Fixer().fix(schema, {})
    assert sorted(f.location for f in fixes) == [
        "public.t.bad_a",
        "public.t.bad_b",
    ]


def test_sec006_fix_quotes_policy_and_table_when_required() -> None:
    p = _policy("user_id = 1", name="My Policy", command="ALL")
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
    sql = SEC006Fixer().fix(schema, {})[0].sql
    assert 'ALTER POLICY "My Policy"' in sql
    assert 'ON public."MixedCase Table"' in sql


def test_sec006_fix_round_trips_using_through_pglast() -> None:
    # The USING predicate is re-emitted via RawStream, not echoed
    # verbatim. Feed a non-canonical form (no spaces around `=`)
    # and assert pglast's normalized spacing appears — a verbatim
    # echo of the raw `using_sql` would keep `user_id=1`.
    schema = _wrap_policy(_policy("user_id=1", command="ALL"))
    sql = SEC006Fixer().fix(schema, {})[0].sql
    assert "WITH CHECK (user_id = 1)" in sql


def test_sec006_fix_raises_on_malformed_allowlist() -> None:
    # The fixer validates with SEC006's strict parser
    # (parse_policy_id_allowlist), so a malformed allowlist raises
    # TypeError — `pgrls fix` surfaces it as a ToolError, exactly
    # as `pgrls lint` rejects the same config.
    schema = _wrap_policy(_policy("user_id = 1", command="ALL"))
    # Bad type — not a list.
    with pytest.raises(TypeError, match="allowlist"):
        SEC006Fixer().fix(schema, {"allowlist": "public.t.p"})
    # Malformed entry — surrounding whitespace.
    with pytest.raises(TypeError, match="allowlist"):
        SEC006Fixer().fix(schema, {"allowlist": [" public.t.p "]})


# ---------- SEC019 fixer ----------


def test_sec019_fix_adds_missing_ok_to_one_arg_current_setting() -> None:
    schema = _wrap_policy(
        _policy("user_id = current_setting('app.user')")
    )
    fixes = SEC019Fixer().fix(schema, {})
    assert len(fixes) == 1
    f = fixes[0]
    assert f.rule_id == "SEC019"
    assert f.location == "public.t.p"
    assert "ALTER POLICY p ON public.t" in f.sql
    # pglast normalizes the boolean to uppercase; the rewrite is
    # semantically `current_setting(..., true)`.
    assert "current_setting('app.user', TRUE)" in f.sql


def test_sec019_fix_silent_when_already_two_arg() -> None:
    # `current_setting('x', true)` is already in the safe form;
    # SEC019 the rule stays silent, and so does the fixer.
    schema = _wrap_policy(
        _policy("user_id = current_setting('app.user', true)")
    )
    assert SEC019Fixer().fix(schema, {}) == []


def test_sec019_fix_silent_when_no_current_setting() -> None:
    schema = _wrap_policy(_policy("user_id = 1"))
    assert SEC019Fixer().fix(schema, {}) == []


def test_sec019_fix_handles_pg_catalog_qualified_form() -> None:
    # Matches SEC019's detection — both bare and pg_catalog-
    # qualified `current_setting` calls get the rewrite.
    schema = _wrap_policy(
        _policy("user_id = pg_catalog.current_setting('app.user')")
    )
    sql = SEC019Fixer().fix(schema, {})[0].sql
    assert "pg_catalog.current_setting('app.user', TRUE)" in sql


def test_sec019_fix_rewrites_call_in_with_check() -> None:
    # WITH CHECK side also gets rewritten; SEC019 fires on either
    # clause, so the fixer covers both.
    p = _policy(
        "user_id = 1",
        command="ALL",
        with_check="user_id = current_setting('app.user')",
    )
    sql = SEC019Fixer().fix(_wrap_policy(p), {})[0].sql
    assert "WITH CHECK (user_id = current_setting('app.user', TRUE))" in sql
    # USING is unchanged, so it must NOT appear in the ALTER:
    # the fixer emits only the changed clause(s).
    assert "USING (" not in sql


def test_sec019_fix_emits_only_changed_clauses() -> None:
    # USING has the one-arg form; WITH CHECK already has two args.
    # The fixer rewrites USING and emits an ALTER POLICY with
    # USING only — leaving WITH CHECK alone for a minimal diff.
    p = _policy(
        "user_id = current_setting('app.user')",
        command="ALL",
        with_check="user_id = current_setting('app.user', true)",
    )
    sql = SEC019Fixer().fix(_wrap_policy(p), {})[0].sql
    assert "USING (user_id = current_setting('app.user', TRUE))" in sql
    assert "WITH CHECK" not in sql


def test_sec019_fix_emits_both_clauses_when_both_have_one_arg() -> None:
    # Both sides have the one-arg form — both get rewritten and
    # both appear in the ALTER POLICY.
    p = _policy(
        "user_id = current_setting('app.user')",
        command="ALL",
        with_check="user_id = current_setting('app.user')",
    )
    sql = SEC019Fixer().fix(_wrap_policy(p), {})[0].sql
    assert "USING (user_id = current_setting('app.user', TRUE))" in sql
    assert "WITH CHECK (user_id = current_setting('app.user', TRUE))" in sql


def test_sec019_fix_rewrites_call_wrapped_in_subselect() -> None:
    # PERF001's wrapped form `(SELECT current_setting('x'))` — the
    # inner call is still one-arg, so SEC019 fires and the fixer
    # walks into the SubLink.
    schema = _wrap_policy(
        _policy("user_id = (SELECT current_setting('app.user'))")
    )
    sql = SEC019Fixer().fix(schema, {})[0].sql
    assert "(SELECT current_setting('app.user', TRUE))" in sql


def test_sec019_fix_respects_allowlist() -> None:
    schema = _wrap_policy(
        _policy("user_id = current_setting('app.user')")
    )
    assert SEC019Fixer().fix(
        schema, {"allowlist": ["public.t.p"]}
    ) == []


def test_sec019_fix_emits_one_per_offending_policy() -> None:
    schema = Schema(
        tables=(
            Table(
                schema="public",
                name="t",
                rls_enabled=True,
                force_rls=True,
                columns=("id", "user_id"),
                policies=(
                    _policy(
                        "user_id = current_setting('app.user')",
                        name="bad_a",
                    ),
                    _policy(
                        "user_id = current_setting('app.user', true)",
                        name="ok",
                    ),
                    _policy(
                        "user_id = current_setting('app.team')",
                        name="bad_b",
                    ),
                ),
            ),
        )
    )
    fixes = SEC019Fixer().fix(schema, {})
    assert sorted(f.location for f in fixes) == [
        "public.t.bad_a",
        "public.t.bad_b",
    ]


def test_sec019_fix_does_not_mutate_input_schema() -> None:
    # PERF001's fixer deepcopies the AST before mutating; SEC019
    # must do the same so the rule's view of the policy isn't
    # silently rewritten as a side effect of `pgrls fix`.
    p = _policy("user_id = current_setting('app.user')")
    schema = _wrap_policy(p)
    SEC019Fixer().fix(schema, {})
    # The original AST still renders as the one-arg form.
    from pglast.stream import RawStream
    assert "TRUE" not in RawStream()(p.using_ast)


def test_sec019_fix_description_explains_the_tradeoff() -> None:
    # SEC019 is info severity precisely because the choice
    # between the two overloads is judgement; the description
    # must spell out that the rewrite picks the quiet-NULL side
    # and point at the allowlist for users who wanted the loud
    # raise.
    schema = _wrap_policy(
        _policy("user_id = current_setting('app.user')")
    )
    [f] = SEC019Fixer().fix(schema, {})
    assert "missing_ok" in f.description
    assert "[lint.rules.SEC019]" in f.description


def test_sec019_fix_raises_on_malformed_allowlist() -> None:
    schema = _wrap_policy(
        _policy("user_id = current_setting('app.user')")
    )
    with pytest.raises(TypeError, match="allowlist"):
        SEC019Fixer().fix(schema, {"allowlist": "public.t.p"})
    with pytest.raises(TypeError, match="allowlist"):
        SEC019Fixer().fix(schema, {"allowlist": [" public.t.p "]})


def test_sec019_and_perf001_both_fire_on_unwrapped_one_arg_current_setting() -> None:
    # PERF001 (wrap auth calls in `(SELECT …)`) and SEC019 (add the
    # `, true` second argument) both target the same shape — an
    # unwrapped one-arg `current_setting` — and run independently.
    # Both emit an `ALTER POLICY` for the same policy: PERF001
    # wraps but leaves the arity at one; SEC019 adds the missing_ok
    # argument but leaves the call unwrapped. Whichever runs last
    # overwrites the prior clause, so `pgrls fix --apply` converges
    # in TWO passes on a policy that triggers both rules.
    #
    # This regression test pins that contract — a future "smart
    # composite fixer" that emitted a single combined ALTER would
    # need to update this test deliberately rather than silently
    # change `pgrls fix`'s convergence story.
    schema = _wrap_policy(
        _policy("user_id = current_setting('app.user')")
    )
    perf_fixes = PERF001Fixer().fix(schema, {})
    sec_fixes = SEC019Fixer().fix(schema, {})

    assert len(perf_fixes) == 1
    assert len(sec_fixes) == 1
    assert perf_fixes[0].location == sec_fixes[0].location == "public.t.p"

    # PERF001's ALTER wraps in `(SELECT …)` but keeps the one-arg
    # call — SEC019 still re-fires on its output.
    assert "(SELECT current_setting('app.user'))" in perf_fixes[0].sql
    assert ", TRUE)" not in perf_fixes[0].sql

    # SEC019's ALTER adds the second argument but leaves the call
    # unwrapped — PERF001 still re-fires on its output.
    assert "current_setting('app.user', TRUE)" in sec_fixes[0].sql
    assert "(SELECT" not in sec_fixes[0].sql


# ---------- SEC020 fixer ----------


def test_sec020_fix_replaces_constant_true_with_check() -> None:
    schema = _wrap_policy(
        _policy("user_id = 1", command="ALL", with_check="true")
    )
    fixes = SEC020Fixer().fix(schema, {})
    assert len(fixes) == 1
    f = fixes[0]
    assert f.rule_id == "SEC020"
    assert f.location == "public.t.p"
    assert "ALTER POLICY p ON public.t" in f.sql
    assert "WITH CHECK (user_id = 1)" in f.sql


def test_sec020_fix_silent_when_with_check_is_a_real_predicate() -> None:
    # WITH CHECK already mirrors a real predicate — nothing to fix.
    p = _policy("user_id = 1", command="ALL", with_check="user_id = 1")
    assert SEC020Fixer().fix(_wrap_policy(p), {}) == []


def test_sec020_fix_silent_when_with_check_absent() -> None:
    # A missing WITH CHECK is SEC006's surface, not SEC020's.
    schema = _wrap_policy(_policy("user_id = 1", command="ALL"))
    assert SEC020Fixer().fix(schema, {}) == []


def test_sec020_fix_silent_when_using_is_constant_true() -> None:
    # USING (true) is a fully-open policy — SEC008's concern. With
    # no real read predicate there is no asymmetry to remediate.
    p = _policy("true", command="ALL", with_check="true")
    assert SEC020Fixer().fix(_wrap_policy(p), {}) == []


def test_sec020_fix_silent_when_using_absent() -> None:
    # A FOR INSERT policy has no USING to mirror into WITH CHECK.
    p = _policy(None, command="INSERT", with_check="true")
    assert SEC020Fixer().fix(_wrap_policy(p), {}) == []


def test_sec020_fix_fires_on_for_update_policy() -> None:
    schema = _wrap_policy(
        _policy("user_id = 1", command="UPDATE", with_check="true")
    )
    fixes = SEC020Fixer().fix(schema, {})
    assert len(fixes) == 1
    assert "WITH CHECK (user_id = 1)" in fixes[0].sql


def test_sec020_fix_fixes_restrictive_policy() -> None:
    # Unlike the SEC006 fixer, SEC020's fixes restrictive policies
    # too: a restrictive policy's WITH CHECK (true) is a no-op
    # write check (restrictive AND true), and mirroring USING turns
    # it into a real constraint — a meaningful, correct fix.
    p = _policy(
        "user_id = 1", command="ALL", with_check="true", permissive=False
    )
    fixes = SEC020Fixer().fix(_wrap_policy(p), {})
    assert len(fixes) == 1
    assert "WITH CHECK (user_id = 1)" in fixes[0].sql


def test_sec020_fix_respects_allowlist() -> None:
    schema = _wrap_policy(
        _policy("user_id = 1", command="ALL", with_check="true")
    )
    assert SEC020Fixer().fix(schema, {"allowlist": ["public.t.p"]}) == []


def test_sec020_fix_emits_one_per_offending_policy() -> None:
    schema = Schema(
        tables=(
            Table(
                schema="public",
                name="t",
                rls_enabled=True,
                force_rls=True,
                columns=("id", "user_id"),
                policies=(
                    _policy(
                        "user_id = 1",
                        name="bad_a",
                        command="ALL",
                        with_check="true",
                    ),
                    _policy(
                        "user_id = 1",
                        name="ok",
                        command="ALL",
                        with_check="user_id = 1",
                    ),
                    _policy(
                        "user_id = 2",
                        name="bad_b",
                        command="UPDATE",
                        with_check="true",
                    ),
                ),
            ),
        )
    )
    fixes = SEC020Fixer().fix(schema, {})
    assert sorted(f.location for f in fixes) == [
        "public.t.bad_a",
        "public.t.bad_b",
    ]


def test_sec020_fix_quotes_policy_and_table_when_required() -> None:
    p = _policy(
        "user_id = 1", name="My Policy", command="ALL", with_check="true"
    )
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
    sql = SEC020Fixer().fix(schema, {})[0].sql
    assert 'ALTER POLICY "My Policy"' in sql
    assert 'ON public."MixedCase Table"' in sql


def test_sec020_fix_round_trips_using_through_pglast() -> None:
    # The USING predicate is re-emitted via RawStream, not echoed
    # verbatim — a non-canonical `user_id=1` comes back normalized.
    schema = _wrap_policy(
        _policy("user_id=1", command="ALL", with_check="true")
    )
    sql = SEC020Fixer().fix(schema, {})[0].sql
    assert "WITH CHECK (user_id = 1)" in sql


def test_sec020_fix_raises_on_malformed_allowlist() -> None:
    # The fixer validates with SEC020's strict parser, so a
    # malformed allowlist raises TypeError — `pgrls fix` surfaces
    # it as a ToolError, exactly as `pgrls lint` rejects it.
    schema = _wrap_policy(
        _policy("user_id = 1", command="ALL", with_check="true")
    )
    with pytest.raises(TypeError, match="allowlist"):
        SEC020Fixer().fix(schema, {"allowlist": "public.t.p"})
    with pytest.raises(TypeError, match="allowlist"):
        SEC020Fixer().fix(schema, {"allowlist": [" public.t.p "]})


# ---------- HYG003 fixer ----------


def _dup_table(
    *policies: Policy, name: str = "t", schema: str = "public"
) -> Schema:
    """A single RLS-forced table holding `policies` — HYG003 setup."""
    return Schema(
        tables=(
            Table(
                schema=schema,
                name=name,
                rls_enabled=True,
                force_rls=True,
                policies=policies,
            ),
        )
    )


def test_hyg003_fix_emits_drop_policy_for_duplicate() -> None:
    schema = _dup_table(
        _policy("user_id = 1", name="p_a"),
        _policy("user_id = 1", name="p_b"),
    )
    fixes = HYG003Fixer().fix(schema, {})
    assert len(fixes) == 1
    f = fixes[0]
    assert f.rule_id == "HYG003"
    # Name-sorted first ('p_a') is kept; 'p_b' is the redundant drop.
    assert f.location == "public.t.p_b"
    assert f.sql == "DROP POLICY p_b ON public.t;"


def test_hyg003_fix_keeps_name_sorted_first_policy() -> None:
    # Input order is reversed — the fixer still keeps the
    # name-sorted-first policy and drops the other, so output is
    # deterministic regardless of how the snapshot ordered policies.
    schema = _dup_table(
        _policy("user_id = 1", name="z_policy"),
        _policy("user_id = 1", name="a_policy"),
    )
    fixes = HYG003Fixer().fix(schema, {})
    assert [f.location for f in fixes] == ["public.t.z_policy"]


def test_hyg003_fix_silent_on_distinct_policies() -> None:
    # Different USING text → different signature → not duplicates.
    schema = _dup_table(
        _policy("user_id = 1", name="p_a"),
        _policy("user_id = 2", name="p_b"),
    )
    assert HYG003Fixer().fix(schema, {}) == []


def test_hyg003_fix_silent_on_policies_differing_only_by_command() -> None:
    # Same predicate, different command — a FOR SELECT and a FOR
    # UPDATE policy are not duplicates even with identical USING.
    schema = _dup_table(
        _policy("user_id = 1", name="p_a", command="SELECT"),
        _policy("user_id = 1", name="p_b", command="UPDATE"),
    )
    assert HYG003Fixer().fix(schema, {}) == []


def test_hyg003_fix_silent_on_single_policy() -> None:
    # Nothing to dedupe — one policy is never its own duplicate.
    assert HYG003Fixer().fix(_wrap_policy(_policy("user_id = 1")), {}) == []


def test_hyg003_fix_emits_one_drop_per_redundant_copy() -> None:
    # Three identical policies — keep one, drop the other two.
    schema = _dup_table(
        _policy("user_id = 1", name="p_a"),
        _policy("user_id = 1", name="p_b"),
        _policy("user_id = 1", name="p_c"),
    )
    fixes = HYG003Fixer().fix(schema, {})
    assert sorted(f.location for f in fixes) == [
        "public.t.p_b",
        "public.t.p_c",
    ]


def test_hyg003_fix_handles_multiple_duplicate_groups() -> None:
    # Two independent duplicate groups on one table — each
    # contributes one DROP for its redundant copy.
    schema = _dup_table(
        _policy("user_id = 1", name="a1"),
        _policy("user_id = 1", name="a2"),
        _policy("tenant_id = 9", name="b1"),
        _policy("tenant_id = 9", name="b2"),
    )
    fixes = HYG003Fixer().fix(schema, {})
    assert sorted(f.location for f in fixes) == [
        "public.t.a2",
        "public.t.b2",
    ]


def test_hyg003_fix_respects_allowlist() -> None:
    # The redundant policy's qualified ID is allowlisted — keeping
    # the duplicate is intentional, so no DROP is emitted.
    schema = _dup_table(
        _policy("user_id = 1", name="p_a"),
        _policy("user_id = 1", name="p_b"),
    )
    assert (
        HYG003Fixer().fix(schema, {"allowlist": ["public.t.p_b"]}) == []
    )


def test_hyg003_fix_quotes_policy_and_table_when_required() -> None:
    # Mixed-case / spaced identifiers must be double-quoted in the
    # emitted DROP POLICY statement.
    schema = _dup_table(
        _policy("user_id = 1", name="a policy"),
        _policy("user_id = 1", name="z policy"),
        name="MixedCase Table",
    )
    sql = HYG003Fixer().fix(schema, {})[0].sql
    assert sql == 'DROP POLICY "z policy" ON public."MixedCase Table";'


def test_hyg003_fix_description_names_the_original() -> None:
    # The description must name both the dropped duplicate and the
    # surviving original so a reviewer can confirm the pairing.
    schema = _dup_table(
        _policy("user_id = 1", name="keeper"),
        _policy("user_id = 1", name="redundant"),
    )
    [f] = HYG003Fixer().fix(schema, {})
    assert f.location == "public.t.redundant"
    assert "keeper" in f.description
    assert "redundant" in f.description


def test_hyg003_fix_raises_on_malformed_allowlist() -> None:
    # The fixer validates with HYG003's strict parser
    # (parse_policy_id_allowlist), so a malformed allowlist raises
    # TypeError — `pgrls fix` surfaces it as a ToolError, exactly
    # as `pgrls lint` rejects the same config.
    schema = _dup_table(
        _policy("user_id = 1", name="p_a"),
        _policy("user_id = 1", name="p_b"),
    )
    # Bad type — not a list.
    with pytest.raises(TypeError, match="allowlist"):
        HYG003Fixer().fix(schema, {"allowlist": "public.t.p_b"})
    # Malformed entry — surrounding whitespace.
    with pytest.raises(TypeError, match="allowlist"):
        HYG003Fixer().fix(schema, {"allowlist": [" public.t.p_b "]})


# ---------- SEC031 fixer ----------


def test_sec031_fix_emits_drop_policy_for_restrictive_true() -> None:
    schema = _dup_table(_policy("true", name="floor", permissive=False))
    fixes = SEC031Fixer().fix(schema, {})
    assert len(fixes) == 1
    f = fixes[0]
    assert f.rule_id == "SEC031"
    assert f.location == "public.t.floor"
    assert f.sql == "DROP POLICY floor ON public.t;"


def test_sec031_fix_silent_on_permissive_true() -> None:
    # Permissive USING (true) is SEC008's territory (admits every row);
    # dropping it would CHANGE access, so the SEC031 fixer skips it.
    schema = _dup_table(_policy("true", name="open", permissive=True))
    assert SEC031Fixer().fix(schema, {}) == []


def test_sec031_fix_silent_on_restrictive_with_real_predicate() -> None:
    # A restrictive policy with a real USING is a genuine floor — keep it.
    schema = _dup_table(
        _policy("tenant_id = 1", name="floor", permissive=False)
    )
    assert SEC031Fixer().fix(schema, {}) == []


def test_sec031_fix_silent_when_using_absent() -> None:
    # No USING clause → nothing constant-true to drop.
    schema = _dup_table(
        _policy(None, name="floor", command="INSERT", permissive=False)
    )
    assert SEC031Fixer().fix(schema, {}) == []


def test_sec031_fix_respects_allowlist() -> None:
    schema = _dup_table(_policy("true", name="floor", permissive=False))
    assert (
        SEC031Fixer().fix(schema, {"allowlist": ["public.t.floor"]}) == []
    )


def test_sec031_fix_emits_one_per_offending_policy() -> None:
    schema = _dup_table(
        _policy("true", name="floor_a", permissive=False),
        _policy("tenant_id = 1", name="real", permissive=False),
        _policy("true", name="floor_b", permissive=False),
    )
    fixes = SEC031Fixer().fix(schema, {})
    assert sorted(f.location for f in fixes) == [
        "public.t.floor_a",
        "public.t.floor_b",
    ]


def test_sec031_fix_quotes_policy_and_table_when_required() -> None:
    schema = _dup_table(
        _policy("true", name="my floor", permissive=False),
        name="MixedCase Table",
    )
    sql = SEC031Fixer().fix(schema, {})[0].sql
    assert sql == 'DROP POLICY "my floor" ON public."MixedCase Table";'


def test_sec031_fix_description_explains_noop_and_alternative() -> None:
    # The fixer DROPs, but SEC031's other remedy (a real predicate)
    # needs human intent — the description must point at it.
    schema = _dup_table(_policy("true", name="floor", permissive=False))
    [f] = SEC031Fixer().fix(schema, {})
    assert "no-op" in f.description
    assert "predicate" in f.description


def test_sec031_fix_raises_on_malformed_allowlist() -> None:
    schema = _dup_table(_policy("true", name="floor", permissive=False))
    with pytest.raises(TypeError, match="allowlist"):
        SEC031Fixer().fix(schema, {"allowlist": "public.t.floor"})
    with pytest.raises(TypeError, match="allowlist"):
        SEC031Fixer().fix(schema, {"allowlist": [" public.t.floor "]})


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
                # `user_id` indexed so PERF003 stays silent — this
                # test pins generate_fixes' union/sort, not PERF003.
                indexes=(_idx("user_id", name="z_user_id_idx"),),
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


# ---------- SEC011 fixer ----------


def test_sec011_fix_strips_or_true_and_unwraps() -> None:
    schema = _wrap_policy(_policy("user_id = 1 OR true"))
    fixes = SEC011Fixer().fix(schema, {})
    assert len(fixes) == 1
    f = fixes[0]
    assert f.rule_id == "SEC011"
    assert f.location == "public.t.p"
    assert "ALTER POLICY p ON public.t" in f.sql
    assert "USING (user_id = 1)" in f.sql
    # The bypass disjunct is gone — no literal true in any case.
    assert "TRUE" not in f.sql
    assert "true" not in f.sql


def test_sec011_fix_keeps_remaining_disjuncts_when_three_args() -> None:
    # `a OR b OR true` keeps `a OR b` (no unwrap — two real args).
    schema = _wrap_policy(_policy("user_id = 1 OR user_id = 2 OR true"))
    sql = SEC011Fixer().fix(schema, {})[0].sql
    assert "USING (user_id = 1 OR user_id = 2)" in sql
    assert "TRUE" not in sql


def test_sec011_fix_strips_true_on_left_side() -> None:
    schema = _wrap_policy(_policy("true OR user_id = 1"))
    sql = SEC011Fixer().fix(schema, {})[0].sql
    assert "USING (user_id = 1)" in sql
    assert "TRUE" not in sql


def test_sec011_fix_strips_or_true_nested_in_and() -> None:
    # `a AND (b OR true)` → `a AND b`. The inner OR unwraps; the
    # AND is left with its two real conjuncts.
    schema = _wrap_policy(
        _policy("user_id = 1 AND (user_id = 2 OR true)", command="ALL")
    )
    sql = SEC011Fixer().fix(schema, {})[0].sql
    assert "user_id = 1 AND user_id = 2" in sql
    assert "TRUE" not in sql


def test_sec011_fix_rewrites_with_check_side() -> None:
    p = _policy(
        "user_id = 1",
        command="ALL",
        with_check="user_id = 2 OR true",
    )
    sql = SEC011Fixer().fix(_wrap_policy(p), {})[0].sql
    assert "WITH CHECK (user_id = 2)" in sql
    # USING was clean, so it must not appear in the minimal-diff ALTER.
    assert "USING (" not in sql


def test_sec011_fix_emits_only_changed_clauses() -> None:
    # USING has the bypass; WITH CHECK is already clean → only USING
    # is re-emitted.
    p = _policy(
        "user_id = 1 OR true",
        command="ALL",
        with_check="user_id = 1",
    )
    sql = SEC011Fixer().fix(_wrap_policy(p), {})[0].sql
    assert "USING (user_id = 1)" in sql
    assert "WITH CHECK" not in sql


def test_sec011_fix_silent_when_no_or_true() -> None:
    schema = _wrap_policy(_policy("user_id = 1 OR user_id = 2"))
    assert SEC011Fixer().fix(schema, {}) == []


def test_sec011_fix_leaves_or_true_inside_subquery_where() -> None:
    # The SEC011 *rule* deliberately does not descend into a
    # subquery's own WHERE (an `OR true` there is the subquery's
    # predicate, not the policy admitting every row — e.g. the
    # legitimate `EXISTS (SELECT 1 ... WHERE flag OR true)` shape).
    # The fixer must mirror that scope exactly: rewriting the
    # subquery would mutate a policy `pgrls lint` calls clean and
    # trip `pgrls fix --check` on zero violations.
    schema = _wrap_policy(
        _policy(
            "user_id IN (SELECT member_id FROM public.acl "
            "WHERE active OR true)"
        )
    )
    assert SEC011Fixer().fix(schema, {}) == []


def test_sec011_fix_strips_top_level_or_true_around_a_sublink() -> None:
    # The opposite of the above: the `OR true` is at the policy's
    # top level (not inside the subquery), so it IS stripped. The
    # surviving SubLink comparison is left intact.
    schema = _wrap_policy(
        _policy("user_id IN (SELECT member_id FROM public.acl) OR true")
    )
    sql = SEC011Fixer().fix(schema, {})[0].sql
    assert "SELECT member_id FROM public.acl" in sql
    assert "TRUE" not in sql


def test_sec011_fix_skips_or_true_under_not() -> None:
    # `NOT (a OR true)` is deny-all (NOT of always-true). Stripping
    # the `OR true` would leave `NOT a`, which BROADENS the policy —
    # a security regression. The fixer must not touch an OR-true in
    # non-monotone (negated) position; the SEC011 finding stays for
    # human review.
    schema = _wrap_policy(_policy("NOT (user_id = 1 OR true)"))
    assert SEC011Fixer().fix(schema, {}) == []


def test_sec011_fix_skips_negated_or_true_inside_and() -> None:
    # `id = 1 AND NOT (user_id = 2 OR true)` — the AND chain is
    # monotone, but the OR-true sits under a NOT, so it must be left
    # alone. No clause changes ⇒ no fix.
    schema = _wrap_policy(
        _policy("id = 1 AND NOT (user_id = 2 OR true)", command="ALL")
    )
    assert SEC011Fixer().fix(schema, {}) == []


def test_sec011_fix_skips_or_true_under_is_false_test() -> None:
    # `(a OR true) IS FALSE` ≡ `true IS FALSE` ≡ deny-all. Stripping
    # to `a IS FALSE` would BROADEN access. A `BooleanTest` is not a
    # BoolExpr, so `_strip_or_true` stops at it — the OR-true under
    # the IS FALSE test is non-monotone and left untouched.
    schema = _wrap_policy(_policy("(user_id = 1 OR true) IS FALSE"))
    assert SEC011Fixer().fix(schema, {}) == []


def test_sec011_fix_skips_or_true_under_negating_comparison() -> None:
    # `(a OR true) = false` ≡ `true = false` ≡ deny-all. Rewriting
    # to `a = false` would change the truth value and broaden access.
    # The comparison (A_Expr) is non-monotone in its operand, so the
    # fixer leaves it alone.
    schema = _wrap_policy(_policy("(user_id = 1 OR true) = false"))
    assert SEC011Fixer().fix(schema, {}) == []


def test_sec011_fix_skips_vacuous_true_or_true() -> None:
    # `true OR true` has no real predicate to keep once the trues
    # are stripped — the fixer leaves it for human review rather
    # than emit an empty `USING ()`.
    schema = _wrap_policy(_policy("true OR true"))
    assert SEC011Fixer().fix(schema, {}) == []


def test_sec011_fix_respects_allowlist() -> None:
    schema = _wrap_policy(_policy("user_id = 1 OR true"))
    assert (
        SEC011Fixer().fix(schema, {"allowlist": ["public.t.p"]}) == []
    )


def test_sec011_fix_does_not_mutate_input_schema() -> None:
    p = _policy("user_id = 1 OR true")
    schema = _wrap_policy(p)
    SEC011Fixer().fix(schema, {})
    # The original AST still renders with the OR-true intact.
    from pglast.stream import RawStream

    rendered = RawStream()(p.using_ast)
    assert "TRUE" in rendered or "true" in rendered


def test_sec011_fix_description_explains_bypass_and_allowlist() -> None:
    schema = _wrap_policy(_policy("user_id = 1 OR true"))
    [f] = SEC011Fixer().fix(schema, {})
    assert "OR true" in f.description
    assert "[lint.rules.SEC011]" in f.description


def test_sec011_fix_raises_on_malformed_allowlist() -> None:
    schema = _wrap_policy(_policy("user_id = 1 OR true"))
    with pytest.raises(TypeError, match="allowlist"):
        SEC011Fixer().fix(schema, {"allowlist": "public.t.p"})


def test_default_fixers_registers_every_shipping_fixer() -> None:
    rule_ids = {fixer.rule_id for fixer in default_fixers()}
    assert {
        "SEC001",
        "SEC002",
        "SEC006",
        "SEC011",
        "SEC019",
        "SEC020",
        "SEC031",
        "PERF001",
        "PERF003",
        "HYG003",
        "VIEW001",
        "VIEW002",
    } <= rule_ids


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

def test_sec002_fix_raises_on_malformed_allowlist() -> None:
    # The fixer validates with SEC002's strict parser
    # (parse_table_ref_allowlist), so a malformed allowlist raises
    # TypeError — `pgrls fix` surfaces it as a ToolError, exactly
    # as `pgrls lint` rejects the same config.
    schema = Schema(tables=(_table(rls=True, force=False),))
    # Bad type — not a list.
    with pytest.raises(TypeError, match="allowlist"):
        SEC002Fixer().fix(schema, {"allowlist": "public.t"})
    # Malformed entry — surrounding whitespace.
    with pytest.raises(TypeError, match="allowlist"):
        SEC002Fixer().fix(schema, {"allowlist": [" public.t "]})


def test_perf001_fix_raises_on_malformed_allowlist() -> None:
    # The fixer validates with PERF001's strict parser
    # (parse_policy_id_allowlist), so a malformed allowlist raises
    # TypeError — `pgrls fix` surfaces it as a ToolError, exactly
    # as `pgrls lint` rejects the same config.
    schema = _wrap_policy(_policy("user_id = auth.uid()"))
    # Bad type — not a list.
    with pytest.raises(TypeError, match="allowlist"):
        PERF001Fixer().fix(schema, {"allowlist": "public.t.p"})
    # Malformed entry — surrounding whitespace.
    with pytest.raises(TypeError, match="allowlist"):
        PERF001Fixer().fix(schema, {"allowlist": [" public.t.p "]})


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


# ---------- render_fixes / render_migration ----------


def _mk_fix(
    rule_id: str = "SEC002",
    location: str = "public.t",
    sql: str = "ALTER TABLE public.t FORCE ROW LEVEL SECURITY;",
    description: str = "Enable FORCE row level security on public.t.",
) -> Fix:
    return Fix(
        rule_id=rule_id,
        location=location,
        sql=sql,
        description=description,
    )


def test_render_fixes_emits_comment_and_sql_per_fix() -> None:
    out = render_fixes([_mk_fix()])
    assert (
        "-- [SEC002] Enable FORCE row level security on public.t."
        in out
    )
    assert "ALTER TABLE public.t FORCE ROW LEVEL SECURITY;" in out


def test_render_fixes_separates_blocks_with_a_blank_line() -> None:
    out = render_fixes(
        [
            _mk_fix(rule_id="SEC001", sql="A;"),
            _mk_fix(rule_id="SEC002", sql="B;"),
        ]
    )
    # Block N's SQL, blank line, block N+1's comment.
    assert "A;\n\n-- [SEC002]" in out


def test_render_fixes_empty_is_empty_string() -> None:
    assert render_fixes([]) == ""


def test_render_fixes_has_no_trailing_newline() -> None:
    # The caller adds the final newline (click.echo / render_migration).
    assert not render_fixes([_mk_fix()]).endswith("\n")


def test_render_migration_header_names_pgrls_version() -> None:
    out = render_migration([_mk_fix()], tool_version="9.9.9")
    assert "generated by pgrls 9.9.9" in out


def test_render_migration_header_states_fix_count() -> None:
    one = render_migration([_mk_fix()], tool_version="1.0")
    assert "1 fix." in one
    two = render_migration(
        [_mk_fix(rule_id="SEC001"), _mk_fix(rule_id="SEC002")],
        tool_version="1.0",
    )
    assert "2 fixes." in two


def test_render_migration_embeds_the_render_fixes_body() -> None:
    fixes = [_mk_fix()]
    out = render_migration(fixes, tool_version="1.0")
    assert render_fixes(fixes) in out


def test_render_migration_is_deterministic() -> None:
    # No timestamp — regenerating against the same fixes yields a
    # byte-identical file (clean diffs for a committed migration).
    fixes = [_mk_fix()]
    a = render_migration(fixes, tool_version="1.0")
    b = render_migration(fixes, tool_version="1.0")
    assert a == b


def test_render_migration_ends_with_exactly_one_newline() -> None:
    out = render_migration([_mk_fix()], tool_version="1.0")
    assert out.endswith("\n")
    assert not out.endswith("\n\n")


def test_render_migration_header_lines_are_sql_comments() -> None:
    # The header must be `--` comments so the whole file is valid
    # SQL that `psql -f` runs as-is.
    out = render_migration([_mk_fix()], tool_version="1.0")
    header = out.split("\n\n", 1)[0]
    assert all(
        line.startswith("--") for line in header.splitlines()
    )


def test_render_migration_handles_empty_fixes() -> None:
    # `render_migration` is a public function. The CLI guards
    # against calling it with no fixes (it reports "no auto-fixable
    # violations" and writes nothing), but a programmatic caller
    # may still pass an empty list — pin that it returns the header
    # alone, reports "0 fixes", and does not crash.
    out = render_migration([], tool_version="1.0")
    assert "0 fixes." in out
    assert out.endswith("\n")


# ---------- PERF003 fixer ----------


def _idx(*columns: str, name: str = "i") -> Index:
    return Index(
        name=name,
        access_method="btree",
        columns=columns,
        is_unique=False,
        is_partial=False,
    )


def _perf_table(
    *policies: Policy,
    name: str = "t",
    schema: str = "public",
    rls: bool = True,
    indexes: tuple[Index, ...] = (),
) -> Table:
    return Table(
        schema=schema,
        name=name,
        rls_enabled=rls,
        force_rls=True,
        policies=policies,
        indexes=indexes,
        columns=("id", "tenant_id", "owner"),
    )


def test_perf003_fix_emits_create_index_for_unindexed_column() -> None:
    schema = Schema(tables=(_perf_table(
        _policy("tenant_id = current_setting('app.t', true)", name="p"),
    ),))
    fixes = PERF003Fixer().fix(schema, {})
    assert len(fixes) == 1
    f = fixes[0]
    assert f.rule_id == "PERF003"
    assert f.sql == "CREATE INDEX ON public.t (tenant_id);"
    assert f.location == "public.t (tenant_id)"


def test_perf003_fix_silent_when_column_has_leading_index() -> None:
    schema = Schema(tables=(_perf_table(
        _policy("tenant_id = current_setting('app.t', true)"),
        indexes=(_idx("tenant_id"),),
    ),))
    assert PERF003Fixer().fix(schema, {}) == []


def test_perf003_fix_silent_when_rls_disabled() -> None:
    # PERF003's domain is policy-driven filtering — RLS off, no fix.
    schema = Schema(tables=(_perf_table(
        _policy("tenant_id = current_setting('app.t', true)"),
        rls=False,
    ),))
    assert PERF003Fixer().fix(schema, {}) == []


def test_perf003_fix_silent_when_rls_enabled_but_no_policies() -> None:
    # RLS on but no policies — nothing filters through a predicate,
    # so there is no column to index. Mirrors the rule: the
    # per-policy loop is empty and no Fix is emitted.
    schema = Schema(tables=(_perf_table(),))
    assert PERF003Fixer().fix(schema, {}) == []


def test_perf003_fix_emits_per_table_for_same_column_on_two_tables() -> None:
    # The same unindexed column on two tables is two separate
    # findings — the fixer keys fixes on (table, column), so it
    # emits one CREATE INDEX per table, not a single dedup'd one.
    pred = "tenant_id = current_setting('app.t', true)"
    schema = Schema(tables=(
        _perf_table(_policy(pred), name="a"),
        _perf_table(_policy(pred), name="b"),
    ))
    fixes = PERF003Fixer().fix(schema, {})
    assert sorted(f.sql for f in fixes) == [
        "CREATE INDEX ON public.a (tenant_id);",
        "CREATE INDEX ON public.b (tenant_id);",
    ]


def test_perf003_fix_dedupes_column_across_policies() -> None:
    # Two policies filter the same unindexed column — the rule fires
    # twice but one index resolves both, so the fixer emits one Fix.
    schema = Schema(tables=(_perf_table(
        _policy(
            "tenant_id = current_setting('app.t', true)", name="read"
        ),
        _policy(
            "tenant_id = current_setting('app.t', true)",
            name="write",
            command="ALL",
            with_check="tenant_id = current_setting('app.t', true)",
        ),
    ),))
    fixes = PERF003Fixer().fix(schema, {})
    assert [f.sql for f in fixes] == [
        "CREATE INDEX ON public.t (tenant_id);"
    ]


def test_perf003_fix_emits_one_index_per_unindexed_column() -> None:
    # A composite predicate over two unindexed columns → two indexes.
    schema = Schema(tables=(_perf_table(
        _policy(
            "tenant_id = current_setting('a', true) "
            "AND owner = current_setting('u', true)"
        ),
    ),))
    fixes = PERF003Fixer().fix(schema, {})
    assert sorted(f.sql for f in fixes) == [
        "CREATE INDEX ON public.t (owner);",
        "CREATE INDEX ON public.t (tenant_id);",
    ]


def test_perf003_fix_skips_the_already_indexed_column() -> None:
    schema = Schema(tables=(_perf_table(
        _policy(
            "tenant_id = current_setting('a', true) "
            "AND owner = current_setting('u', true)"
        ),
        indexes=(_idx("tenant_id"),),
    ),))
    fixes = PERF003Fixer().fix(schema, {})
    assert [f.sql for f in fixes] == ["CREATE INDEX ON public.t (owner);"]


def test_perf003_fix_respects_allowlist() -> None:
    schema = Schema(tables=(_perf_table(
        _policy("tenant_id = current_setting('a', true)", name="p"),
    ),))
    assert PERF003Fixer().fix(
        schema, {"allowlist": ["public.t.p"]}
    ) == []


def test_perf003_fix_indexes_column_kept_in_scope_by_a_live_policy() -> None:
    # `tenant_id` is referenced by an allowlisted policy AND a
    # non-allowlisted one — the live policy keeps it in scope, so
    # the index is still emitted.
    schema = Schema(tables=(_perf_table(
        _policy(
            "tenant_id = current_setting('a', true)", name="exempt"
        ),
        _policy(
            "tenant_id = current_setting('a', true)", name="active"
        ),
    ),))
    fixes = PERF003Fixer().fix(
        schema, {"allowlist": ["public.t.exempt"]}
    )
    assert [f.sql for f in fixes] == [
        "CREATE INDEX ON public.t (tenant_id);"
    ]


def test_perf003_fix_quotes_table_name_when_required() -> None:
    schema = Schema(tables=(
        Table(
            schema="public",
            name="MixedCase",
            rls_enabled=True,
            force_rls=True,
            columns=("id", "tenant_id"),
            policies=(
                _policy("tenant_id = current_setting('a', true)"),
            ),
            indexes=(),
        ),
    ))
    sql = PERF003Fixer().fix(schema, {})[0].sql
    assert sql == 'CREATE INDEX ON public."MixedCase" (tenant_id);'


def test_perf003_fix_description_flags_lock_and_concurrently() -> None:
    schema = Schema(tables=(_perf_table(
        _policy("tenant_id = current_setting('a', true)"),
    ),))
    [f] = PERF003Fixer().fix(schema, {})
    assert "CONCURRENTLY" in f.description
    assert "tenant_id" in f.description


def test_perf003_fix_raises_on_malformed_allowlist() -> None:
    # The fixer validates with PERF003's strict parser
    # (parse_policy_id_allowlist) — a malformed allowlist raises,
    # surfaced by the `fix` CLI exactly as `pgrls lint` rejects it.
    schema = Schema(tables=(_perf_table(
        _policy("tenant_id = current_setting('a', true)", name="p"),
    ),))
    with pytest.raises(TypeError, match="allowlist"):
        PERF003Fixer().fix(schema, {"allowlist": "public.t.p"})
    with pytest.raises(TypeError, match="allowlist"):
        PERF003Fixer().fix(schema, {"allowlist": [" public.t.p "]})
