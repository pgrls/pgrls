"""Tests for `pgrls verify` — the Z3 anonymous-isolation proof."""
from __future__ import annotations

import json
from pathlib import Path

import psycopg
import pytest
from click.testing import CliRunner
from pglast import parse_sql

from pgrls.cli import main
from pgrls.diff._z3_compare import (
    Z3_AVAILABLE,
    _Context,
    _DEFAULT_AUTH_FUNCTIONS,
    _anon_3vl,
    _distinct_tenant_pairs,
    _lift_to_tv,
)
from pgrls.introspect import introspect
from pgrls.model import (
    OwnerReachableMember,
    Policy,
    RoleMembership,
    Schema,
    SecdefFunction,
    Table,
    View,
)
from pgrls.verify import (
    PolicyProof,
    TableVerdict,
    Verification,
    _witness_phrase,
    build_verification,
    diff_verifications,
    render_delta_json,
    render_delta_text,
    render_json,
    render_sarif,
    render_text,
)

_SARIF_SCHEMA = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/"
    "sarif-schema-2.1.0.json"
)

requires_z3 = pytest.mark.skipif(not Z3_AVAILABLE, reason="z3-solver not installed")


def _docker_available() -> bool:
    try:
        import docker  # noqa: PLC0415

        docker.from_env().ping()
        return True
    except Exception:
        return False


requires_docker = pytest.mark.skipif(
    not _docker_available(), reason="Docker not available for live introspection"
)

# Postgres validates a policy's USING expression at CREATE POLICY, so the
# auth.* helpers must exist before the policy references them. Minimal stub
# (mirrors the Supabase prelude the ephemeral engine installs).
_AUTH_STUB = (
    "CREATE SCHEMA IF NOT EXISTS auth;"
    "CREATE OR REPLACE FUNCTION auth.uid() RETURNS uuid LANGUAGE sql STABLE AS "
    "$$ SELECT NULLIF(current_setting('request.jwt.claim.sub', true), '')::uuid $$;"
)


def _using_ast(sql: str):
    return parse_sql(f"SELECT 1 WHERE {sql}")[0].stmt.whereClause


def _policy(
    using: str | None,
    *,
    name: str = "p",
    permissive: bool = True,
    command: str = "ALL",
    with_check: str | None = None,
    roles: tuple[str, ...] = ("anon",),
) -> Policy:
    return Policy(
        name=name,
        command=command,
        permissive=permissive,
        roles=roles,
        using_sql=using,
        with_check_sql=with_check,
        using_ast=_using_ast(using) if using is not None else None,
        with_check_ast=_using_ast(with_check) if with_check is not None else None,
    )


def _table(name: str, *, rls: bool = True, policies: tuple[Policy, ...] = ()) -> Table:
    return Table(
        schema="public",
        name=name,
        rls_enabled=rls,
        force_rls=True,
        policies=policies,
    )


def _verdict(v: Verification, table: str) -> str:
    return next(t.verdict for t in v.tables if t.qualified_name == table)


# --- verdict logic (Z3) ----------------------------------------------------


@requires_z3
def test_scoped_policy_is_proven_isolated() -> None:
    schema = Schema(tables=(_table("t", policies=(_policy("tenant_id = auth.uid()"),)),))
    assert _verdict(build_verification(schema), "public.t") == "isolated"


@requires_z3
def test_inverted_auth_is_proven_leak() -> None:
    # The signature Supabase bug — SEC004 shape — now PROVEN as a leak.
    schema = Schema(
        tables=(
            _table("t", policies=(_policy("auth.uid() IS NULL OR tenant_id = auth.uid()"),)),
        )
    )
    v = build_verification(schema)
    assert _verdict(v, "public.t") == "leak"
    assert v.has_leak


@requires_z3
def test_never_null_current_setting_is_null_disjunct_is_isolated() -> None:
    # Regression (review MED-1): `current_setting('app.x') IS NULL` is a DEAD
    # disjunct under anon — the one-arg form RAISES on an unset GUC and is
    # otherwise non-NULL, so the policy is genuinely isolated. The anon
    # satisfiability path must not manufacture a leak from a free null-flag
    # (SEC038 already stays silent on this; verify must agree).
    schema = Schema(
        tables=(
            _table(
                "t",
                policies=(
                    _policy(
                        "current_setting('app.x') IS NULL "
                        "OR tenant_id = auth.uid()"
                    ),
                ),
            ),
        )
    )
    assert _verdict(build_verification(schema), "public.t") == "isolated"


@requires_z3
def test_nullable_two_arg_current_setting_is_null_stays_leak() -> None:
    # Precision control for MED-1: the two-arg current_setting(name, true) form
    # IS NULLable under anon (returns NULL on an unset GUC), so `… IS NULL OR …`
    # is a real anon leak and must stay reported — the never-NULL pin must not
    # over-reach into the nullable form (that would be a false PROVEN).
    schema = Schema(
        tables=(
            _table(
                "t",
                policies=(
                    _policy(
                        "current_setting('app.x', true) IS NULL "
                        "OR tenant_id = auth.uid()"
                    ),
                ),
            ),
        )
    )
    assert _verdict(build_verification(schema), "public.t") == "leak"


# --- never-NULL current_setting as a tenant scope (MF5) --------------------
#
# The canonical multi-tenant policy `col = current_setting('app.tenant')` was
# reported as a conditional LEAK (exit 1) in the DEFAULT anon mode. The
# never-NULL routing correctly pinned `is_null=False` but left the value a
# FREE opaque, so the anon satisfiability query existentially picked a GUC
# value equal to a free row. An anonymous session has not run `SET`, so a
# custom (dotted) GUC is unset and reading it RAISES — no rows come back.


@requires_z3
@pytest.mark.parametrize(
    "pred",
    [
        # one-arg
        "tenant_id = current_setting('app.tenant')",
        # two-arg missing_ok=false — also raises on an unset GUC
        "tenant_id = current_setting('app.tenant', false)",
        # the PERF001-recommended (SELECT …) wrap
        "tenant_id = (SELECT current_setting('app.tenant'))",
        # cast — the marker must survive _anon_typecast
        "tenant_id = current_setting('app.tenant')::uuid",
        # the shape the CATALOG actually stores: pg_get_expr renders the
        # literal as 'app.tenant'::text, so the name arg is a TypeCast, not
        # a bare A_Const. A fix that only matched the bare literal is a
        # silent no-op on every real policy.
        "tenant_id = current_setting('app.tenant'::text)",
    ],
)
def test_never_null_current_setting_tenant_scope_is_isolated(pred: str) -> None:
    schema = Schema(tables=(_table("t", policies=(_policy(pred),)),))
    assert _verdict(build_verification(schema), "public.t") == "isolated"


@requires_z3
@pytest.mark.parametrize(
    "pred",
    [
        # A BUILT-IN GUC is always set and USERSET — the caller genuinely
        # controls it, so this stays a real leak. Non-dotted is the gate.
        "tenant_id = current_setting('search_path')",
        # A computed name cannot be classified — stay conservative.
        "tenant_id = current_setting(guc_name)",
        # Short-circuit control: Postgres evaluates `true OR …` without ever
        # reaching the raising call, so the open disjunct is a REAL leak.
        # Kleene U on the erroring side must not swallow it.
        "true OR tenant_id = current_setting('app.tenant')",
        # NOT must not turn "the statement errored" into a visible row.
        "NOT (tenant_id = current_setting('app.tenant')) OR true",
    ],
)
def test_never_null_current_setting_precision_controls_stay_leak(pred: str) -> None:
    schema = Schema(tables=(_table("t", policies=(_policy(pred),)),))
    assert _verdict(build_verification(schema), "public.t") == "leak"


@requires_z3
def test_never_null_current_setting_under_not_is_isolated() -> None:
    # Why the erroring read is modelled as Kleene U and not FALSE: `NOT U` is
    # still U, so a NOT cannot flip the raising branch back into a visible row.
    # Verified on live PG16 — an anon SELECT under
    # `USING (NOT (tenant_id = current_setting('app.tenant')))` with the GUC
    # unset raises `unrecognized configuration parameter` and returns no rows,
    # so "no anonymous read" is the accurate verdict. Modelling the comparison
    # as FALSE would report a leak here that cannot be exhibited.
    schema = Schema(
        tables=(
            _table(
                "t",
                policies=(
                    _policy("NOT (tenant_id = current_setting('app.tenant'))"),
                ),
            ),
        )
    )
    assert _verdict(build_verification(schema), "public.t") == "isolated"


@requires_z3
def test_never_null_current_setting_scope_is_cross_tenant_isolated() -> None:
    # Same root cause on the cross-tenant path: the never-NULL call was not
    # minted as the session identity symbol, so no tenant pair was recorded
    # and the canonical policy degraded to UNVERIFIED purely because it spelled
    # its identity read without `missing_ok`.
    schema = Schema(
        tables=(
            _table(
                "t",
                policies=(_policy("tenant_id = current_setting('app.tenant')"),),
            ),
        )
    )
    assert _verdict(_xt(schema), "public.t") == "isolated"


@requires_z3
def test_using_true_is_leak_all_rows() -> None:
    schema = Schema(tables=(_table("t", policies=(_policy("true"),)),))
    v = build_verification(schema)
    [t] = v.tables
    [p] = t.proofs
    assert t.verdict == "leak"
    assert p.witness == {}  # unconditional → "all rows"


@requires_z3
def test_characterizing_counterexample_row() -> None:
    # A row-specific leak yields a concrete characterizing assignment.
    schema = Schema(
        tables=(
            _table("t", policies=(_policy("is_public OR tenant_id = (select auth.uid())"),)),
        )
    )
    v = build_verification(schema)
    [t] = v.tables
    leak = next(p for p in t.proofs if p.verdict == "leak")
    assert leak.witness == {"is_public": True}


@requires_z3
def test_conditional_leak_has_none_witness() -> None:
    # A conditional leak the prover can't pin to a single real-column row
    # (the discriminator is a synthetic null-flag) → witness None, NOT {} —
    # so callers don't claim "every row".
    schema = Schema(
        tables=(
            _table(
                "t",
                policies=(_policy("tenant_id = auth.uid() OR public_level IS NOT NULL"),),
            ),
        )
    )
    v = build_verification(schema)
    [t] = v.tables
    [p] = t.proofs
    assert t.verdict == "leak"
    assert p.witness is None  # conditional, uncharacterized (not {} = all-rows)
    assert "conditional" in render_text(v)


@requires_z3
def test_undecidable_predicate_is_unverified() -> None:
    schema = Schema(
        tables=(
            _table(
                "t",
                policies=(
                    _policy("tenant_id = ANY(string_to_array(current_setting('x'), ','))"),
                ),
            ),
        )
    )
    assert _verdict(build_verification(schema), "public.t") == "unverified"


@requires_z3
def test_any_array_membership_now_proves_isolated() -> None:
    # `status = ANY(ARRAY[...])` used to abstain (UNVERIFIED); now modeled, so a
    # genuinely anon-safe policy that happens to use a membership allowlist is
    # PROVEN isolated. Anon: auth.uid() is NULL → `tenant_id = auth.uid()` is
    # Kleene-U, and `U AND <membership>` can never be TRUE → no row leaks.
    schema = Schema(
        tables=(
            _table(
                "t",
                policies=(
                    _policy(
                        "tenant_id = auth.uid() "
                        "AND status = ANY(ARRAY['active','pending'])"
                    ),
                ),
            ),
        )
    )
    assert _verdict(build_verification(schema), "public.t") == "isolated"


@requires_z3
def test_any_array_open_allowlist_is_anon_leak() -> None:
    # A membership predicate with no identity gate admits matching rows to
    # everyone, anon included → a real leak the verifier now proves (was
    # UNVERIFIED).
    schema = Schema(
        tables=(
            _table("t", policies=(_policy("role = ANY(ARRAY['admin','editor'])"),)),
        )
    )
    assert _verdict(build_verification(schema), "public.t") == "leak"


@requires_z3
def test_any_array_cast_elements_match_uncast() -> None:
    # The introspected form casts every element (`'admin'::text`); it must reach
    # the same verdict as the bare-literal form (elements route through the
    # existing TypeCast resolver, not a raw literal extractor).
    cast = _table(
        "c",
        policies=(_policy("role = ANY(ARRAY['admin'::text,'editor'::text])"),),
    )
    bare = _table("b", policies=(_policy("role = ANY(ARRAY['admin','editor'])"),))
    v = build_verification(Schema(tables=(cast, bare)))
    assert _verdict(v, "public.c") == _verdict(v, "public.b") == "leak"


@requires_z3
def test_not_in_normalization_stays_unverified() -> None:
    # `<> ALL(ARRAY[...])` is the NOT-IN normalization (AEXPR_OP_ALL, op `<>`) —
    # the COMPLEMENT of membership. The encoder must NOT mistake it for `= ANY`;
    # it abstains, so the verdict stays UNVERIFIED (soundness over recall).
    schema = Schema(
        tables=(
            _table(
                "t",
                policies=(
                    _policy("tenant_id = auth.uid() OR role <> ALL(ARRAY['a','b'])"),
                ),
            ),
        )
    )
    assert _verdict(build_verification(schema), "public.t") == "unverified"
    assert _verdict(_xt(schema), "public.t") == "unverified"


@requires_z3
def test_any_array_over_a_column_stays_unverified() -> None:
    # `= ANY(<array column>)` needs array-containment reasoning we don't model;
    # the encoder abstains rather than guess, so the literal-array gate is real.
    schema = Schema(
        tables=(
            _table("t", policies=(_policy("auth.uid() = ANY(member_ids)"),)),
        )
    )
    assert _verdict(build_verification(schema), "public.t") == "unverified"


@requires_z3
def test_restrictive_floor_that_does_not_block_the_leak_is_proven_leak() -> None:
    # Composition: `USING (true)` leaks, and the restrictive floor
    # `tenant_id IS NOT NULL` does NOT block an anon read of a non-null-tenant
    # row — so `true AND tenant_id IS NOT NULL` is a proven LEAK (was UNVERIFIED
    # before the floor was composed into the proof).
    schema = Schema(
        tables=(
            _table(
                "t",
                policies=(
                    _policy("true", name="perm"),
                    _policy("tenant_id IS NOT NULL", name="floor", permissive=False),
                ),
            ),
        )
    )
    v = build_verification(schema)
    assert _verdict(v, "public.t") == "leak"
    assert v.has_leak


@requires_z3
def test_restrictive_floor_that_blocks_the_leak_is_proven_isolated() -> None:
    # Composition: `USING (true)` leaks in isolation, but a restrictive
    # `USING (false)` floor blocks every row — so `true AND false` is UNSAT and
    # the table is proven ISOLATED (was UNVERIFIED before composition).
    schema = Schema(
        tables=(
            _table(
                "t",
                policies=(
                    _policy("true", name="perm"),
                    _policy("false", name="floor", permissive=False),
                ),
            ),
        )
    )
    v = build_verification(schema)
    assert _verdict(v, "public.t") == "isolated"
    assert not v.has_leak


@requires_z3
def test_restrictive_scoping_floor_blocks_the_anon_leak() -> None:
    # A permissive anon leak (`is_public OR tenant_id = auth.uid()`) that a
    # restrictive tenant-scoping floor (`tenant_id = auth.uid()`) closes: under
    # anon, auth.uid() is NULL so the floor is false, so the composed predicate
    # is unsatisfiable → ISOLATED.
    schema = Schema(
        tables=(
            _table(
                "t",
                policies=(
                    _policy("is_public OR tenant_id = auth.uid()", name="perm"),
                    _policy(
                        "tenant_id = auth.uid()", name="floor", permissive=False
                    ),
                ),
            ),
        )
    )
    v = build_verification(schema)
    assert _verdict(v, "public.t") == "isolated"


@requires_z3
def test_isolated_permissive_with_restrictive_floor_stays_proven() -> None:
    # A restrictive floor only narrows access, so an already-isolated permissive
    # policy stays isolated (the floor downgrade is leak-only). A note flags the
    # floor's presence.
    schema = Schema(
        tables=(
            _table(
                "t",
                policies=(
                    _policy("tenant_id = auth.uid()", name="perm"),
                    _policy("tenant_id IS NOT NULL", name="floor", permissive=False),
                ),
            ),
        )
    )
    v = build_verification(schema)
    [t] = v.tables
    assert t.verdict == "isolated"
    assert t.note and "restrictive read floor" in t.note


@requires_z3
def test_floor_scoped_to_a_role_the_permissive_outreaches_is_not_composed() -> None:
    # SOUNDNESS (role coverage): a permissive `TO public` leaks to anon via
    # `is_public`; a restrictive floor scoped `TO authenticated` does NOT
    # constrain an anon session, so it must not be AND-ed into the anon proof —
    # the leak stands. A role-blind composition would compose the inapplicable
    # floor (`is_public AND tenant_id = auth.uid()`, false under anon) and
    # falsely prove ISOLATED.
    schema = Schema(
        tables=(
            _table(
                "t",
                policies=(
                    _policy("is_public", name="perm", roles=("PUBLIC",)),
                    _policy(
                        "tenant_id = auth.uid()",
                        name="floor",
                        permissive=False,
                        roles=("authenticated",),
                    ),
                ),
            ),
        )
    )
    v = build_verification(schema)
    assert _verdict(v, "public.t") == "leak"
    assert v.has_leak


@requires_z3
def test_floor_for_a_different_write_command_is_not_composed() -> None:
    # SOUNDNESS (command coverage): a FOR INSERT write leak (WITH CHECK admits a
    # cross-tenant row via `is_public`) is not constrained by a FOR UPDATE
    # restrictive floor — a FOR UPDATE policy never gates an INSERT. Composing it
    # would falsely prove the write ISOLATED; the leak must stand.
    schema = Schema(
        tables=(
            _table(
                "t",
                policies=(
                    _policy(
                        None,
                        name="perm",
                        command="INSERT",
                        with_check="tenant_id = auth.uid() OR is_public",
                    ),
                    _policy(
                        None,
                        name="floor",
                        permissive=False,
                        command="UPDATE",
                        with_check="tenant_id = auth.uid()",
                    ),
                ),
            ),
        )
    )
    assert _verdict(_wr(schema), "public.t") == "leak"


@requires_z3
def test_satisfiable_nullable_tautology_is_conditional() -> None:
    # `flag OR NOT flag` is NOT a 3VL tautology — a NULL `flag` row evaluates to
    # NULL (hidden) — so it's a conditional leak (witness None), not "all rows".
    schema = Schema(tables=(_table("t", policies=(_policy("flag OR NOT flag"),)),))
    v = build_verification(schema)
    [t] = v.tables
    [p] = t.proofs
    assert t.verdict == "leak"
    assert p.witness is None


def test_rls_on_no_permissive_policy_is_isolated() -> None:
    # Default-deny: RLS on, no permissive read policy → trivially isolated.
    schema = Schema(tables=(_table("t", policies=()),))
    v = build_verification(schema)
    assert _verdict(v, "public.t") == "isolated"
    assert v.tables[0].proofs == ()


def test_rls_off_table_is_out_of_scope() -> None:
    schema = Schema(tables=(_table("t", rls=False, policies=(_policy("true"),)),))
    assert build_verification(schema).tables == ()


def test_missing_using_ast_is_unverified() -> None:
    pol = Policy(
        name="p", command="ALL", permissive=True, roles=("anon",),
        using_sql="?", with_check_sql=None, using_ast=None, with_check_ast=None,
    )
    schema = Schema(tables=(_table("t", policies=(pol,)),))
    assert _verdict(build_verification(schema), "public.t") == "unverified"


def test_insert_only_policy_is_not_a_read_policy() -> None:
    # A FOR INSERT policy is not a read policy → no permissive read → isolated.
    schema = Schema(
        tables=(_table("t", policies=(_policy("true", command="INSERT"),)),)
    )
    assert _verdict(build_verification(schema), "public.t") == "isolated"


# --- anon role gate (who can invoke the policy, not just what it says) ------
#
# `verify --mode anon` proves what an *anonymous session* can read. A permissive
# policy an anon session cannot invoke (its roles are outside the anon-reachable
# `pg_auth_members` closure) exposes nothing to anon, regardless of its
# predicate — so a table whose only permissive policy is role-scoped away from
# anon proves ISOLATED, not a false LEAK. Membership is decided from a
# live-captured graph (`Schema.role_memberships`); when it is absent we abstain.


def _mem(member: str, role: str) -> RoleMembership:
    """`member` inherits the privileges of `role` (a pg_auth_members edge)."""
    return RoleMembership(member=member, role=role)


@requires_z3
def test_anon_policy_inverted_auth_is_leak() -> None:
    # The signature Supabase bug, exposed TO anon → a real, proven anon leak.
    schema = Schema(
        tables=(
            _table(
                "t",
                policies=(
                    _policy(
                        "auth.uid() IS NULL OR tenant_id = auth.uid()",
                        roles=("anon",),
                    ),
                ),
            ),
        ),
        role_memberships=(),
    )
    v = build_verification(schema)
    assert _verdict(v, "public.t") == "leak"
    assert v.has_leak


@requires_z3
def test_public_policy_inverted_auth_is_leak() -> None:
    # PUBLIC applies to every session incl. anon → the same leak stands.
    schema = Schema(
        tables=(
            _table(
                "t",
                policies=(
                    _policy(
                        "auth.uid() IS NULL OR tenant_id = auth.uid()",
                        roles=("PUBLIC",),
                    ),
                ),
            ),
        ),
        role_memberships=(),
    )
    assert _verdict(build_verification(schema), "public.t") == "leak"


@requires_z3
def test_authenticated_inverted_auth_is_isolated_when_graph_present() -> None:
    # THE FIX. The exact SEC004 shape, but scoped TO authenticated: an anon
    # session is not a member of `authenticated`, so it can never invoke this
    # policy → it exposes nothing to anon → ISOLATED. Before the role gate,
    # verify Z3-checked the predicate blind to the role and reported a false
    # LEAK — disagreeing with lint, which (post-#265) only WARNs on the
    # non-anon role.
    schema = Schema(
        tables=(
            _table(
                "t",
                policies=(
                    _policy(
                        "auth.uid() IS NULL OR tenant_id = auth.uid()",
                        roles=("authenticated",),
                    ),
                ),
            ),
        ),
        role_memberships=(),  # captured, empty: anon reaches only itself + PUBLIC
    )
    v = build_verification(schema)
    assert _verdict(v, "public.t") == "isolated"
    assert not v.has_leak


@requires_z3
def test_authenticated_open_policy_is_isolated_when_graph_present() -> None:
    # Even a `USING (true)` blanket-read policy leaks nothing to *anon* when it
    # is scoped TO authenticated and anon is not a member.
    schema = Schema(
        tables=(_table("t", policies=(_policy("true", roles=("authenticated",)),)),),
        role_memberships=(),
    )
    assert _verdict(build_verification(schema), "public.t") == "isolated"


@requires_z3
def test_custom_role_anon_is_member_is_leak() -> None:
    # `GRANT app_reader TO anon`: anon inherits app_reader, so a leaky policy
    # TO app_reader IS anon-reachable → leak. The closure must follow the edge.
    schema = Schema(
        tables=(_table("t", policies=(_policy("true", roles=("app_reader",)),)),),
        role_memberships=(_mem("anon", "app_reader"),),
    )
    assert _verdict(build_verification(schema), "public.t") == "leak"


@requires_z3
def test_transitive_membership_reaches_leak() -> None:
    # Two hops: anon → mid → app_reader. The upward closure must reach
    # app_reader, so the leaky policy TO app_reader is still a leak.
    schema = Schema(
        tables=(_table("t", policies=(_policy("true", roles=("app_reader",)),)),),
        role_memberships=(_mem("anon", "mid"), _mem("mid", "app_reader")),
    )
    assert _verdict(build_verification(schema), "public.t") == "leak"


@requires_z3
def test_custom_role_anon_not_member_is_isolated() -> None:
    # anon is NOT a member of app_reader (the only edge is unrelated), so the
    # leaky policy TO app_reader is unreachable by anon → isolated.
    schema = Schema(
        tables=(_table("t", policies=(_policy("true", roles=("app_reader",)),)),),
        role_memberships=(_mem("service_worker", "app_reader"),),
    )
    assert _verdict(build_verification(schema), "public.t") == "isolated"


@requires_z3
def test_mixed_anon_leak_dominates_unreachable_scoped_policy() -> None:
    # A leaky TO anon policy alongside a scoped TO authenticated one: the anon
    # leak dominates; the authenticated policy is dropped from the anon model.
    schema = Schema(
        tables=(
            _table(
                "t",
                policies=(
                    _policy("true", name="pub", roles=("anon",)),
                    _policy(
                        "tenant_id = auth.uid()",
                        name="scoped",
                        roles=("authenticated",),
                    ),
                ),
            ),
        ),
        role_memberships=(),
    )
    assert _verdict(build_verification(schema), "public.t") == "leak"


@requires_z3
def test_anon_roles_override_treats_named_role_as_anon() -> None:
    # The [verify].anon_roles config (mirrors SEC004): naming `visitor` the anon
    # role makes a leaky policy TO visitor a leak; by default it is isolated.
    schema = Schema(
        tables=(_table("t", policies=(_policy("true", roles=("visitor",)),)),),
        role_memberships=(),
    )
    assert _verdict(build_verification(schema), "public.t") == "isolated"
    assert (
        _verdict(build_verification(schema, anon_roles={"visitor"}), "public.t")
        == "leak"
    )


def test_non_anon_role_is_unverified_when_graph_absent() -> None:
    # A leaking predicate scoped to a non-anon role, offline / --against (no
    # membership graph): we cannot decide whether anon reaches `authenticated`,
    # so the *leak* is abstained (UNVERIFIED) — never guessed isolated. (A
    # *scoped* predicate would prove isolated regardless — see the test below.)
    schema = Schema(
        tables=(_table("t", policies=(_policy("true", roles=("authenticated",)),)),),
    )  # role_memberships defaults to None
    v = build_verification(schema)
    assert _verdict(v, "public.t") == "unverified"
    [t] = v.tables
    assert any(
        "role-membership graph was not captured" in (p.reason or "")
        for p in t.proofs
    )


@requires_z3
def test_scoped_non_anon_role_is_isolated_offline_via_predicate() -> None:
    # The complement of the abstain above: a scoped policy proves ISOLATED under
    # anon from its predicate alone (`auth.uid()` is NULL → no row matches),
    # independent of role or graph. So an offline / snapshot schema with a
    # `TO authenticated` scoped policy is soundly `isolated`, NOT abstained —
    # the role gate only intercepts *leaking* predicates.
    schema = Schema(
        tables=(
            _table(
                "t",
                policies=(
                    _policy("tenant_id = auth.uid()", roles=("authenticated",)),
                ),
            ),
        ),
    )  # role_memberships defaults to None (offline)
    assert _verdict(build_verification(schema), "public.t") == "isolated"


@requires_z3
def test_empty_anon_roles_falls_back_to_default() -> None:
    # A degenerate *empty* anon set must NOT collapse the reachable seed to just
    # `{PUBLIC}` and false-clear a `TO anon` leak — the prover falls back to the
    # default `{anon, PUBLIC}` (there is always at least PUBLIC = every session).
    schema = Schema(
        tables=(_table("t", policies=(_policy("true", roles=("anon",)),)),),
        role_memberships=(),
    )
    assert (
        _verdict(build_verification(schema, anon_roles=set()), "public.t") == "leak"
    )


@requires_z3
def test_leak_is_not_dropped_on_uncanonicalized_roles() -> None:
    # Fail-open hardening: a hand-built Schema whose leaking policy carries an
    # un-canonicalized role — lowercase `public` (Postgres reserves the name, so
    # it is always the PUBLIC pseudo-role) or a degenerate empty role set — must
    # NOT be silently dropped to `isolated` by the role gate. The leak stands.
    for roles in (("public",), ()):
        schema = Schema(
            tables=(_table("t", policies=(_policy("true", roles=roles),)),),
            role_memberships=(),  # graph captured → the gate is active
        )
        assert _verdict(build_verification(schema), "public.t") == "leak", roles


def test_anon_and_non_anon_role_absent_graph_still_leaks() -> None:
    # Soundness both ways: even with the graph absent, a policy that literally
    # names anon is decidable → its predicate is checked and the leak stands
    # (only the *non-anon* policy abstains).
    schema = Schema(
        tables=(_table("t", policies=(_policy("true", roles=("anon", "staff")),)),),
    )
    assert _verdict(build_verification(schema), "public.t") == "leak"


# --- renderers -------------------------------------------------------------


def _sample() -> Verification:
    return build_verification(
        Schema(
            tables=(
                _table("safe", policies=(_policy("tenant_id = auth.uid()"),)),
                _table("leaky", policies=(_policy("true"),)),
            )
        )
    )


@requires_z3
def test_render_text_has_verdicts_and_summary() -> None:
    out = render_text(_sample())
    assert "PROVEN" in out and "LEAK" in out
    assert "public.safe" in out and "public.leaky" in out
    assert "every row is anonymously readable" in out
    assert "proven isolated" in out and "leaking" in out


def test_render_text_empty() -> None:
    assert "No RLS-enabled tables" in render_text(build_verification(Schema(tables=())))


@requires_z3
def test_render_json_shape() -> None:
    payload = json.loads(render_json(_sample()))
    assert set(payload["summary"]) == {"tables", "isolated", "leak", "unverified"}
    leaky = next(t for t in payload["tables"] if t["table"] == "public.leaky")
    assert leaky["verdict"] == "leak"
    p = leaky["policies"][0]
    assert p["witness_scope"] == "all_rows"
    assert p["witness"] == {}


@requires_z3
def test_render_json_unicode_preserved() -> None:
    schema = Schema(tables=(_table("café", policies=(_policy("true"),)),))
    out = render_json(build_verification(schema))
    assert "café" in out and "\\u" not in out


# --- SARIF renderer --------------------------------------------------------
#
# `pgrls verify --format sarif` reuses lint's `format_sarif` (the same precedent
# `pgrls diff` sets) by projecting each *actionable* verdict into a Violation, so
# these tests pin (a) the structural contract shared with lint — version /
# $schema / tool.driver — exactly as tests/test_formatter_sarif.py does, and
# (b) the verify-specific verdict→result mapping (the central contract): a result
# is present iff the run would fail the gate.


def _sarif(v: Verification, *, strict: bool = False) -> dict:
    """Parse `render_sarif` output, asserting it is valid JSON first."""
    out = render_sarif(v, strict=strict)
    return json.loads(out)


@requires_z3
def test_render_sarif_is_valid_json_and_lint_consistent_top_level() -> None:
    # Structural consistency with lint SARIF: same version, $schema, and
    # tool.driver block (name / version / informationUri). This is the whole
    # point of routing through `format_sarif` — verify, lint, and diff can never
    # drift on the envelope.
    from pgrls import __version__

    doc = _sarif(_sample())
    assert doc["version"] == "2.1.0"
    assert doc["$schema"] == _SARIF_SCHEMA
    assert len(doc["runs"]) == 1
    driver = doc["runs"][0]["tool"]["driver"]
    assert driver["name"] == "pgrls"
    assert driver["version"] == __version__
    assert driver["informationUri"].startswith("https://")


@requires_z3
def test_render_sarif_leak_is_error_result_with_location_and_witness() -> None:
    # The central contract for a LEAK: exactly one `error`-level result, located
    # at the leaking policy (schema.table.policy), carrying the witness phrase.
    doc = _sarif(_sample())
    results = doc["runs"][0]["results"]
    # _sample() has one leaking table (public.leaky, USING true) and one proven
    # isolated table (public.safe) → exactly one result.
    assert len(results) == 1
    [r] = results
    assert r["ruleId"] == "pgrls-anon-isolation"
    assert r["level"] == "error"
    fqn = r["locations"][0]["logicalLocations"][0]["fullyQualifiedName"]
    # public.leaky's only policy is named "p" → schema.table.policy.
    assert fqn == "public.leaky.p"
    # Message carries the table and the witness phrase render_text surfaces.
    assert r["message"]["text"] == "public.leaky: every row is anonymously readable"


@requires_z3
def test_render_sarif_proven_only_schema_has_no_results() -> None:
    # A PROVEN-only schema produces clean SARIF: a well-formed run with an empty
    # results array (the SARIF "all clear" state) — and, since no rule fired,
    # an empty rules array. Mirrors lint's zero-violations contract.
    schema = Schema(tables=(_table("safe", policies=(_policy("tenant_id = auth.uid()"),)),))
    doc = _sarif(build_verification(schema))
    run = doc["runs"][0]
    assert run["results"] == []
    assert run["tool"]["driver"]["rules"] == []


@requires_z3
def test_render_sarif_rule_descriptor_shape_and_help_uri() -> None:
    # Exactly one rule descriptor per run (single mode); `name == id` (SARIF
    # §3.49.7 identifier, not the prose title); defaultConfiguration.level is
    # `error`; helpUri routes the `pgrls-` prefix to the README verify anchor
    # (NOT a docs/RULES.md per-rule page, which would 404).
    doc = _sarif(_sample())
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    assert len(rules) == 1
    [rule] = rules
    assert rule["id"] == "pgrls-anon-isolation"
    assert rule["name"] == "pgrls-anon-isolation"
    assert rule["shortDescription"]["text"] == "Anonymous read-isolation proof"
    assert rule["defaultConfiguration"]["level"] == "error"
    assert rule["helpUri"].endswith(
        "README.md#prove-tenant-isolation--pgrls-verify"
    )


@requires_z3
def test_render_sarif_unverified_is_omitted_by_default() -> None:
    # UNVERIFIED does not fail a non-strict gate, so it produces no result by
    # default (it is not actionable). The run is still well-formed (empty
    # results + rules).
    schema = Schema(
        tables=(
            _table(
                "t",
                policies=(
                    _policy("tenant_id = ANY(string_to_array(current_setting('x'), ','))"),
                ),
            ),
        )
    )
    v = build_verification(schema)
    assert _verdict(v, "public.t") == "unverified"
    run = _sarif(v)["runs"][0]
    assert run["results"] == []
    assert run["tool"]["driver"]["rules"] == []


@requires_z3
def test_render_sarif_strict_emits_note_for_unverified() -> None:
    # Under --strict, UNVERIFIED *does* fail the gate, so it surfaces as one
    # `note`-level result (SARIF's below-warning level) per unverified table,
    # located at the table (no policy suffix), message = the table's reason.
    schema = Schema(
        tables=(
            _table(
                "t",
                policies=(
                    _policy("tenant_id = ANY(string_to_array(current_setting('x'), ','))"),
                ),
            ),
        )
    )
    v = build_verification(schema)
    doc = _sarif(v, strict=True)
    results = doc["runs"][0]["results"]
    assert len(results) == 1
    [r] = results
    assert r["level"] == "note"
    assert r["ruleId"] == "pgrls-anon-isolation"
    fqn = r["locations"][0]["logicalLocations"][0]["fullyQualifiedName"]
    assert fqn == "public.t"  # table, no .policy suffix
    assert r["message"]["text"].startswith("public.t: ")
    # With no leak in the run, the only severity observed for the rule is the
    # strict-UNVERIFIED `info` → the descriptor's defaultConfiguration.level is
    # `note` (it is derived from the first observed severity for that rule id, per
    # lint's `format_sarif`). The mixed leak+strict case — where `error` is
    # observed first and the descriptor stays `error` while the per-result level
    # is `note` — is pinned separately below.
    [rule] = doc["runs"][0]["tool"]["driver"]["rules"]
    assert rule["defaultConfiguration"]["level"] == "note"


@requires_z3
def test_render_sarif_strict_leak_and_unverified_share_one_rule_descriptor() -> None:
    # When a LEAK (error) and a strict-UNVERIFIED note coexist they reuse the
    # SAME rule id → exactly one descriptor. `error` is observed first, so the
    # descriptor's defaultConfiguration.level is `error`, while the unverified
    # row's per-result level stays `note` (per-result level wins — lint's
    # contract). This is the mixed case the design note describes.
    schema = Schema(
        tables=(
            _table("leaky", policies=(_policy("true"),)),
            _table(
                "murky",
                policies=(
                    _policy("tenant_id = ANY(string_to_array(current_setting('x'), ','))"),
                ),
            ),
        )
    )
    doc = _sarif(build_verification(schema), strict=True)
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    assert len(rules) == 1  # one descriptor, shared
    assert rules[0]["defaultConfiguration"]["level"] == "error"
    results = doc["runs"][0]["results"]
    by_table = {
        r["locations"][0]["logicalLocations"][0]["fullyQualifiedName"]: r["level"]
        for r in results
    }
    assert by_table["public.leaky.p"] == "error"
    assert by_table["public.murky"] == "note"


@requires_z3
def test_render_sarif_proven_schema_clean_even_under_strict() -> None:
    # A PROVEN-only schema is clean under --strict too — strict only adds
    # UNVERIFIED notes, never touches the isolated verdict.
    schema = Schema(tables=(_table("safe", policies=(_policy("tenant_id = auth.uid()"),)),))
    run = _sarif(build_verification(schema), strict=True)["runs"][0]
    assert run["results"] == []


@requires_z3
def test_render_sarif_cross_tenant_rule_id_and_witness() -> None:
    # In cross-tenant mode the rule id + witness phrasing switch: the leak is a
    # cross-tenant one and the message frames the row as another tenant's.
    schema = Schema(
        tables=(_table("docs", policies=(_policy("tenant_id = auth.uid() OR is_public"),)),)
    )
    doc = _sarif(build_verification(schema, mode="cross-tenant"))
    [r] = doc["runs"][0]["results"]
    assert r["ruleId"] == "pgrls-cross-tenant-isolation"
    assert r["level"] == "error"
    assert r["message"]["text"] == (
        "public.docs: a row of another tenant with is_public=True is readable"
    )
    [rule] = doc["runs"][0]["tool"]["driver"]["rules"]
    assert rule["id"] == "pgrls-cross-tenant-isolation"
    assert rule["shortDescription"]["text"] == "Cross-tenant read-isolation proof"


@requires_z3
def test_render_sarif_unicode_preserved() -> None:
    # Inherited from lint's `format_sarif`: ensure_ascii=False, so a non-ASCII
    # table name is preserved verbatim (not \uXXXX-escaped).
    schema = Schema(tables=(_table("café", policies=(_policy("true"),)),))
    out = render_sarif(build_verification(schema))
    assert "café" in out and "\\u" not in out


@requires_z3
def test_render_sarif_ends_with_newline() -> None:
    # Shell-friendliness — byte-compatible with lint's trailing-newline contract.
    assert render_sarif(_sample()).endswith("\n")


@requires_z3
def test_render_sarif_every_leak_result_has_nonempty_fqn() -> None:
    # GitHub Code Scanning rejects a result with an empty fullyQualifiedName. A
    # leak rollup always has a representative leak proof, so every leak result
    # pins to schema.table.policy — the `(schema-wide)` sentinel is never hit.
    doc = _sarif(_sample())
    for r in doc["runs"][0]["results"]:
        fqn = r["locations"][0]["logicalLocations"][0]["fullyQualifiedName"]
        assert fqn and fqn != "(schema-wide)"


@requires_z3
def test_render_sarif_and_json_agree_on_which_tables_leak() -> None:
    # Cross-format consistency: the set of LEAK tables JSON reports must equal
    # the set of tables SARIF pins a result to. SARIF deliberately omits the
    # PROVEN/UNVERIFIED rows JSON carries (only actionable verdicts become
    # results), but the *leaking* tables — the answer the gate turns on — must
    # match across both machine surfaces.
    schema = Schema(
        tables=(
            _table("safe", policies=(_policy("tenant_id = auth.uid()"),)),
            _table("leaky_a", policies=(_policy("true"),)),
            _table("leaky_b", policies=(_policy("auth.uid() IS NULL OR tenant_id = auth.uid()"),)),
        )
    )
    v = build_verification(schema)
    json_leak_tables = {
        t["table"] for t in json.loads(render_json(v))["tables"] if t["verdict"] == "leak"
    }
    sarif_leak_tables = {
        # fullyQualifiedName is schema.table[.policy]; the leak FQN is
        # schema.table.policy, so strip the trailing policy segment.
        r["locations"][0]["logicalLocations"][0]["fullyQualifiedName"].rsplit(".", 1)[0]
        for r in _sarif(v)["runs"][0]["results"]
    }
    assert json_leak_tables == {"public.leaky_a", "public.leaky_b"}
    assert sarif_leak_tables == json_leak_tables


@requires_z3
def test_render_sarif_levels_are_only_error_or_note() -> None:
    # The only severities verify projects are error (leak) and info→note
    # (strict unverified). Pin that no `warning`/`none` ever leaks in, across a
    # mixed schema under strict.
    schema = Schema(
        tables=(
            _table("leaky", policies=(_policy("true"),)),
            _table("safe", policies=(_policy("tenant_id = auth.uid()"),)),
            _table(
                "murky",
                policies=(
                    _policy("tenant_id = ANY(string_to_array(current_setting('x'), ','))"),
                ),
            ),
        )
    )
    doc = _sarif(build_verification(schema), strict=True)
    levels = {r["level"] for r in doc["runs"][0]["results"]}
    assert levels <= {"error", "note"}
    # Leak → error, the unverified table → note (under strict), safe → nothing.
    assert levels == {"error", "note"}


# --- CLI -------------------------------------------------------------------


def test_verify_cli_help() -> None:
    result = CliRunner().invoke(main, ["verify", "--help"])
    assert result.exit_code == 0
    assert "Prove tenant isolation" in result.output


def test_verify_cli_errors_without_database_url() -> None:
    result = CliRunner().invoke(main, ["verify"], env={"DATABASE_URL": ""})
    assert result.exit_code == 2
    assert "No database connection" in result.output


def test_verify_cli_is_registered_format_list() -> None:
    from pgrls.verify import VERIFY_FORMATS

    assert VERIFY_FORMATS == ("text", "json", "sarif")


def test_verify_cli_help_lists_sarif_format() -> None:
    # The `@output_format_options(list(VERIFY_FORMATS), …)` decorator must
    # surface `sarif` in the `--format [text|json|sarif]` choice in --help.
    result = CliRunner().invoke(main, ["verify", "--help"])
    assert result.exit_code == 0
    assert "text|json|sarif" in result.output


# --- live introspection (Docker) ------------------------------------------


@requires_docker
@requires_z3
def test_verify_cli_live_leak_exits_one(pg_conn: psycopg.Connection) -> None:
    with pg_conn.cursor() as cur:
        cur.execute(_AUTH_STUB)
        cur.execute(
            "CREATE TABLE public.docs (id bigint PRIMARY KEY, tenant_id uuid);"
            "ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;"
            "ALTER TABLE public.docs FORCE ROW LEVEL SECURITY;"
            # The inverted-auth leak: anon (auth.uid() NULL) sees every row.
            "CREATE POLICY p ON public.docs FOR SELECT TO public "
            "  USING (auth.uid() IS NULL OR tenant_id = auth.uid());"
        )
    schema = introspect(pg_conn, schemas=["public"])
    v = build_verification(schema)
    assert _verdict(v, "public.docs") == "leak"


@requires_docker
@requires_z3
def test_verify_cli_live_exit_code_and_output(
    pg_url: str, pg_conn: psycopg.Connection
) -> None:
    # End-to-end CLI: a leaking policy makes `pgrls verify` exit 1 (the CI
    # tenant-isolation gate) and print the LEAK verdict.
    with pg_conn.cursor() as cur:
        cur.execute(_AUTH_STUB)
        cur.execute(
            "CREATE TABLE public.docs (id bigint PRIMARY KEY, tenant_id uuid);"
            "ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;"
            "ALTER TABLE public.docs FORCE ROW LEVEL SECURITY;"
            "CREATE POLICY p ON public.docs FOR SELECT TO public "
            "  USING (auth.uid() IS NULL OR tenant_id = auth.uid());"
        )
    result = CliRunner().invoke(
        main, ["verify", "--database-url", pg_url, "--schemas", "public"]
    )
    assert result.exit_code == 1, result.output
    assert "LEAK" in result.output and "public.docs" in result.output


@requires_docker
@requires_z3
def test_verify_cli_live_write_mode_leak_exits_one(
    pg_url: str, pg_conn: psycopg.Connection
) -> None:
    # End-to-end: a FOR INSERT WITH CHECK with an unscoped disjunct lets a
    # caller stamp a row for another tenant → `verify --mode write` exits 1.
    with pg_conn.cursor() as cur:
        cur.execute(_AUTH_STUB)
        cur.execute(
            "CREATE TABLE public.docs "
            "  (id bigint PRIMARY KEY, tenant_id uuid, is_public boolean);"
            "ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;"
            "ALTER TABLE public.docs FORCE ROW LEVEL SECURITY;"
            "CREATE POLICY p ON public.docs FOR INSERT TO public "
            "  WITH CHECK (is_public OR tenant_id = (select auth.uid()));"
        )
    result = CliRunner().invoke(
        main,
        ["verify", "--database-url", pg_url, "--schemas", "public",
         "--mode", "write"],
    )
    assert result.exit_code == 1, result.output
    assert "LEAK" in result.output and "public.docs" in result.output


@requires_docker
@requires_z3
def test_verify_cli_live_write_mode_scoped_exits_zero(
    pg_url: str, pg_conn: psycopg.Connection
) -> None:
    # A FOR INSERT WITH CHECK that binds the tenant to the session is proven
    # write-isolated → `verify --mode write` exits 0.
    with pg_conn.cursor() as cur:
        cur.execute(_AUTH_STUB)
        cur.execute(
            "CREATE TABLE public.docs (id bigint PRIMARY KEY, tenant_id uuid);"
            "ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;"
            "ALTER TABLE public.docs FORCE ROW LEVEL SECURITY;"
            "CREATE POLICY p ON public.docs FOR INSERT TO public "
            "  WITH CHECK (tenant_id = (select auth.uid()));"
        )
    result = CliRunner().invoke(
        main,
        ["verify", "--database-url", pg_url, "--schemas", "public",
         "--mode", "write"],
    )
    assert result.exit_code == 0, result.output
    assert "PROVEN" in result.output


@requires_docker
@requires_z3
def test_verify_cli_live_sarif_leak_end_to_end(
    pg_url: str, pg_conn: psycopg.Connection
) -> None:
    # End-to-end through the CLI: `pgrls verify --format sarif` on a leaking
    # policy emits a valid SARIF document (parseable, lint-consistent envelope)
    # with one `error` result pinned to the leaking policy, and still exits 1
    # (the gate fires regardless of output format).
    with pg_conn.cursor() as cur:
        cur.execute(_AUTH_STUB)
        cur.execute(
            "CREATE TABLE public.docs (id bigint PRIMARY KEY, tenant_id uuid);"
            "ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;"
            "ALTER TABLE public.docs FORCE ROW LEVEL SECURITY;"
            "CREATE POLICY p ON public.docs FOR SELECT TO public "
            "  USING (auth.uid() IS NULL OR tenant_id = auth.uid());"
        )
    result = CliRunner().invoke(
        main,
        ["verify", "--database-url", pg_url, "--schemas", "public",
         "--format", "sarif"],
    )
    assert result.exit_code == 1, result.output  # leak → exit 1
    doc = json.loads(result.output)  # valid JSON
    assert doc["version"] == "2.1.0"
    assert doc["$schema"] == _SARIF_SCHEMA
    assert doc["runs"][0]["tool"]["driver"]["name"] == "pgrls"
    [r] = doc["runs"][0]["results"]
    assert r["ruleId"] == "pgrls-anon-isolation"
    assert r["level"] == "error"
    assert (
        r["locations"][0]["logicalLocations"][0]["fullyQualifiedName"]
        == "public.docs.p"
    )


@requires_docker
@requires_z3
def test_verify_cli_live_sarif_proven_is_clean_and_exits_zero(
    pg_conn: psycopg.Connection, pg_url: str
) -> None:
    # The complement: a properly-scoped policy → SARIF with zero results and a
    # zero exit code (the SARIF "all clear" gate state), end-to-end.
    with pg_conn.cursor() as cur:
        cur.execute(_AUTH_STUB)
        cur.execute(
            "CREATE TABLE public.acct (id bigint PRIMARY KEY, tenant_id uuid);"
            "ALTER TABLE public.acct ENABLE ROW LEVEL SECURITY;"
            "ALTER TABLE public.acct FORCE ROW LEVEL SECURITY;"
            "CREATE POLICY p ON public.acct FOR SELECT TO public "
            "  USING (tenant_id = (select auth.uid()));"
        )
    result = CliRunner().invoke(
        main,
        ["verify", "--database-url", pg_url, "--schemas", "public",
         "--format", "sarif"],
    )
    assert result.exit_code == 0, result.output
    doc = json.loads(result.output)
    assert doc["runs"][0]["results"] == []


@requires_docker
@requires_z3
def test_verify_cli_emit_repro_force_guard(
    pg_url: str, pg_conn: psycopg.Connection, tmp_path: Path
) -> None:
    # `--emit-repro` must not silently clobber a hand-edited reproduction: a
    # second run without --force errors (exit 2) and preserves the edit; --force
    # rewrites. Mirrors the generate/fix/init --output guard convention.
    with pg_conn.cursor() as cur:
        cur.execute(_AUTH_STUB)
        cur.execute(
            "CREATE TABLE public.docs (id bigint PRIMARY KEY, tenant_id uuid);"
            "ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;"
            "ALTER TABLE public.docs FORCE ROW LEVEL SECURITY;"
            "CREATE POLICY p ON public.docs FOR SELECT TO public "
            "  USING (auth.uid() IS NULL OR tenant_id = auth.uid());"
        )
    out = tmp_path / "repro"
    runner = CliRunner()
    args = [
        "verify", "--database-url", pg_url, "--schemas", "public",
        "--emit-repro", str(out),
    ]
    r1 = runner.invoke(main, args)
    assert r1.exit_code == 1, r1.output  # leak → exit 1 (files written first)
    sqlf = out / "public_docs_p.sql"
    assert sqlf.exists()
    sqlf.write_text("-- HAND-EDITED\n" + sqlf.read_text(), encoding="utf-8")

    # second run, no --force → refuses (ToolError exit 2), edit preserved
    r2 = runner.invoke(main, args)
    assert r2.exit_code == 2, r2.output
    assert "already exists" in r2.output and "--force" in r2.output
    assert "HAND-EDITED" in sqlf.read_text()

    # --force → overwrites, back to the leak exit
    r3 = runner.invoke(main, [*args, "--force"])
    assert r3.exit_code == 1, r3.output
    assert "HAND-EDITED" not in sqlf.read_text()


@requires_docker
@requires_z3
def test_verify_cli_emit_repro_unwritable_dir_clean_error(
    pg_url: str, pg_conn: psycopg.Connection, tmp_path: Path
) -> None:
    # An unwritable --emit-repro dir must surface a clean ToolError (exit 2),
    # not a raw OSError traceback — matching init/fix/generate's write guard.
    with pg_conn.cursor() as cur:
        cur.execute(_AUTH_STUB)
        cur.execute(
            "CREATE TABLE public.docs (id bigint PRIMARY KEY, tenant_id uuid);"
            "ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;"
            "ALTER TABLE public.docs FORCE ROW LEVEL SECURITY;"
            "CREATE POLICY p ON public.docs FOR SELECT TO public "
            "  USING (auth.uid() IS NULL OR tenant_id = auth.uid());"
        )
    # A regular file in the path → mkdir(parents=True) raises NotADirectoryError
    # (an OSError), independent of uid/permissions.
    blocker = tmp_path / "blocker"
    blocker.write_text("not a dir", encoding="utf-8")
    result = CliRunner().invoke(
        main,
        ["verify", "--database-url", pg_url, "--schemas", "public",
         "--emit-repro", str(blocker / "sub")],
    )
    assert result.exit_code == 2, result.output
    assert "Cannot write reproduction files" in result.output


@requires_docker
@requires_z3
def test_verify_cli_live_scoped_is_isolated(pg_conn: psycopg.Connection) -> None:
    with pg_conn.cursor() as cur:
        cur.execute(_AUTH_STUB)
        cur.execute(
            "CREATE TABLE public.acct (id bigint PRIMARY KEY, tenant_id uuid);"
            "ALTER TABLE public.acct ENABLE ROW LEVEL SECURITY;"
            "ALTER TABLE public.acct FORCE ROW LEVEL SECURITY;"
            "CREATE POLICY p ON public.acct FOR SELECT TO public "
            "  USING (tenant_id = (select auth.uid()));"
        )
    schema = introspect(pg_conn, schemas=["public"])
    assert _verdict(build_verification(schema), "public.acct") == "isolated"


# --- cross-tenant mode (Z3) ------------------------------------------------


def _xt(schema: Schema) -> Verification:
    return build_verification(schema, mode="cross-tenant")


def _wr(schema: Schema) -> Verification:
    return build_verification(schema, mode="write")


def test_build_verification_default_mode_is_anon() -> None:
    v = build_verification(Schema(tables=(_table("t", policies=()),)))
    assert v.mode == "anon"


# --- write mode (WITH CHECK isolation) -------------------------------------


@requires_z3
def test_write_insert_with_check_scoped_is_isolated() -> None:
    # FOR INSERT with a tenant-scoped WITH CHECK → a caller cannot stamp a row
    # for another tenant. PROVEN write-isolated.
    schema = Schema(
        tables=(
            _table(
                "t",
                policies=(
                    _policy(
                        None, command="INSERT", with_check="tenant_id = auth.uid()"
                    ),
                ),
            ),
        )
    )
    assert _verdict(_wr(schema), "public.t") == "isolated"


@requires_z3
def test_write_update_using_fallback_is_isolated() -> None:
    # FOR UPDATE with NO WITH CHECK: Postgres reuses USING as the new-row check,
    # so a scoped USING write-isolates. The soundness-critical fallback — if the
    # encoder ignored USING here it would falsely prove a re-stamp impossible.
    schema = Schema(
        tables=(
            _table(
                "t",
                policies=(_policy("tenant_id = auth.uid()", command="UPDATE"),),
            ),
        )
    )
    assert _verdict(_wr(schema), "public.t") == "isolated"


@requires_z3
def test_write_all_using_fallback_is_isolated() -> None:
    schema = Schema(
        tables=(
            _table("t", policies=(_policy("tenant_id = auth.uid()", command="ALL"),)),
        )
    )
    assert _verdict(_wr(schema), "public.t") == "isolated"


# --- write mode covers the OLD-row gate, not just the new-row check (MF3) ---
#
# A write crosses tenants two ways: stamping a NEW row for another tenant
# (WITH CHECK), or reaching an EXISTING row of another tenant to take over or
# delete it (USING). Checking only the first proved "no cross-tenant write" on
# schemas where the second was wide open. Both exploits are live-verified on
# PG16 with a statement that reads no column (bare `DELETE FROM t` /
# `UPDATE t SET ...`), which escapes the SELECT-applicable re-check.


@requires_z3
def test_write_open_old_row_gate_lets_a_tenant_steal_a_row() -> None:
    # `USING (true) WITH CHECK (tenant = me)`: the new-row check is scoped, so
    # the old behaviour proved isolated — yet the open old-row gate lets a
    # session re-stamp ANOTHER tenant's row to itself. Verified live: the row's
    # owner changed and its body came with it.
    schema = Schema(
        tables=(
            _table(
                "t",
                policies=(
                    _policy(
                        "true", command="UPDATE", with_check="tenant_id = auth.uid()"
                    ),
                ),
            ),
        )
    )
    assert _verdict(_wr(schema), "public.t") == "leak"


@requires_z3
def test_write_mode_covers_delete_policies() -> None:
    # A FOR DELETE policy has no WITH CHECK at all, so it contributed nothing
    # and the table proved "no cross-tenant write" while any tenant could wipe
    # it. DELETE destroys an existing row and is gated solely by its USING.
    leaky = Schema(
        tables=(
            _table(
                "t",
                policies=(
                    _policy(
                        "tenant_id = auth.uid() OR is_public", command="DELETE"
                    ),
                ),
            ),
        )
    )
    assert _verdict(_wr(leaky), "public.t") == "leak"

    scoped = Schema(
        tables=(
            _table(
                "t",
                policies=(_policy("tenant_id = auth.uid()", command="DELETE"),),
            ),
        )
    )
    assert _verdict(_wr(scoped), "public.t") == "isolated"


@requires_z3
def test_write_unscoped_open_delete_is_not_proven() -> None:
    # `FOR DELETE USING (true)` carries no tenant axis, so the cross-tenant
    # prover cannot characterize "another tenant's row" and declines — the same
    # boundary it applies to an unscoped read. The point is that it is no
    # longer PROVEN: an honest no-claim fails `--strict`, a false clear does not.
    schema = Schema(
        tables=(_table("t", policies=(_policy("true", command="DELETE"),)),)
    )
    assert _verdict(_wr(schema), "public.t") != "isolated"


@requires_z3
def test_write_gold_standard_all_policy_stays_isolated() -> None:
    # Precision control: OR-composing the two gates must not manufacture a leak
    # on the shape `pgrls generate` emits, where both gates are the same scoped
    # predicate (they dedupe to one term).
    schema = Schema(
        tables=(
            _table(
                "t",
                policies=(
                    _policy(
                        "tenant_id = auth.uid()",
                        command="ALL",
                        with_check="tenant_id = auth.uid()",
                    ),
                ),
            ),
        )
    )
    assert _verdict(_wr(schema), "public.t") == "isolated"


@requires_z3
def test_write_with_check_overrides_using() -> None:
    # WITH CHECK FULLY overrides USING for the new row (NOT AND-combined). A
    # scoped USING with `WITH CHECK (true)` lets a caller write any tenant's row,
    # so the prover must NOT say isolated — a regression that AND-ed USING in
    # would wrongly do so.
    #
    # This used to be `unverified`: checking the new-row gate alone left the
    # prover a bare `true` with no tenant axis to reason about. Now that both
    # write gates are OR-composed, the USING supplies the scoping equality and
    # the constant-true WITH CHECK makes it satisfiable for a foreign tenant, so
    # the leak is PROVEN rather than merely unclaimed — strictly stronger, and
    # exactly what the policy does (take your own row, re-stamp it to anyone).
    schema = Schema(
        tables=(
            _table(
                "t",
                policies=(
                    _policy(
                        "tenant_id = auth.uid()", command="UPDATE", with_check="true"
                    ),
                ),
            ),
        )
    )
    assert _verdict(_wr(schema), "public.t") == "leak"


@requires_z3
def test_write_unscoped_with_check_true_is_unverified_not_isolated() -> None:
    # An unscoped `WITH CHECK (true)` carries no tenant-scoping equality → the
    # prover declines (unverified), never isolated. SEC006/020/028/040 are the
    # linter fallback for this constant-true write-check.
    schema = Schema(
        tables=(
            _table("t", policies=(_policy(None, command="INSERT", with_check="true"),)),
        )
    )
    assert _verdict(_wr(schema), "public.t") == "unverified"


@requires_z3
def test_write_cross_tenant_disjunct_is_leak_with_witness() -> None:
    # A write-check with an unscoped disjunct lets a caller stamp another
    # tenant's row → proven write LEAK with a characterizing witness.
    schema = Schema(
        tables=(
            _table(
                "t",
                policies=(
                    _policy(
                        None,
                        command="INSERT",
                        with_check="is_public OR tenant_id = (select auth.uid())",
                    ),
                ),
            ),
        )
    )
    v = _wr(schema)
    [t] = v.tables
    assert t.verdict == "leak"
    leak = next(p for p in t.proofs if p.verdict == "leak")
    assert leak.witness == {"is_public": True}


@requires_z3
def test_write_select_only_table_is_isolated_no_write_policy() -> None:
    # A SELECT-only policy never gates a write → no permissive write policy →
    # Postgres default-denies writes → trivially isolated (no proofs emitted).
    schema = Schema(
        tables=(_table("t", policies=(_policy("tenant_id = auth.uid()", command="SELECT"),)),)
    )
    v = _wr(schema)
    [t] = v.tables
    assert t.verdict == "isolated"
    assert t.proofs == ()
    assert t.note == "no permissive write policy — RLS default-denies writes"


@requires_z3
def test_write_delete_only_table_is_isolated() -> None:
    schema = Schema(
        tables=(_table("t", policies=(_policy("tenant_id = auth.uid()", command="DELETE"),)),)
    )
    assert _verdict(_wr(schema), "public.t") == "isolated"


@requires_z3
def test_write_bare_insert_is_skipped_and_isolated() -> None:
    # A bare FOR INSERT (no WITH CHECK) grants no write path (Postgres
    # default-denies it), so it emits NO proof — not a spurious "unverified".
    schema = Schema(
        tables=(_table("t", policies=(_policy(None, command="INSERT"),)),)
    )
    v = _wr(schema)
    [t] = v.tables
    assert t.verdict == "isolated"
    assert t.proofs == ()  # the bare insert contributed nothing


@requires_z3
def test_write_missing_ast_on_update_is_unverified() -> None:
    # A FOR UPDATE policy whose ASTs are absent (snapshot without parsed ASTs)
    # cannot be checked → unverified "write-check not available" (distinct from
    # the bare-insert skip above).
    policy = Policy(
        name="p",
        command="UPDATE",
        permissive=True,
        roles=("authenticated",),
        using_sql=None,
        with_check_sql=None,
        using_ast=None,
        with_check_ast=None,
    )
    schema = Schema(tables=(_table("t", policies=(policy,)),))
    v = _wr(schema)
    [t] = v.tables
    assert t.verdict == "unverified"
    [proof] = t.proofs
    assert proof.reason == "write-check not available"


@requires_z3
def test_write_restrictive_floor_composed_but_prover_abstains() -> None:
    # A permissive unscoped write-check + a restrictive scoped write floor: the
    # floor IS composed into the proof, but the cross-tenant WRITE prover needs a
    # single `<column> = <session identity>` scoping equality and can't extract
    # one from the composed `true AND tenant_id = auth.uid()` — so it abstains
    # (unverified). Sound: no possibly-wrong verdict, and the note reflects that
    # composition was attempted.
    schema = Schema(
        tables=(
            _table(
                "t",
                policies=(
                    _policy(None, command="INSERT", with_check="true"),
                    _policy(
                        None,
                        name="floor",
                        permissive=False,
                        command="INSERT",
                        with_check="tenant_id = auth.uid()",
                    ),
                ),
            ),
        )
    )
    v = _wr(schema)
    [t] = v.tables
    assert t.verdict == "unverified"
    assert t.note == "restrictive write floor composed into the proof"


@requires_z3
def test_write_mode_carried_in_json_and_sarif() -> None:
    schema = Schema(
        tables=(
            _table(
                "t",
                policies=(
                    _policy(
                        None,
                        command="INSERT",
                        with_check="is_public OR tenant_id = (select auth.uid())",
                    ),
                ),
            ),
        )
    )
    v = _wr(schema)
    payload = json.loads(render_json(v))
    assert payload["mode"] == "write"
    scopes = [
        p["witness_scope"]
        for tbl in payload["tables"]
        for p in tbl["policies"]
    ]
    assert "any_other_tenant" in scopes or "row" in scopes
    sarif = json.loads(render_sarif(v))
    rule_ids = {
        r["ruleId"] for r in sarif["runs"][0]["results"]
    }
    assert rule_ids == {"pgrls-write-isolation"}


@requires_z3
def test_cross_tenant_scoped_policy_is_proven() -> None:
    schema = Schema(tables=(_table("t", policies=(_policy("tenant_id = auth.uid()"),)),))
    assert _verdict(_xt(schema), "public.t") == "isolated"


@requires_z3
def test_cross_tenant_cast_scoping_is_proven() -> None:
    # The exact predicate `pgrls generate` emits — the cast is a no-op (uuid →
    # String) so the auth value stays a session symbol and the proof holds.
    schema = Schema(
        tables=(
            _table(
                "t",
                policies=(
                    _policy("tenant_id = current_setting('app.tenant_id', true)::uuid"),
                ),
            ),
        )
    )
    assert _verdict(_xt(schema), "public.t") == "isolated"


@requires_z3
def test_cross_tenant_or_public_is_leak_with_row_witness() -> None:
    # An `OR is_public` bypass exposes another tenant's public rows.
    schema = Schema(
        tables=(_table("t", policies=(_policy("tenant_id = auth.uid() OR is_public"),)),)
    )
    v = _xt(schema)
    [t] = v.tables
    leak = next(p for p in t.proofs if p.verdict == "leak")
    assert t.verdict == "leak"
    assert leak.witness == {"is_public": True}


@requires_z3
def test_cross_tenant_or_any_array_public_is_leak() -> None:
    # The `= ANY(ARRAY[...])` analog of the `OR is_public` bypass: an unscoped
    # membership disjunct exposes another tenant's matching rows. Was UNVERIFIED
    # before the membership encoding; now a proven leak with a row witness.
    schema = Schema(
        tables=(
            _table(
                "t",
                policies=(
                    _policy("tenant_id = auth.uid() OR status = ANY(ARRAY['public'])"),
                ),
            ),
        )
    )
    v = _xt(schema)
    [t] = v.tables
    assert t.verdict == "leak"
    leak = next(p for p in t.proofs if p.verdict == "leak")
    assert leak.witness == {"status": "public"}


@requires_z3
def test_cross_tenant_admin_bypass_is_conditional_leak() -> None:
    # An admin disjunct lets an admin session read every tenant, but the leak
    # is conditional on the SESSION's role (not any row column) — so the row
    # witness is not self-sufficient → conditional leak (witness None), not an
    # over-claiming row.
    schema = Schema(
        tables=(
            _table(
                "t",
                policies=(_policy("tenant_id = auth.uid() OR auth.role() = 'admin'"),),
            ),
        )
    )
    v = _xt(schema)
    [t] = v.tables
    [p] = t.proofs
    assert t.verdict == "leak"
    assert p.witness is None


@requires_z3
def test_cross_tenant_witness_not_over_claimed_on_opaque_conjunct() -> None:
    # A bypass disjunct gated by an opaque runtime value
    # (`is_public AND current_setting(...) = 'x'`) is a real leak, but pinning
    # `is_public=True` alone does NOT force it — the row witness must NOT
    # over-claim. The sufficiency gate downgrades it to a conditional leak.
    schema = Schema(
        tables=(
            _table(
                "t",
                policies=(
                    _policy(
                        "tenant_id = auth.uid() "
                        "OR (is_public AND current_setting('app.x') = 'y')"
                    ),
                ),
            ),
        )
    )
    v = _xt(schema)
    [t] = v.tables
    [p] = t.proofs
    assert t.verdict == "leak"
    assert p.witness is None  # NOT {"is_public": True} — that would over-claim


@requires_z3
def test_cross_tenant_unconditional_bypass_is_any_other_tenant() -> None:
    # A disjunct that is unconditionally true alongside the scoping equality
    # exposes every other-tenant row with no row condition → empty witness,
    # rendered as the `any_other_tenant` scope.
    schema = Schema(tables=(_table("t", policies=(_policy("tenant_id = auth.uid() OR true"),)),))
    v = _xt(schema)
    [t] = v.tables
    [p] = t.proofs
    assert t.verdict == "leak"
    assert p.witness == {}


@requires_z3
def test_cross_tenant_hardcoded_tenant_pins_witness() -> None:
    # A hardcoded other-tenant disjunct pins the leak to that one tenant value
    # (the discriminator IS characterizing here, unlike the don't-care cases).
    tid = "00000000-0000-0000-0000-000000000000"
    schema = Schema(
        tables=(
            _table(
                "t",
                policies=(_policy(f"tenant_id = auth.uid() OR tenant_id = '{tid}'"),),
            ),
        )
    )
    v = _xt(schema)
    [t] = v.tables
    leak = next(p for p in t.proofs if p.verdict == "leak")
    assert t.verdict == "leak"
    assert leak.witness == {"tenant_id": tid}


@requires_z3
def test_cross_tenant_inverted_auth_is_proven_complementary() -> None:
    # THE headline: the inverted-auth policy is an anon LEAK but cross-tenant
    # ISOLATED — an authenticated tenant only sees its own rows (the IS NULL
    # branch is false when authenticated). The two modes are complementary.
    schema = Schema(
        tables=(
            _table(
                "t",
                policies=(_policy("auth.uid() IS NULL OR tenant_id = auth.uid()"),),
            ),
        )
    )
    assert _verdict(build_verification(schema), "public.t") == "leak"  # anon
    assert _verdict(_xt(schema), "public.t") == "isolated"  # cross-tenant


@requires_z3
def test_cross_tenant_using_true_is_unverified_not_leak() -> None:
    # USING(true) has no scoping equality → cross-tenant makes no claim (it is
    # already caught as an anon leak). Soundness: never a false isolated.
    schema = Schema(tables=(_table("t", policies=(_policy("true"),)),))
    v = _xt(schema)
    assert _verdict(v, "public.t") == "unverified"
    assert not v.has_leak


@requires_z3
def test_cross_tenant_multi_axis_is_unverified() -> None:
    # Two distinct scoping equalities (different columns) → no single tenant
    # axis → unverified. Conservative: soundness over recall.
    schema = Schema(
        tables=(
            _table(
                "t",
                policies=(_policy("tenant_id = auth.uid() OR org_id = auth.uid()"),),
            ),
        )
    )
    assert _verdict(_xt(schema), "public.t") == "unverified"


@requires_z3
def test_cross_tenant_undecidable_predicate_is_unverified() -> None:
    # An untranslatable predicate → no claim (the verifier degrades to the
    # linter), same as anon mode.
    schema = Schema(
        tables=(
            _table(
                "t",
                policies=(
                    _policy(
                        "tenant_id = ANY(string_to_array(current_setting('x'), ','))"
                    ),
                ),
            ),
        )
    )
    assert _verdict(_xt(schema), "public.t") == "unverified"


@requires_z3
def test_cross_tenant_scoped_is_anon_unverified_or_proven() -> None:
    # The plain scoped policy `tenant_id = auth.uid()` is cross-tenant PROVEN;
    # under anon it is also isolated (auth.uid() NULL → tenant_id = NULL is U,
    # no row visible). Pin both so the modes don't accidentally converge wrong.
    schema = Schema(tables=(_table("t", policies=(_policy("tenant_id = auth.uid()"),)),))
    assert _verdict(build_verification(schema), "public.t") == "isolated"
    assert _verdict(_xt(schema), "public.t") == "isolated"


# --- cross-tenant int/bigint tenant recall ---------------------------------


@requires_z3
def test_cross_tenant_int_session_cast_is_proven_isolated() -> None:
    # Recall: a sort-changing cast on the session identity
    # (`current_setting(...)::bigint`/`::int` — the predicate pgrls generate
    # emits for an integer/bigint tenant column) is now cross-tenant PROVEN
    # rather than degrading to UNVERIFIED. uuid/text already worked (those
    # casts preserve the String sort, so no session marker was lost).
    for cast in ("bigint", "int", "integer", "smallint"):
        using = f"tenant_id = current_setting('app.tenant_id', true)::{cast}"
        schema = Schema(tables=(_table("t", policies=(_policy(using),)),))
        assert _verdict(_xt(schema), "public.t") == "isolated", cast


@requires_z3
def test_cross_tenant_int_session_cast_leak_is_detected() -> None:
    # The same int-cast identity with an `OR is_public` bypass is a real
    # cross-tenant LEAK — previously invisible (the policy was UNVERIFIED).
    using = "tenant_id = current_setting('app.tenant_id', true)::bigint OR is_public"
    schema = Schema(tables=(_table("t", policies=(_policy(using),)),))
    v = _xt(schema)
    assert _verdict(v, "public.t") == "leak"
    assert v.has_leak


@requires_z3
def test_int_session_cast_anon_path_unchanged() -> None:
    # The recall fork is gated on session_mode, so the anon verdict for an
    # int-cast scoped policy is unchanged: current_setting → NULL under anon,
    # so the equality is never true → no anonymous leak → isolated.
    using = "tenant_id = current_setting('app.tenant_id', true)::bigint"
    schema = Schema(tables=(_table("t", policies=(_policy(using),)),))
    assert _verdict(build_verification(schema), "public.t") == "isolated"


@requires_z3
def test_int_session_cast_recall_is_non_vacuous() -> None:
    # The recall must be REAL, not vacuous: an int/bigint-cast scoped policy is
    # `isolated` because the predicate forces same-tenant, NOT because it admits
    # zero rows. Pin (a) exactly one tenant pair is recorded — the cast keeps
    # the session marker — and (b) the cross-tenant `is_true` is satisfiable in
    # isolation: a session CAN see its OWN tenant's rows, so the session
    # identity is a real, non-null value. A regression making the cast a
    # NULL-flagged or opaque symbol would still report `isolated` (vacuously /
    # UNVERIFIED) but fail here.
    import z3  # noqa: PLC0415

    node = _using_ast("tenant_id = current_setting('app.tenant_id', true)::bigint")
    ctx = _Context()
    ctx.session_mode = True
    assertions: list[object] = []
    tv = _lift_to_tv(_anon_3vl(node, ctx, set(_DEFAULT_AUTH_FUNCTIONS), assertions), assertions)
    assert tv is not None
    assert len(_distinct_tenant_pairs(ctx.tenant_pairs)) == 1  # the pair was recorded
    solver = z3.Solver()
    for a in assertions:
        solver.add(a)
    solver.add(tv.is_true)
    assert solver.check() == z3.sat  # the session sees its own rows — not vacuous


@requires_z3
def test_any_array_membership_is_exactly_or_of_equalities() -> None:
    # Soundness heart: `x = ANY(ARRAY[a,b,c])` is encoded as the EXACT
    # desugaring `x = a OR x = b OR x = c`, not an approximation. Build both in
    # ONE context (so `x` and the literals share Z3 vars) and assert their
    # Kleene truth AND null are logically equivalent (the negation is UNSAT) —
    # the membership branch can never drift from a hand-written OR chain.
    import z3  # noqa: PLC0415

    # Cover both the bare-literal form and the per-element-cast form that
    # `pg_get_expr` actually emits for an introspected `IN (…)`
    # (`= ANY (ARRAY['a'::text, 'b'::text])`) — the cast elements must resolve
    # through the same path as the hand-written `=`.
    pairs = (
        ("x = ANY(ARRAY[1,2,3])", "x = 1 OR x = 2 OR x = 3"),
        (
            "x = ANY(ARRAY['a'::text,'b'::text])",
            "x = 'a'::text OR x = 'b'::text",
        ),
    )
    for any_sql, or_sql in pairs:
        ctx = _Context()
        assertions: list[object] = []
        any_tv = _anon_3vl(_using_ast(any_sql), ctx, set(), assertions)
        or_tv = _anon_3vl(_using_ast(or_sql), ctx, set(), assertions)
        assert any_tv is not None and or_tv is not None
        solver = z3.Solver()
        for a in assertions:
            solver.add(a)
        for field in ("is_true", "is_null"):
            solver.push()
            solver.add(z3.Not(getattr(any_tv, field) == getattr(or_tv, field)))
            assert solver.check() == z3.unsat, (
                f"{field} of {any_sql!r} must match the OR chain"
            )
            solver.pop()


# --- cross-tenant renderers ------------------------------------------------


@requires_z3
def test_cross_tenant_render_text_phrasing() -> None:
    schema = Schema(
        tables=(
            _table("safe", policies=(_policy("tenant_id = auth.uid()"),)),
            _table("leaky", policies=(_policy("tenant_id = auth.uid() OR is_public"),)),
        )
    )
    out = render_text(_xt(schema))
    assert "no cross-tenant read" in out
    assert "a row of another tenant with is_public=True is readable" in out
    # the anon-only phrasings must NOT appear in cross-tenant output
    assert "anonymously readable" not in out


def test_cross_tenant_witness_phrase_unconditional_says_any_other_tenant() -> None:
    # The unconditional cross-tenant leak ({} witness) must read "a row of ANY
    # other tenant" — matching the emitted repro (repro.py) and the README.
    # Regression: verify.py once said "another tenant" here while repro/README
    # said "any other tenant", diverging for the same verdict across surfaces.
    assert (
        _witness_phrase({}, mode="cross-tenant")
        == "a row of any other tenant is readable"
    )
    # the characterizing-row and conditional branches are unchanged
    assert _witness_phrase({"is_public": True}, mode="cross-tenant") == (
        "a row of another tenant with is_public=True is readable"
    )
    assert _witness_phrase(None, mode="cross-tenant") == (
        "a conditional cross-tenant leak — no single row characterizes it"
    )


@requires_z3
def test_cross_tenant_render_json_mode_and_scope() -> None:
    schema = Schema(
        tables=(
            _table("u", policies=(_policy("tenant_id = auth.uid() OR true"),)),
        )
    )
    payload = json.loads(render_json(_xt(schema)))
    assert payload["mode"] == "cross-tenant"
    p = payload["tables"][0]["policies"][0]
    assert p["witness_scope"] == "any_other_tenant"
    assert p["witness"] == {}


def test_anon_render_json_records_mode() -> None:
    # Regression: the default mode is recorded in JSON (no Z3 needed — a
    # policy-free table is trivially isolated).
    payload = json.loads(
        render_json(build_verification(Schema(tables=(_table("t", policies=()),))))
    )
    assert payload["mode"] == "anon"


# --- cross-tenant CLI ------------------------------------------------------


def test_verify_cli_mode_option_in_help() -> None:
    result = CliRunner().invoke(main, ["verify", "--help"])
    assert result.exit_code == 0
    assert "--mode" in result.output and "cross-tenant" in result.output


@requires_docker
@requires_z3
def test_verify_cli_emit_repro_cross_tenant(
    pg_url: str, pg_conn: psycopg.Connection, tmp_path: Path
) -> None:
    # `--mode cross-tenant --emit-repro` writes a cross-tenant reproduction for
    # each leak (exit 1) — it is no longer rejected.
    with pg_conn.cursor() as cur:
        cur.execute(_AUTH_STUB)
        cur.execute(
            "CREATE TABLE public.docs "
            "  (id bigint PRIMARY KEY, tenant_id uuid, is_public boolean);"
            "ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;"
            "ALTER TABLE public.docs FORCE ROW LEVEL SECURITY;"
            "CREATE POLICY p ON public.docs FOR SELECT TO public "
            "  USING (tenant_id = auth.uid() OR is_public);"
        )
    out = tmp_path / "xt"
    result = CliRunner().invoke(
        main,
        [
            "verify", "--mode", "cross-tenant", "--database-url", pg_url,
            "--schemas", "public", "--emit-repro", str(out),
        ],
    )
    assert result.exit_code == 1, result.output  # leak → exit 1
    sqlf = out / "public_docs_p.sql"
    assert sqlf.exists()
    body = sqlf.read_text()
    assert "cross-tenant leak reproduction" in body
    assert "set_config('request.jwt.claim.sub'" in body


@requires_docker
@requires_z3
def test_verify_cli_live_cross_tenant_leak_exits_one(
    pg_url: str, pg_conn: psycopg.Connection
) -> None:
    # End-to-end: an `OR is_public` bypass is a cross-tenant LEAK → exit 1, and
    # the report frames the row as another tenant's.
    with pg_conn.cursor() as cur:
        cur.execute(_AUTH_STUB)
        cur.execute(
            "CREATE TABLE public.docs "
            "  (id bigint PRIMARY KEY, tenant_id uuid, is_public boolean);"
            "ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;"
            "ALTER TABLE public.docs FORCE ROW LEVEL SECURITY;"
            "CREATE POLICY p ON public.docs FOR SELECT TO public "
            "  USING (tenant_id = auth.uid() OR is_public);"
        )
    result = CliRunner().invoke(
        main,
        [
            "verify",
            "--mode",
            "cross-tenant",
            "--database-url",
            pg_url,
            "--schemas",
            "public",
        ],
    )
    assert result.exit_code == 1, result.output
    assert "LEAK" in result.output and "another tenant" in result.output


@requires_docker
@requires_z3
def test_verify_live_cross_tenant_scoped_is_isolated(
    pg_conn: psycopg.Connection,
) -> None:
    # The gold-standard `pgrls generate` shape is cross-tenant PROVEN end-to-end.
    with pg_conn.cursor() as cur:
        cur.execute(_AUTH_STUB)
        cur.execute(
            "CREATE TABLE public.acct (id bigint PRIMARY KEY, tenant_id uuid);"
            "ALTER TABLE public.acct ENABLE ROW LEVEL SECURITY;"
            "ALTER TABLE public.acct FORCE ROW LEVEL SECURITY;"
            "CREATE POLICY p ON public.acct FOR SELECT TO public "
            "  USING (tenant_id = (select auth.uid()));"
        )
    schema = introspect(pg_conn, schemas=["public"])
    assert _verdict(_xt(schema), "public.acct") == "isolated"


# --- escalation mode (SEC048 owner-reachability) ---------------------------


def _owned(
    name: str,
    owner: str,
    *,
    force: bool = False,
    policies: tuple[Policy, ...] = (),
    rls: bool = True,
) -> Table:
    """A table with an explicit owner + FORCE flag, for escalation tests."""
    return Table(
        schema="public",
        name=name,
        rls_enabled=rls,
        force_rls=force,
        owner=owner,
        policies=policies,
    )


def _reach(*members_to_owners: tuple[str, tuple[str, ...]]) -> tuple[OwnerReachableMember, ...]:
    return tuple(
        OwnerReachableMember(member=m, via_owners=owners, member_can_login=True)
        for m, owners in members_to_owners
    )


def _esc(schema: Schema) -> Verification:
    return build_verification(schema, mode="escalation")


@requires_z3
def test_escalation_isolated_table_reachable_owner_is_leak() -> None:
    # A cross-tenant-isolated table owned by a reachable owner, not FORCE'd:
    # the reachable low-trust role bypasses the proven isolation -> LEAK.
    schema = Schema(
        tables=(_owned("docs", "app_owner", policies=(_policy("tenant_id = auth.uid()"),)),),
        owner_reachable_members=_reach(("lowtrust", ("app_owner",))),
    )
    v = _esc(schema)
    assert v.mode == "escalation"
    assert _verdict(v, "public.docs") == "leak"
    assert v.has_leak
    [t] = v.tables
    # The reaching role + owner are carried in the note (surfaced in text/sarif).
    assert t.note is not None and "lowtrust" in t.note and "app_owner" in t.note
    [proof] = t.proofs
    assert proof.witness == {}  # every row (unconditional bypass)


@requires_z3
def test_escalation_forced_table_is_no_finding() -> None:
    # FORCE'd: the owner is itself RLS-scoped -> no bypass (SEC048 wouldn't fire).
    schema = Schema(
        tables=(
            _owned("docs", "app_owner", force=True, policies=(_policy("tenant_id = auth.uid()"),)),
        ),
        owner_reachable_members=_reach(("lowtrust", ("app_owner",))),
    )
    assert _esc(schema).tables == ()


@requires_z3
def test_escalation_owner_not_reachable_is_no_finding() -> None:
    # No low-trust role reaches this table's owner -> not a candidate.
    schema = Schema(
        tables=(_owned("docs", "other_owner", policies=(_policy("tenant_id = auth.uid()"),)),),
        owner_reachable_members=_reach(("lowtrust", ("app_owner",))),
    )
    assert _esc(schema).tables == ()


@requires_z3
def test_escalation_default_deny_table_is_leak() -> None:
    # RLS on, no permissive policy (default-deny — the strongest isolation):
    # the owner bypass exposes every row the default-deny hid -> LEAK.
    schema = Schema(
        tables=(_owned("docs", "app_owner", policies=()),),
        owner_reachable_members=_reach(("lowtrust", ("app_owner",))),
    )
    assert _verdict(_esc(schema), "public.docs") == "leak"


@requires_z3
def test_escalation_non_scoping_policy_is_unverified() -> None:
    # USING(true) has no provable tenant-scoping equality -> the cross-tenant
    # prover abstains, so escalation cannot prove a cross-tenant leak -> UNVERIFIED.
    schema = Schema(
        tables=(_owned("docs", "app_owner", policies=(_policy("true"),)),),
        owner_reachable_members=_reach(("lowtrust", ("app_owner",))),
    )
    assert _verdict(_esc(schema), "public.docs") == "unverified"


@requires_z3
def test_escalation_partial_cross_tenant_leak_is_still_a_leak() -> None:
    # The policy is scoped but only PARTIALLY leaks cross-tenant (an is_public
    # escape): a direct cross-tenant session reads only the public rows, but the
    # owner bypass reads EVERY row — incl. the other tenants' private rows. The
    # bypass therefore exposes strictly more than the cross-tenant leak -> LEAK,
    # not a false "exposes nothing new" clear.
    schema = Schema(
        tables=(
            _owned("docs", "app_owner", policies=(_policy("tenant_id = auth.uid() OR is_public"),)),
        ),
        owner_reachable_members=_reach(("lowtrust", ("app_owner",))),
    )
    [t] = _esc(schema).tables
    assert t.verdict == "leak"
    assert t.note is not None and "non-public" in t.note  # explains the excess


@requires_z3
def test_escalation_total_cross_tenant_leak_is_ceded_isolated() -> None:
    # The policy leaks EVERY row cross-tenant (an `OR true` tautology — the
    # prover's witness is {}): the RLS already exposes all rows to a direct
    # session, so the owner bypass exposes nothing new -> ISOLATED, ceded to
    # verify --mode cross-tenant.
    schema = Schema(
        tables=(
            _owned("docs", "app_owner", policies=(_policy("tenant_id = auth.uid() OR true"),)),
        ),
        owner_reachable_members=_reach(("lowtrust", ("app_owner",))),
    )
    [t] = _esc(schema).tables
    assert t.verdict == "isolated"
    assert t.note is not None and "every row cross-tenant" in t.note


@requires_z3
def test_escalation_rls_off_table_is_no_finding() -> None:
    schema = Schema(
        tables=(_owned("docs", "app_owner", rls=False, policies=()),),
        owner_reachable_members=_reach(("lowtrust", ("app_owner",))),
    )
    assert _esc(schema).tables == ()


@requires_z3
def test_escalation_lists_all_reaching_roles() -> None:
    schema = Schema(
        tables=(_owned("docs", "app_owner", policies=(_policy("tenant_id = auth.uid()"),)),),
        owner_reachable_members=_reach(
            ("anon", ("app_owner",)), ("authenticated", ("app_owner",))
        ),
    )
    [t] = _esc(schema).tables
    assert t.note is not None and "anon" in t.note and "authenticated" in t.note


def test_escalation_empty_result_renders_mode_specific_message() -> None:
    schema = Schema(tables=(), owner_reachable_members=())
    assert "No reachable escalation paths" in render_text(_esc(schema))


@requires_z3
def test_escalation_text_and_sarif_surface_the_path() -> None:
    schema = Schema(
        tables=(_owned("docs", "app_owner", policies=(_policy("tenant_id = auth.uid()"),)),),
        owner_reachable_members=_reach(("lowtrust", ("app_owner",))),
    )
    v = _esc(schema)
    text = render_text(v)
    assert "LEAK" in text and "app_owner" in text and "lowtrust" in text
    sarif = json.loads(render_sarif(v))
    [result] = sarif["runs"][0]["results"]
    assert result["ruleId"] == "pgrls-escalation-isolation"
    assert result["level"] == "error"
    assert "app_owner" in result["message"]["text"]


# --- escalation mode: SEC042 anon-callable SECDEF bodies -------------------


def _anon_tbl(name: str, using: str) -> Table:
    return Table(
        schema="public",
        name=name,
        rls_enabled=True,
        force_rls=False,
        policies=(_policy(using),),
    )


def _secdef(
    body: str,
    *,
    qname: str = "public.read_secret",
    roles: tuple[str, ...] = ("anon",),
    bypass: bool = True,
    lang: str = "sql",
) -> SecdefFunction:
    return SecdefFunction(
        qualified_name=qname, body=body, language=lang,
        execute_roles=roles, owner_bypasses_rls=bypass,
    )


@requires_z3
def test_escalation_anon_secdef_reading_isolated_table_is_leak() -> None:
    # An anon-EXECUTE-able SECURITY DEFINER function owned by an RLS-exempt role
    # whose body reads an anon-ISOLATED table → an anon caller reads rows its
    # own RLS would deny → LEAK.
    schema = Schema(
        tables=(_anon_tbl("secret", "tenant_id = auth.uid()"),),
        security_definer_functions=(_secdef("SELECT * FROM secret"),),
    )
    [t] = build_verification(schema, mode="escalation").tables
    assert t.qualified_name == "public.read_secret"
    assert t.verdict == "leak"
    assert t.note is not None and "SECURITY DEFINER" in t.note and "anon" in t.note
    assert "secret" in t.note


@requires_z3
def test_escalation_opaque_plpgsql_secdef_is_unverified() -> None:
    schema = Schema(
        tables=(_anon_tbl("secret", "tenant_id = auth.uid()"),),
        security_definer_functions=(_secdef("BEGIN RETURN; END", lang="plpgsql"),),
    )
    [t] = build_verification(schema, mode="escalation").tables
    assert t.verdict == "unverified"
    assert t.note is not None and "opaque" in t.note


@requires_z3
def test_escalation_secdef_not_anon_executable_is_no_finding() -> None:
    schema = Schema(
        tables=(_anon_tbl("secret", "tenant_id = auth.uid()"),),
        security_definer_functions=(_secdef("SELECT * FROM secret", roles=("authenticated",)),),
    )
    assert build_verification(schema, mode="escalation").tables == ()


@requires_z3
def test_escalation_secdef_owner_not_rls_exempt_is_no_finding() -> None:
    schema = Schema(
        tables=(_anon_tbl("secret", "tenant_id = auth.uid()"),),
        security_definer_functions=(_secdef("SELECT * FROM secret", bypass=False),),
    )
    assert build_verification(schema, mode="escalation").tables == ()


@requires_z3
def test_escalation_secdef_reading_total_anon_leak_is_ceded_isolated() -> None:
    # The read table already leaks every row to anon (USING true), so the
    # function exposes nothing new → ISOLATED (ceded to verify --mode anon).
    schema = Schema(
        tables=(_anon_tbl("secret", "true"),),
        security_definer_functions=(_secdef("SELECT * FROM secret"),),
    )
    [t] = build_verification(schema, mode="escalation").tables
    assert t.verdict == "isolated"
    assert t.note is not None and "nothing new" in t.note


@requires_z3
def test_escalation_secdef_reading_partial_anon_leak_is_leak() -> None:
    # The read table only partially leaks to anon (is_public rows); the SECDEF
    # bypass exposes the rest → LEAK.
    schema = Schema(
        tables=(_anon_tbl("secret", "is_public"),),
        security_definer_functions=(_secdef("SELECT * FROM secret"),),
    )
    [t] = build_verification(schema, mode="escalation").tables
    assert t.verdict == "leak"


@requires_z3
def test_escalation_combines_owner_and_secdef_findings() -> None:
    # One escalation run surfaces both an owner-reachability LEAK and a SECDEF
    # LEAK, sorted by location.
    schema = Schema(
        tables=(
            _owned("docs", "app_owner", policies=(_policy("tenant_id = auth.uid()"),)),
            _anon_tbl("secret", "tenant_id = auth.uid()"),
        ),
        owner_reachable_members=_reach(("lowtrust", ("app_owner",))),
        security_definer_functions=(_secdef("SELECT * FROM secret"),),
    )
    v = build_verification(schema, mode="escalation")
    locs = {t.qualified_name: t.verdict for t in v.tables}
    assert locs == {"public.docs": "leak", "public.read_secret": "leak"}


@requires_z3
def test_escalation_opaque_overload_blocks_isolated_cede() -> None:
    # Two anon-exposed RLS-exempt overloads of one function: the analyzable SQL
    # body reads a table anon already leaks totally (would cede to ISOLATED),
    # but the sibling PL/pgSQL overload is opaque and might read a different
    # protected table — so the function must NOT be cleared. UNVERIFIED, not a
    # false ISOLATED.
    schema = Schema(
        tables=(_anon_tbl("secret", "true"),),
        security_definer_functions=(
            _secdef("SELECT * FROM secret", qname="public.f"),
            _secdef("BEGIN RETURN; END", qname="public.f", lang="plpgsql"),
        ),
    )
    [t] = build_verification(schema, mode="escalation").tables
    assert t.qualified_name == "public.f"
    assert t.verdict == "unverified"
    assert t.note is not None and "opaque" in t.note


def _view(name: str, base: str = "secret") -> "View":
    return View(
        schema="public", name=name, is_materialized=False,
        security_invoker=False, security_barrier=False,
        definition=f"SELECT * FROM {base}", references=(("public", base),),
        security_definer_calls=(),
    )


@requires_z3
def test_escalation_secdef_reading_via_view_is_unverified_not_cleared() -> None:
    # A SECDEF body that reads an RLS table THROUGH A VIEW (the dominant
    # PostgREST/Supabase shape) must not be silently cleared — the view is a
    # source we can't see through, so abstain (UNVERIFIED), never "no finding".
    schema = Schema(
        tables=(_anon_tbl("secret", "tenant_id = auth.uid()"),),
        views=(_view("secret_view"),),
        security_definer_functions=(_secdef("SELECT * FROM secret_view"),),
    )
    [t] = build_verification(schema, mode="escalation").tables
    assert t.verdict == "unverified"
    assert t.note is not None and "view" in t.note


@requires_z3
def test_escalation_secdef_reading_via_function_call_is_unverified() -> None:
    # A set-returning function call in FROM is a source we can't see through.
    schema = Schema(
        tables=(_anon_tbl("secret", "tenant_id = auth.uid()"),),
        security_definer_functions=(_secdef("SELECT * FROM inner_reader()"),),
    )
    [t] = build_verification(schema, mode="escalation").tables
    assert t.verdict == "unverified"


@requires_z3
def test_escalation_secdef_scalar_function_call_read_is_unverified() -> None:
    # SOUNDNESS: a scalar function call (`SELECT get_secret()`) is a data source
    # the range-var walk never surfaces — get_secret may read a protected table
    # through the SECDEF owner's bypass. It must abstain (UNVERIFIED), not be
    # silently cleared. (A `RangeFunction` in FROM was already abstained; a
    # scalar `FuncCall` in the target list / WHERE was not.)
    for body in (
        "SELECT get_secret()",
        "SELECT 1 WHERE secret_leaks()",
        "SELECT coalesce(get_secret(), 0)",
    ):
        schema = Schema(
            tables=(_anon_tbl("secret", "tenant_id = auth.uid()"),),
            security_definer_functions=(_secdef(body),),
        )
        [t] = build_verification(schema, mode="escalation").tables
        assert t.verdict == "unverified", body


@requires_z3
def test_escalation_secdef_auth_call_in_body_does_not_block_a_real_read() -> None:
    # Recall preserved: an auth/session call (`auth.uid()`) does not read a user
    # table, so it must NOT trigger the scalar-call abstention — a body that
    # directly reads an isolated table while filtering on auth.uid() is still a
    # proven LEAK, not downgraded to UNVERIFIED.
    schema = Schema(
        tables=(_anon_tbl("secret", "tenant_id = auth.uid()"),),
        security_definer_functions=(
            _secdef("SELECT * FROM secret WHERE tenant_id = auth.uid()"),
        ),
    )
    [t] = build_verification(schema, mode="escalation").tables
    assert t.verdict == "leak"


@requires_z3
def test_escalation_secdef_reading_only_non_rls_table_is_no_finding() -> None:
    # Precision retained: a body whose every source is a known NON-RLS base
    # table provably reads no protected data → not a finding (not UNVERIFIED).
    public_cfg = Table(
        schema="public", name="app_config", rls_enabled=False,
        force_rls=False, policies=(),
    )
    schema = Schema(
        tables=(_anon_tbl("secret", "tenant_id = auth.uid()"), public_cfg),
        security_definer_functions=(_secdef("SELECT * FROM app_config"),),
    )
    assert build_verification(schema, mode="escalation").tables == ()


@requires_z3
def test_escalation_secdef_bare_builtin_over_non_rls_table_is_no_finding() -> None:
    # A bare built-in (`count`) reads no user table — an introspected body stores
    # builtins UNqualified, so the opaque-funccall check must recognize them or
    # it would wrongly abstain (UNVERIFIED) on a benign `SELECT count(*) FROM
    # <non-RLS table>`. Still no finding, not UNVERIFIED.
    public_cfg = Table(
        schema="public", name="app_config", rls_enabled=False,
        force_rls=False, policies=(),
    )
    for body in ("SELECT count(*) FROM app_config", "SELECT max(id) FROM app_config"):
        schema = Schema(
            tables=(_anon_tbl("secret", "tenant_id = auth.uid()"), public_cfg),
            security_definer_functions=(_secdef(body),),
        )
        assert build_verification(schema, mode="escalation").tables == (), body


@requires_z3
def test_escalation_honors_configured_anon_roles() -> None:
    # SEC042's anon_roles is configurable; escalation must honor it. A function
    # EXECUTE-able only by a renamed anon role (web_anon) is missed under the
    # default {anon, PUBLIC} but proven when web_anon is the configured set.
    schema = Schema(
        tables=(_anon_tbl("secret", "tenant_id = auth.uid()"),),
        security_definer_functions=(
            _secdef("SELECT * FROM secret", roles=("web_anon",)),
        ),
    )
    assert build_verification(schema, mode="escalation").tables == ()
    [t] = build_verification(
        schema, mode="escalation", anon_roles={"web_anon"}
    ).tables
    assert t.verdict == "leak"


@requires_z3
def test_escalation_same_named_cte_shadowing_rls_table_is_unverified() -> None:
    # `WITH secret AS (SELECT * FROM secret) ...` — the body parser treats the
    # bare ref as the CTE and hides the real read of the protected table inside
    # the CTE definition. A CTE whose name collides with a base table is a blind
    # spot → abstain (UNVERIFIED), never silently clear a real leak.
    schema = Schema(
        tables=(_anon_tbl("secret", "tenant_id = auth.uid()"),),
        security_definer_functions=(
            _secdef("WITH secret AS (SELECT * FROM secret) SELECT * FROM secret"),
        ),
    )
    [t] = build_verification(schema, mode="escalation").tables
    assert t.verdict == "unverified"


@requires_z3
def test_escalation_cte_name_does_not_bleed_across_statements() -> None:
    # A CTE defined in statement 1 must not suppress a same-named *relation* ref
    # in statement 2 (CTE scope is per-statement). Here statement 2 reads an
    # unseen view → UNVERIFIED, not a silent clear.
    schema = Schema(
        tables=(_anon_tbl("secret", "tenant_id = auth.uid()"),),
        views=(_view("secret_view"),),
        security_definer_functions=(
            _secdef("WITH secret_view AS (SELECT 1) SELECT 1; SELECT * FROM secret_view"),
        ),
    )
    [t] = build_verification(schema, mode="escalation").tables
    assert t.verdict == "unverified"


@requires_z3
def test_escalation_benign_cte_over_base_table_still_resolves() -> None:
    # A CTE whose name does NOT collide with a base table, reading only a known
    # non-RLS base table, is still provably clean → no finding (no over-abstain).
    public_cfg = Table(
        schema="public", name="app_config", rls_enabled=False,
        force_rls=False, policies=(),
    )
    schema = Schema(
        tables=(_anon_tbl("secret", "tenant_id = auth.uid()"), public_cfg),
        security_definer_functions=(
            _secdef("WITH cfg AS (SELECT * FROM app_config) SELECT * FROM cfg"),
        ),
    )
    assert build_verification(schema, mode="escalation").tables == ()


@requires_z3
def test_escalation_qualified_read_inside_shadowing_cte_is_leak() -> None:
    # If the read inside a same-named CTE is schema-QUALIFIED, the body parser
    # resolves it unambiguously to the RLS table (the shadow only affects bare
    # refs) → proven LEAK, the stronger correct verdict (not just UNVERIFIED).
    schema = Schema(
        tables=(_anon_tbl("secret", "tenant_id = auth.uid()"),),
        security_definer_functions=(
            _secdef(
                "WITH secret AS (SELECT * FROM public.secret) SELECT * FROM secret"
            ),
        ),
    )
    [t] = build_verification(schema, mode="escalation").tables
    assert t.verdict == "leak"


@requires_z3
def test_escalation_secdef_leak_renders_in_text_and_sarif() -> None:
    # A SEC042 SECDEF LEAK and an opaque-body UNVERIFIED render correctly across
    # text and SARIF (SARIF: LEAK is one error result at the function, located
    # via logicalLocations; the UNVERIFIED is omitted by default and a note
    # under --strict — its ruleId defined in the driver).
    schema = Schema(
        tables=(_anon_tbl("secret", "tenant_id = auth.uid()"),),
        security_definer_functions=(
            _secdef("SELECT * FROM secret", qname="public.read_iso"),
            _secdef("BEGIN END", qname="public.opaque_fn", lang="plpgsql"),
        ),
    )
    v = build_verification(schema, mode="escalation")
    text = render_text(v)
    assert "public.read_iso" in text and "LEAK" in text
    assert "public.opaque_fn" in text and "UNVERIFIED" in text

    run = json.loads(render_sarif(v))["runs"][0]
    leaks = [r for r in run["results"] if r["level"] == "error"]
    assert len(leaks) == 1
    assert leaks[0]["ruleId"] == "pgrls-escalation-isolation"
    fqn = leaks[0]["locations"][0]["logicalLocations"][0]["fullyQualifiedName"]
    assert fqn.startswith("public.read_iso")
    # default: the UNVERIFIED opaque fn is not a result
    assert all("opaque_fn" not in json.dumps(r) for r in run["results"])

    strict = json.loads(render_sarif(v, strict=True))["runs"][0]
    notes = [r for r in strict["results"] if r["level"] == "note"]
    assert len(notes) == 1 and "opaque_fn" in json.dumps(notes[0])
    defined = {r["id"] for r in strict["tool"]["driver"]["rules"]}
    assert all(r["ruleId"] in defined for r in strict["results"])


# --- verify --against : leak diff / "no new provable leak" PR gate ----------


def _iso_schema() -> Schema:
    return Schema(
        tables=(_table("docs", policies=(_policy("tenant_id = auth.uid()", command="SELECT"),)),)
    )


def _leak_schema() -> Schema:
    return Schema(
        tables=(
            _table(
                "docs",
                policies=(
                    _policy(
                        "auth.uid() IS NULL OR tenant_id = auth.uid()", command="SELECT"
                    ),
                ),
            ),
        )
    )


@requires_z3
def test_against_reports_a_newly_introduced_leak() -> None:
    delta = diff_verifications(
        build_verification(_iso_schema()), build_verification(_leak_schema())
    )
    assert delta.summary == {
        "new_leaks": 1,
        "preexisting_leaks": 0,
        "fixed_leaks": 0,
        "new_unverified": 0,
    }
    assert delta.new_leaks[0].qualified_name == "public.docs"


@requires_z3
def test_against_a_preexisting_leak_is_not_new() -> None:
    delta = diff_verifications(
        build_verification(_leak_schema()), build_verification(_leak_schema())
    )
    assert delta.summary["new_leaks"] == 0
    assert delta.summary["preexisting_leaks"] == 1


@requires_z3
def test_against_a_fixed_leak_is_reported() -> None:
    delta = diff_verifications(
        build_verification(_leak_schema()), build_verification(_iso_schema())
    )
    assert delta.summary["new_leaks"] == 0
    assert delta.fixed_leaks == ("public.docs",)


@requires_z3
def test_against_a_new_leaking_table_counts_as_new() -> None:
    # base has no RLS tables; head adds a leaking one → the leak is introduced.
    base = build_verification(Schema(tables=(_table("unrelated", rls=False),)))
    delta = diff_verifications(base, build_verification(_leak_schema()))
    assert delta.summary["new_leaks"] == 1


def test_against_base_unverified_is_never_counted_new() -> None:
    # Soundness: a base that could not be PROVEN isolated is not a baseline —
    # a head leak there is pre-existing, never attributed to the change.
    base = Verification(
        (
            TableVerdict(
                "public.docs",
                "unverified",
                None,
                (PolicyProof("p", "unverified", None, "outside fragment"),),
            ),
        ),
        "anon",
    )
    head = Verification(
        (TableVerdict("public.docs", "leak", None, (PolicyProof("p", "leak", {}, None),)),),
        "anon",
    )
    delta = diff_verifications(base, head)
    assert delta.summary["new_leaks"] == 0
    assert delta.summary["preexisting_leaks"] == 1


def test_against_a_leak_that_became_unverified_is_not_reported_fixed() -> None:
    # Symmetric to the base-unverified guard: a base LEAK whose head verdict is
    # merely UNVERIFIED (the change made it unprovable, not proven isolated) is
    # NOT "fixed" — it may still leak. Only a proven-ISOLATED (or dropped) head
    # counts as fixed.
    base = Verification(
        (TableVerdict("public.docs", "leak", None, (PolicyProof("p", "leak", {}, None),)),),
        "anon",
    )
    head = Verification(
        (
            TableVerdict(
                "public.docs",
                "unverified",
                None,
                (PolicyProof("p", "unverified", None, "outside fragment"),),
            ),
        ),
        "anon",
    )
    delta = diff_verifications(base, head)
    assert delta.fixed_leaks == ()
    assert delta.summary["fixed_leaks"] == 0


def test_against_isolated_to_unverified_is_new_unverified() -> None:
    base = Verification((TableVerdict("public.docs", "isolated", None, ()),), "anon")
    head = Verification(
        (
            TableVerdict(
                "public.docs", "unverified", None, (PolicyProof("p", "unverified", None, "r"),)
            ),
        ),
        "anon",
    )
    delta = diff_verifications(base, head)
    assert delta.summary["new_unverified"] == 1
    assert delta.summary["new_leaks"] == 0


@requires_z3
def test_render_delta_text_flags_new_and_clean() -> None:
    dirty = render_delta_text(
        diff_verifications(
            build_verification(_iso_schema()), build_verification(_leak_schema())
        )
    )
    assert "NEW leaks introduced" in dirty and "public.docs" in dirty
    clean = render_delta_text(
        diff_verifications(
            build_verification(_iso_schema()), build_verification(_iso_schema())
        )
    )
    assert "No new leaks introduced" in clean


@requires_z3
def test_render_delta_json_shape() -> None:
    d = json.loads(
        render_delta_json(
            diff_verifications(
                build_verification(_leak_schema()), build_verification(_iso_schema())
            )
        )
    )
    assert d["against"] is True
    assert d["mode"] == "anon"
    assert d["fixed_leaks"] == ["public.docs"]
    assert d["summary"]["new_leaks"] == 0


@requires_z3
def test_verify_against_cli_new_leak_exits_one(tmp_path, monkeypatch) -> None:
    # End-to-end CLI glue, offline: head is the live schema (monkeypatched),
    # base is a committed snapshot. A newly-introduced leak exits 1.
    from pgrls import cli
    from pgrls.config import load_config

    base = tmp_path / "base.json"
    base.write_text(json.dumps(_iso_schema().to_snapshot()), encoding="utf-8")
    cfg = load_config(None)
    monkeypatch.setattr(
        cli, "_connect_and_introspect", lambda **kw: (cfg, _leak_schema())
    )
    result = CliRunner().invoke(
        main, ["verify", "--database-url", "postgres://x", "--against", str(base)]
    )
    assert result.exit_code == 1, result.output
    assert "NEW leaks" in result.output and "public.docs" in result.output


@requires_z3
def test_verify_against_cli_no_new_leak_exits_zero(tmp_path, monkeypatch) -> None:
    # Base already leaks; head leaks the same → nothing NEW → gate passes (0).
    from pgrls import cli
    from pgrls.config import load_config

    base = tmp_path / "base.json"
    base.write_text(json.dumps(_leak_schema().to_snapshot()), encoding="utf-8")
    cfg = load_config(None)
    monkeypatch.setattr(
        cli, "_connect_and_introspect", lambda **kw: (cfg, _leak_schema())
    )
    result = CliRunner().invoke(
        main, ["verify", "--database-url", "postgres://x", "--against", str(base)]
    )
    assert result.exit_code == 0, result.output
    assert "No new leaks introduced" in result.output


@requires_docker
@requires_z3
def test_restrictive_floor_composition_matches_postgres(pg_url: str) -> None:
    # Soundness of the whole-table composition: the composed permissive ∧
    # restrictive verdict must match what a real anonymous session actually
    # sees — a blocking floor → ISOLATED (0 rows), a non-blocking one → LEAK.
    cases = [
        ("USING (true)", "USING (false)", "isolated"),
        ("USING (true)", "USING (tenant_id IS NOT NULL)", "leak"),
        (
            "USING (is_public OR tenant_id = auth.uid())",
            "USING (tenant_id = auth.uid())",
            "isolated",
        ),
    ]
    for perm, floor, expected in cases:
        with psycopg.connect(pg_url, autocommit=True) as conn, conn.cursor() as cur:
            cur.execute("DROP TABLE IF EXISTS t CASCADE;")
            cur.execute(_AUTH_STUB)
            cur.execute(
                "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE "
                "rolname='anon') THEN CREATE ROLE anon NOLOGIN NOSUPERUSER "
                "NOBYPASSRLS; END IF; END $$;"
            )
            cur.execute("CREATE TABLE t (id int, tenant_id uuid, is_public boolean);")
            cur.execute("GRANT SELECT ON t TO anon;")
            cur.execute(
                "ALTER TABLE t ENABLE ROW LEVEL SECURITY;"
                "ALTER TABLE t FORCE ROW LEVEL SECURITY;"
            )
            cur.execute(f"CREATE POLICY perm ON t FOR SELECT TO anon {perm};")
            cur.execute(
                f"CREATE POLICY floor ON t AS RESTRICTIVE FOR SELECT TO anon {floor};"
            )
            cur.execute("INSERT INTO t VALUES (1, gen_random_uuid(), true);")
            schema = introspect(conn, schemas=["public"])
        verdict = _verdict(build_verification(schema), "public.t")
        assert verdict == expected, f"{perm} + {floor}: pgrls proved {verdict}"
        # ...and it must match what a live anonymous session sees (rolled back).
        with psycopg.connect(pg_url) as conn, conn.cursor() as cur:
            cur.execute("SET LOCAL ROLE anon;")
            cur.execute("SELECT count(*) FROM t;")
            observed = "leak" if cur.fetchone()[0] else "isolated"
            conn.rollback()
        assert verdict == observed, (
            f"{perm} + {floor}: pgrls={verdict} but a live anon session saw "
            f"{observed} — the composition is unsound"
        )


@requires_docker
@requires_z3
def test_verify_anon_role_gate_matches_live_anon_session(
    pg_url: str, pg_conn: psycopg.Connection
) -> None:
    # The role gate, grounded in real Postgres RLS: `verify --mode anon` must
    # agree with what an actual anonymous session sees.
    #   docs_anon   — inverted-auth policy TO anon           → a real anon leak
    #   docs_authed — the SAME shape but TO authenticated    → ISOLATED (the
    #                 fix: anon is not a member of authenticated, so it can
    #                 never invoke the policy; verify used to false-LEAK here)
    #   docs_reader — USING(true) TO app_reader, GRANT app_reader TO anon → a
    #                 leak the membership closure must find (anon inherits it)
    def _ensure_role(cur: psycopg.Cursor, name: str) -> None:
        cur.execute(
            f"DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE "
            f"rolname='{name}') THEN CREATE ROLE {name} NOLOGIN NOSUPERUSER "
            f"NOBYPASSRLS; END IF; END $$;"
        )

    with pg_conn.cursor() as cur:
        cur.execute(_AUTH_STUB)
        for role in ("anon", "authenticated", "app_reader"):
            _ensure_role(cur, role)
        cur.execute("GRANT app_reader TO anon;")  # anon inherits app_reader
        for name in ("docs_anon", "docs_authed", "docs_reader"):
            cur.execute(
                f"CREATE TABLE {name} (id int, tenant_id uuid);"
                f"ALTER TABLE {name} ENABLE ROW LEVEL SECURITY;"
                f"INSERT INTO {name} VALUES (1, gen_random_uuid());"
            )
        cur.execute("GRANT SELECT ON docs_anon TO anon;")
        cur.execute("GRANT SELECT ON docs_authed TO anon;")
        cur.execute("GRANT SELECT ON docs_reader TO app_reader;")
        cur.execute(
            "CREATE POLICY p ON docs_anon FOR SELECT TO anon "
            "  USING (auth.uid() IS NULL OR tenant_id = auth.uid());"
            "CREATE POLICY p ON docs_authed FOR SELECT TO authenticated "
            "  USING (auth.uid() IS NULL OR tenant_id = auth.uid());"
            "CREATE POLICY p ON docs_reader FOR SELECT TO app_reader USING (true);"
        )

    schema = introspect(pg_conn, schemas=["public"])
    # The `pg_auth_members` closure input must be captured on the live path.
    assert schema.role_memberships is not None
    assert any(
        e.member == "anon" and e.role == "app_reader"
        for e in schema.role_memberships
    )

    v = build_verification(schema, mode="anon")
    static = {t.qualified_name: t.verdict for t in v.tables}
    expected = {
        "public.docs_anon": "leak",
        "public.docs_authed": "isolated",  # the fix — was a false LEAK
        "public.docs_reader": "leak",  # via the anon ∈ app_reader closure
    }
    assert {k: static.get(k) for k in expected} == expected, static

    # Ground each static verdict in what a real anonymous session actually sees.
    for name, verdict in expected.items():
        table = name.split(".", 1)[1]
        with psycopg.connect(pg_url) as conn, conn.cursor() as cur:
            cur.execute("SET LOCAL ROLE anon;")
            cur.execute(f"SELECT count(*) FROM {table};")
            observed = "leak" if cur.fetchone()[0] else "isolated"
            conn.rollback()
        assert observed == verdict, (
            f"{name}: pgrls proved {verdict} but a live anon session saw "
            f"{observed} — the role gate is unsound"
        )


def test_every_mode_is_covered_by_the_sarif_lookups() -> None:
    """Adding a `--mode` must not crash `--format sarif`.

    `render_sarif` indexes `_SARIF_RULE_ID` / `_SARIF_RULE_TITLE` by mode with
    `[]`, so a mode missing from either raises KeyError at render time rather
    than degrading. That is exactly what happened when `reachability` was
    added: text and json rendered fine and sarif died. Assert coverage off the
    `Mode` literal itself, so the next mode is caught by this test instead of
    by a user's CI.
    """
    from typing import get_args

    from pgrls.verify import _SARIF_RULE_ID, _SARIF_RULE_TITLE, Mode

    modes = set(get_args(Mode))
    assert modes <= set(_SARIF_RULE_ID), (
        f"modes missing a SARIF ruleId: {modes - set(_SARIF_RULE_ID)}"
    )
    assert modes <= set(_SARIF_RULE_TITLE), (
        f"modes missing a SARIF title: {modes - set(_SARIF_RULE_TITLE)}"
    )
    # Distinct ruleIds — GitHub Code Scanning groups by ruleId, so two modes
    # sharing one would merge unrelated findings in the UI.
    ids = [_SARIF_RULE_ID[m] for m in modes]
    assert len(ids) == len(set(ids)), f"duplicate SARIF ruleIds: {ids}"
