"""Tests for `pgrls verify --probe` — the live runtime probe.

These tests are live: each opens a (non-autocommit) psycopg connection against a
throwaway Postgres and exercises the seed → become-threat-session → observe →
rollback dance. They skip cleanly when Docker / a test Postgres is unavailable
(the existing `pg_conn` fixture pattern) and when z3-solver is not installed
(the static verdict the probe diffs against needs the prover).
"""
from __future__ import annotations

import json

import psycopg
import pytest
from click.testing import CliRunner

from pgrls.cli import main
from pgrls.diff._z3_compare import Z3_AVAILABLE
from pgrls.introspect import introspect
from pgrls.probe import Probe, run_probe
from pgrls.verify import (
    PolicyProof,
    TableVerdict,
    Verification,
    build_verification,
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

# Minimal Supabase-style auth stub so a policy referencing auth.uid() is
# creatable, plus a request.jwt GUC the probe flips. Mirrors test_verify.py.
_AUTH_STUB = (
    "CREATE SCHEMA IF NOT EXISTS auth;"
    "CREATE OR REPLACE FUNCTION auth.uid() RETURNS uuid LANGUAGE sql STABLE AS "
    "$$ SELECT NULLIF(current_setting('request.jwt.claim.sub', true), '')::uuid $$;"
)


def _result(probe: Probe, table: str):
    return next(r for r in probe.results if r.qualified_name == table)


def _tx(pg_url: str) -> psycopg.Connection:
    """A non-autocommit connection — what run_probe requires (it rolls back)."""
    return psycopg.connect(pg_url)  # autocommit defaults to False


def _probe(
    pg_url: str, schema_obj, *, mode, auth_functions=None, probe_role="pgrls_probe_runner"
) -> Probe:
    verification = build_verification(schema_obj, auth_functions=auth_functions, mode=mode)
    with _tx(pg_url) as conn:
        return run_probe(
            conn, schema_obj, verification,
            mode=mode, auth_functions=auth_functions, probe_role=probe_role,
        )


def _drop_role(conn: psycopg.Connection, role: str) -> None:
    """Drop a test login role and its dependent grants. `DROP ROLE` alone fails
    while the role still holds a table grant (`DependentObjectsStillExist`), and
    roles are cluster-global so `pg_conn`'s per-test schema reset does not remove
    them — revoke owned objects/privileges first, idempotently."""
    with conn.cursor() as cur:
        cur.execute(
            f"DO $$ BEGIN IF EXISTS (SELECT FROM pg_roles WHERE rolname = '{role}') "
            f"THEN EXECUTE 'DROP OWNED BY {role}'; EXECUTE 'DROP ROLE {role}'; "
            "END IF; END $$;"
        )


# --- leak / upgrade --------------------------------------------------------


@requires_docker
@requires_z3
def test_anon_inverted_auth_is_leak_confirmed(
    pg_url: str, pg_conn: psycopg.Connection
) -> None:
    # The flagship SEC004 shape: anon sees every row. Static LEAK, live
    # rows_visible → leak_confirmed.
    with pg_conn.cursor() as cur:
        cur.execute(_AUTH_STUB)
        cur.execute(
            "CREATE TABLE public.docs (id bigserial PRIMARY KEY, tenant_id uuid);"
            "ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;"
            "ALTER TABLE public.docs FORCE ROW LEVEL SECURITY;"
            "CREATE POLICY p ON public.docs FOR SELECT TO public "
            "  USING (auth.uid() IS NULL OR tenant_id = auth.uid());"
            "GRANT SELECT, INSERT ON public.docs TO public;"
        )
    schema = introspect(pg_conn, schemas=["public"])
    probe = _probe(pg_url, schema, mode="anon")
    r = _result(probe, "public.docs")
    assert r.static_verdict == "leak"
    assert r.observed == "rows_visible"
    assert r.agreement == "leak_confirmed"
    assert probe.has_confirmed_leak


@requires_docker
@requires_z3
def test_cross_tenant_or_public_is_leak_confirmed(
    pg_url: str, pg_conn: psycopg.Connection
) -> None:
    # An `OR is_public` bypass exposes another tenant's public rows. The probe
    # seeds a public B-row, authenticates as A, and sees it → leak_confirmed.
    with pg_conn.cursor() as cur:
        cur.execute(_AUTH_STUB)
        cur.execute(
            "CREATE TABLE public.docs "
            "  (id bigserial PRIMARY KEY, tenant_id uuid, is_public boolean);"
            "ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;"
            "ALTER TABLE public.docs FORCE ROW LEVEL SECURITY;"
            "CREATE POLICY p ON public.docs FOR SELECT TO public "
            "  USING (tenant_id = auth.uid() OR is_public);"
            "GRANT SELECT, INSERT ON public.docs TO public;"
        )
    schema = introspect(pg_conn, schemas=["public"])
    probe = _probe(pg_url, schema, mode="cross-tenant")
    r = _result(probe, "public.docs")
    assert r.static_verdict == "leak"
    assert r.observed == "rows_visible"
    assert r.agreement == "leak_confirmed"
    # the seeded public B-row characterizes the leak
    assert r.seeded and r.seeded.get("is_public") is True


@requires_docker
@requires_z3
def test_write_with_check_true_upgrades_unverified_to_leak_confirmed(
    pg_url: str, pg_conn: psycopg.Connection
) -> None:
    # THE headline: reads are tenant-scoped (proven) but the INSERT WITH CHECK is
    # wide open. Static is UNVERIFIED (no scoping write-check), but the probe
    # authenticates as A, attempts a B-stamped INSERT, and it is admitted →
    # leak_confirmed (an honest "no claim" upgraded to a reproduced leak).
    with pg_conn.cursor() as cur:
        cur.execute(_AUTH_STUB)
        cur.execute(
            "CREATE TABLE public.docs "
            "  (id bigserial PRIMARY KEY, tenant_id uuid NOT NULL, body text);"
            "ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;"
            "ALTER TABLE public.docs FORCE ROW LEVEL SECURITY;"
            "CREATE POLICY p_read ON public.docs FOR SELECT TO public "
            "  USING (tenant_id = auth.uid());"
            "CREATE POLICY p_write ON public.docs FOR INSERT TO public "
            "  WITH CHECK (true);"
            "GRANT SELECT, INSERT ON public.docs TO public;"
        )
    schema = introspect(pg_conn, schemas=["public"])
    probe = _probe(pg_url, schema, mode="write")
    r = _result(probe, "public.docs")
    assert r.static_verdict == "unverified"
    assert r.observed == "write_admitted"
    assert r.agreement == "leak_confirmed"


# --- mismatch (proof ↔ reality broken) -------------------------------------


@requires_docker
@requires_z3
def test_mismatch_when_static_isolated_but_live_leaks(
    pg_url: str, pg_conn: psycopg.Connection
) -> None:
    # Decouple the static verdict from reality to exercise the MISMATCH branch:
    # the live policy is USING(true) (anon sees everything), but we hand-build a
    # Verification that (wrongly, as if from a stale snapshot) claims the table
    # is isolated. The probe must catch proof ↔ reality drift.
    with pg_conn.cursor() as cur:
        cur.execute(
            "CREATE TABLE public.docs (id bigserial PRIMARY KEY, tenant_id uuid);"
            "ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;"
            "ALTER TABLE public.docs FORCE ROW LEVEL SECURITY;"
            "CREATE POLICY p ON public.docs FOR SELECT TO public USING (true);"
            "GRANT SELECT, INSERT ON public.docs TO public;"
        )
    schema = introspect(pg_conn, schemas=["public"])
    # Force the verdict to isolated though the live policy is USING(true).
    forced = Verification(
        tables=(
            TableVerdict(
                "public.docs",
                "isolated",
                None,
                (PolicyProof("p", "isolated", None, None),),
            ),
        ),
        mode="anon",
    )
    with _tx(pg_url) as conn:
        probe = run_probe(conn, schema, forced, mode="anon")
    r = _result(probe, "public.docs")
    assert r.static_verdict == "isolated"
    assert r.observed == "rows_visible"
    assert r.agreement == "mismatch"
    assert probe.has_mismatch


@requires_docker
@requires_z3
def test_mismatch_makes_cli_exit_one(
    pg_url: str, pg_conn: psycopg.Connection
) -> None:
    # A live USING(true) → real static LEAK → the CLI probe exits 1; the mismatch
    # branch is covered above with a forced Verification. Here we confirm the
    # gate fires on the real leak path end-to-end.
    with pg_conn.cursor() as cur:
        cur.execute(
            "CREATE TABLE public.docs (id bigserial PRIMARY KEY, tenant_id uuid);"
            "ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;"
            "ALTER TABLE public.docs FORCE ROW LEVEL SECURITY;"
            "CREATE POLICY p ON public.docs FOR SELECT TO public USING (true);"
            "GRANT SELECT, INSERT ON public.docs TO public;"
        )
    result = CliRunner().invoke(
        main, ["verify", "--probe", "--database-url", pg_url, "--schemas", "public"]
    )
    assert result.exit_code == 1, result.output
    assert "LEAK CONFIRMED" in result.output


# --- agree -----------------------------------------------------------------


@requires_docker
@requires_z3
def test_anon_scoped_policy_agrees(
    pg_url: str, pg_conn: psycopg.Connection
) -> None:
    # A properly scoped policy: static PROVEN, anon sees no rows → agree.
    with pg_conn.cursor() as cur:
        cur.execute(_AUTH_STUB)
        cur.execute(
            "CREATE TABLE public.acct (id bigserial PRIMARY KEY, tenant_id uuid);"
            "ALTER TABLE public.acct ENABLE ROW LEVEL SECURITY;"
            "ALTER TABLE public.acct FORCE ROW LEVEL SECURITY;"
            "CREATE POLICY p ON public.acct FOR SELECT TO public "
            "  USING (tenant_id = auth.uid());"
            "GRANT SELECT, INSERT ON public.acct TO public;"
        )
    schema = introspect(pg_conn, schemas=["public"])
    probe = _probe(pg_url, schema, mode="anon")
    r = _result(probe, "public.acct")
    assert r.static_verdict == "isolated"
    assert r.observed == "no_rows"
    assert r.agreement == "agree"


@requires_docker
@requires_z3
def test_cross_tenant_scoped_policy_agrees(
    pg_url: str, pg_conn: psycopg.Connection
) -> None:
    # The gold-standard scoping shape: static PROVEN cross-tenant, the probe
    # seeds a B-row, authenticates as A, and sees nothing → agree.
    with pg_conn.cursor() as cur:
        cur.execute(_AUTH_STUB)
        cur.execute(
            "CREATE TABLE public.acct (id bigserial PRIMARY KEY, tenant_id uuid);"
            "ALTER TABLE public.acct ENABLE ROW LEVEL SECURITY;"
            "ALTER TABLE public.acct FORCE ROW LEVEL SECURITY;"
            "CREATE POLICY p ON public.acct FOR SELECT TO public "
            "  USING (tenant_id = auth.uid());"
            "GRANT SELECT, INSERT ON public.acct TO public;"
        )
    schema = introspect(pg_conn, schemas=["public"])
    probe = _probe(pg_url, schema, mode="cross-tenant")
    r = _result(probe, "public.acct")
    assert r.static_verdict == "isolated"
    assert r.observed == "no_rows"
    assert r.agreement == "agree"


@requires_docker
@requires_z3
def test_write_scoped_with_check_agrees(
    pg_url: str, pg_conn: psycopg.Connection
) -> None:
    # A FOR ALL policy with a tenant-scoped USING (reused as the write-check):
    # static PROVEN write-isolated, the probe's cross-tenant INSERT is rejected
    # → agree. (Own-tenant admitted, cross-tenant rejected is the contract.)
    with pg_conn.cursor() as cur:
        cur.execute(_AUTH_STUB)
        cur.execute(
            "CREATE TABLE public.docs (id bigserial PRIMARY KEY, tenant_id uuid NOT NULL);"
            "ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;"
            "ALTER TABLE public.docs FORCE ROW LEVEL SECURITY;"
            "CREATE POLICY p ON public.docs FOR ALL TO public "
            "  USING (tenant_id = auth.uid()) WITH CHECK (tenant_id = auth.uid());"
            "GRANT SELECT, INSERT ON public.docs TO public;"
        )
    schema = introspect(pg_conn, schemas=["public"])
    probe = _probe(pg_url, schema, mode="write")
    r = _result(probe, "public.docs")
    assert r.static_verdict == "isolated"
    assert r.observed == "write_rejected"
    assert r.agreement == "agree"


@requires_docker
@requires_z3
def test_cross_tenant_agrees_despite_real_rows_at_synthetic_tenants(
    pg_url: str, pg_conn: psycopg.Connection
) -> None:
    # Regression (review C1): the read-observe must count only the row the probe
    # planted (tenant B), not the whole table. An integer tenant key whose live
    # data already holds rows for the small synthetic tenant pool the probe
    # picks A/B from must still AGREE — seeing a real, correctly-scoped row for
    # the *session* tenant the probe authenticates as is RLS working, not a leak.
    with pg_conn.cursor() as cur:
        cur.execute(_AUTH_STUB)
        cur.execute(
            "CREATE TABLE public.acct "
            "  (id bigserial PRIMARY KEY, tenant_id integer NOT NULL, body text);"
            "ALTER TABLE public.acct ENABLE ROW LEVEL SECURITY;"
            "ALTER TABLE public.acct FORCE ROW LEVEL SECURITY;"
            "CREATE POLICY p ON public.acct FOR ALL TO public "
            "  USING (tenant_id = current_setting('app.tenant_id', true)::int) "
            "  WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::int);"
            "GRANT SELECT, INSERT ON public.acct TO public;"
            # Real committed rows across the synthetic pool — whichever value the
            # probe authenticates as (A), one of these is its own visible row.
            "INSERT INTO public.acct (tenant_id, body) "
            "  VALUES (1, 'real 1'), (2, 'real 2'), (3, 'real 3');"
        )
    schema = introspect(pg_conn, schemas=["public"])
    probe = _probe(pg_url, schema, mode="cross-tenant")
    r = _result(probe, "public.acct")
    assert r.static_verdict == "isolated"
    assert r.observed == "no_rows"  # the planted tenant-B row is hidden from A
    assert r.agreement == "agree"  # NOT a false mismatch from the real A row


@requires_docker
@requires_z3
def test_write_probe_abstains_on_fk_violation_instead_of_crashing(
    pg_url: str, pg_conn: psycopg.Connection
) -> None:
    # Regression (review H1): a synthesized cross-tenant write row that trips a
    # non-RLS constraint (an outgoing FK with no matching parent) must ABSTAIN
    # cleanly, not crash the run with an aborted transaction.
    with pg_conn.cursor() as cur:
        cur.execute(_AUTH_STUB)
        cur.execute(
            "CREATE TABLE public.parent (id integer PRIMARY KEY);"
            "CREATE TABLE public.child "
            "  (id bigserial PRIMARY KEY, tenant_id uuid NOT NULL, "
            "   parent_id integer NOT NULL REFERENCES public.parent(id));"
            "ALTER TABLE public.child ENABLE ROW LEVEL SECURITY;"
            "ALTER TABLE public.child FORCE ROW LEVEL SECURITY;"
            "CREATE POLICY p_read ON public.child FOR SELECT TO public "
            "  USING (tenant_id = auth.uid());"
            "CREATE POLICY p_write ON public.child FOR INSERT TO public "
            "  WITH CHECK (true);"  # unscoped → UNVERIFIED write verdict
            "GRANT SELECT, INSERT ON public.child TO public;"
        )
    schema = introspect(pg_conn, schemas=["public"])
    probe = _probe(pg_url, schema, mode="write")  # must not raise
    r = _result(probe, "public.child")
    assert r.observed == "abstained"
    assert r.agreement == "abstained"
    assert "non-RLS constraint" in r.detail


@requires_docker
@requires_z3
def test_write_probe_abstains_when_check_constraint_masks_rls(
    pg_url: str, pg_conn: psycopg.Connection
) -> None:
    # Regression (review M1): an orthogonal table CHECK the synthesized row trips
    # must not be miscredited as an RLS write-rejection (which would mask the
    # real WITH CHECK (true) write-leak as a clean "skipped") — abstain instead.
    with pg_conn.cursor() as cur:
        cur.execute(_AUTH_STUB)
        cur.execute(
            "CREATE TABLE public.docs "
            "  (id bigserial PRIMARY KEY, tenant_id uuid NOT NULL, "
            "   qty integer NOT NULL CHECK (qty > 100));"
            "ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;"
            "ALTER TABLE public.docs FORCE ROW LEVEL SECURITY;"
            "CREATE POLICY p_read ON public.docs FOR SELECT TO public "
            "  USING (tenant_id = auth.uid());"
            "CREATE POLICY p_write ON public.docs FOR INSERT TO public "
            "  WITH CHECK (true);"
            "GRANT SELECT, INSERT ON public.docs TO public;"
        )
    schema = introspect(pg_conn, schemas=["public"])
    probe = _probe(pg_url, schema, mode="write")
    r = _result(probe, "public.docs")
    assert r.observed == "abstained"
    assert r.agreement == "abstained"
    assert "non-RLS constraint" in r.detail


@requires_docker
@requires_z3
def test_probe_confirms_select_wrapped_auth_uid_leak(
    pg_url: str, pg_conn: psycopg.Connection
) -> None:
    # Regression (review MED-2): the dominant Supabase / PERF001 idiom wraps the
    # auth call as `(SELECT auth.uid())`. The probe must NOT treat that bare
    # scalar sub-select as "references other tables" and skip — it must run and
    # confirm the inverted-auth anon leak.
    with pg_conn.cursor() as cur:
        cur.execute(_AUTH_STUB)
        cur.execute(
            "CREATE TABLE public.docs (id bigserial PRIMARY KEY, tenant_id uuid);"
            "ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;"
            "ALTER TABLE public.docs FORCE ROW LEVEL SECURITY;"
            "CREATE POLICY p ON public.docs FOR SELECT TO public "
            "  USING ((SELECT auth.uid()) IS NULL "
            "         OR tenant_id = (SELECT auth.uid()));"
            "GRANT SELECT, INSERT ON public.docs TO public;"
        )
    schema = introspect(pg_conn, schemas=["public"])
    probe = _probe(pg_url, schema, mode="anon")
    r = _result(probe, "public.docs")
    assert r.observed != "skipped"  # not abstained as "references other tables"
    assert r.agreement == "leak_confirmed"


@requires_docker
@requires_z3
def test_probe_confirms_select_wrapped_scoped_policy_agrees(
    pg_url: str, pg_conn: psycopg.Connection
) -> None:
    # The wrapped scalar form on a correctly-scoped policy must AGREE, not skip.
    with pg_conn.cursor() as cur:
        cur.execute(_AUTH_STUB)
        cur.execute(
            "CREATE TABLE public.acct "
            "  (id bigserial PRIMARY KEY, tenant_id uuid NOT NULL);"
            "ALTER TABLE public.acct ENABLE ROW LEVEL SECURITY;"
            "ALTER TABLE public.acct FORCE ROW LEVEL SECURITY;"
            "CREATE POLICY p ON public.acct FOR ALL TO public "
            "  USING (tenant_id = (SELECT auth.uid())) "
            "  WITH CHECK (tenant_id = (SELECT auth.uid()));"
            "GRANT SELECT, INSERT ON public.acct TO public;"
        )
    schema = introspect(pg_conn, schemas=["public"])
    probe = _probe(pg_url, schema, mode="cross-tenant")
    r = _result(probe, "public.acct")
    assert r.observed != "skipped"
    assert r.agreement == "agree"


@requires_docker
@requires_z3
def test_probe_applies_role_scoped_policy(
    pg_url: str, pg_conn: psycopg.Connection
) -> None:
    # Regression (review LOW-1): a policy scoped `TO authenticated` only applies
    # to a session that is a member of `authenticated`. The probe best-effort
    # grants its throwaway role that membership, so a leaky `TO authenticated`
    # policy is CONFIRMED — without it the probe role isn't `authenticated`, the
    # policy doesn't apply, FORCE RLS default-denies, and the static leak is
    # mis-reported as a MISMATCH.
    with pg_conn.cursor() as cur:
        cur.execute(_AUTH_STUB)
        cur.execute(
            "DROP ROLE IF EXISTS pgrls_probe_authn;"
            "CREATE ROLE pgrls_probe_authn NOLOGIN;"
            "CREATE TABLE public.docs "
            "  (id bigserial PRIMARY KEY, tenant_id uuid, is_public boolean);"
            "ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;"
            "ALTER TABLE public.docs FORCE ROW LEVEL SECURITY;"
            "CREATE POLICY p ON public.docs FOR SELECT TO pgrls_probe_authn "
            "  USING (tenant_id = auth.uid() OR is_public);"
            "GRANT SELECT, INSERT ON public.docs TO pgrls_probe_authn;"
        )
    schema = introspect(pg_conn, schemas=["public"])
    probe = _probe(pg_url, schema, mode="cross-tenant")
    r = _result(probe, "public.docs")
    assert r.agreement == "leak_confirmed"
    _drop_role(pg_conn, "pgrls_probe_authn")


# --- non-destructiveness / lifecycle ---------------------------------------


@requires_docker
@requires_z3
def test_probe_is_non_destructive_and_drops_its_role(
    pg_url: str, pg_conn: psycopg.Connection
) -> None:
    # The invariant: committed row counts are unchanged after the probe, no
    # seeded row escapes, and the probe role does not survive the rollback.
    with pg_conn.cursor() as cur:
        cur.execute(_AUTH_STUB)
        cur.execute(
            "CREATE TABLE public.docs "
            "  (id bigserial PRIMARY KEY, tenant_id uuid NOT NULL, body text);"
            "ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;"
            "ALTER TABLE public.docs FORCE ROW LEVEL SECURITY;"
            "CREATE POLICY p_read ON public.docs FOR SELECT TO public "
            "  USING (tenant_id = auth.uid());"
            "CREATE POLICY p_write ON public.docs FOR INSERT TO public "
            "  WITH CHECK (true);"
            "GRANT SELECT, INSERT ON public.docs TO public;"
            "INSERT INTO public.docs (tenant_id, body) "
            "  VALUES ('00000000-0000-0000-0000-0000000000a1', 'committed');"
        )

    def _committed_rows() -> int:
        with pg_conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM public.docs")
            return cur.fetchone()[0]

    def _role_exists() -> bool:
        with pg_conn.cursor() as cur:
            cur.execute("SELECT 1 FROM pg_roles WHERE rolname = 'pgrls_probe_runner'")
            return cur.fetchone() is not None

    before = _committed_rows()
    assert before == 1
    schema = introspect(pg_conn, schemas=["public"])
    # write-mode probe admits a cross-tenant INSERT (leak) — but rolled back.
    probe = _probe(pg_url, schema, mode="write")
    assert probe.has_confirmed_leak  # it really did admit the write live
    assert _committed_rows() == before  # ...but nothing was committed
    assert not _role_exists()  # the probe role did not persist


@requires_docker
@requires_z3
def test_seed_via_guc_flip_works_from_non_superuser_insert_connection(
    pg_url: str, pg_conn: psycopg.Connection
) -> None:
    # The seed lever (set the identity GUC to B, then INSERT) is the only
    # non-superuser-safe seed under FORCE RLS. Drive the probe over a
    # non-superuser, INSERT-capable, CREATEROLE login role and confirm a
    # cross-tenant agree still works (the seed B-row was admitted, the A session
    # then saw nothing).
    with pg_conn.cursor() as cur:
        cur.execute(_AUTH_STUB)
        cur.execute(
            "CREATE TABLE public.acct (id bigserial PRIMARY KEY, tenant_id uuid NOT NULL);"
            "ALTER TABLE public.acct ENABLE ROW LEVEL SECURITY;"
            "ALTER TABLE public.acct FORCE ROW LEVEL SECURITY;"
            "CREATE POLICY p ON public.acct FOR ALL TO public "
            "  USING (tenant_id = auth.uid()) WITH CHECK (tenant_id = auth.uid());"
            "GRANT USAGE ON SCHEMA auth TO PUBLIC;"
            "GRANT SELECT, INSERT ON public.acct TO public;"
            "DROP ROLE IF EXISTS pgrls_probe_driver;"
            # CREATEROLE so it can make the probe role; NOSUPERUSER so the seed
            # really goes through RLS (the GUC-flip path), not a bypass.
            "CREATE ROLE pgrls_probe_driver LOGIN PASSWORD 'drv' "
            "  NOSUPERUSER NOCREATEDB CREATEROLE;"
        )
    # Build a connection URL for the driver role against the same database.
    info = psycopg.conninfo.conninfo_to_dict(pg_url)
    driver_url = psycopg.conninfo.make_conninfo(
        **{**info, "user": "pgrls_probe_driver", "password": "drv"}
    )
    schema = introspect(pg_conn, schemas=["public"])
    verification = build_verification(schema, mode="cross-tenant")
    with _tx(driver_url) as conn:
        probe = run_probe(conn, schema, verification, mode="cross-tenant")
    r = _result(probe, "public.acct")
    # The seed (GUC-flip → INSERT a B-row) and the A-session read both ran under
    # a non-superuser; a scoped policy hides the B-row from A → agree.
    assert r.observed == "no_rows"
    assert r.agreement == "agree"
    _drop_role(pg_conn, "pgrls_probe_driver")


# --- abstain ---------------------------------------------------------------


@requires_docker
@requires_z3
def test_nocreaterole_connection_abstains_all(
    pg_url: str, pg_conn: psycopg.Connection
) -> None:
    # A connection that cannot create a role abstains on every table (exit 0,
    # or exit 1 under --strict — checked via the CLI below). The probe never
    # crashes; it degrades gracefully.
    with pg_conn.cursor() as cur:
        cur.execute(_AUTH_STUB)
        cur.execute(
            "CREATE TABLE public.docs (id bigserial PRIMARY KEY, tenant_id uuid);"
            "ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;"
            "ALTER TABLE public.docs FORCE ROW LEVEL SECURITY;"
            "CREATE POLICY p ON public.docs FOR SELECT TO public USING (true);"
            "GRANT SELECT, INSERT ON public.docs TO public;"
            "DROP ROLE IF EXISTS pgrls_weak;"
            "CREATE ROLE pgrls_weak LOGIN PASSWORD 'weak' "
            "  NOSUPERUSER NOCREATEDB NOCREATEROLE;"
            "GRANT SELECT, INSERT ON public.docs TO pgrls_weak;"
        )
    info = psycopg.conninfo.conninfo_to_dict(pg_url)
    weak_url = psycopg.conninfo.make_conninfo(
        **{**info, "user": "pgrls_weak", "password": "weak"}
    )
    schema = introspect(pg_conn, schemas=["public"])
    verification = build_verification(schema, mode="anon")
    with _tx(weak_url) as conn:
        probe = run_probe(conn, schema, verification, mode="anon")
    r = _result(probe, "public.docs")
    assert r.observed == "abstained"
    assert r.agreement == "abstained"
    assert "create probe role" in r.detail
    assert not probe.has_mismatch and not probe.has_confirmed_leak
    _drop_role(pg_conn, "pgrls_weak")


@requires_docker
@requires_z3
def test_cross_tenant_using_true_has_no_axis_and_is_skipped(
    pg_url: str, pg_conn: psycopg.Connection
) -> None:
    # USING(true) carries no tenant-scoping equality, so a cross-tenant probe has
    # no axis to pivot on → skipped (a "nothing to prove" boundary, not a leak).
    with pg_conn.cursor() as cur:
        cur.execute(
            "CREATE TABLE public.docs (id bigserial PRIMARY KEY, tenant_id uuid);"
            "ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;"
            "ALTER TABLE public.docs FORCE ROW LEVEL SECURITY;"
            "CREATE POLICY p ON public.docs FOR SELECT TO public USING (true);"
            "GRANT SELECT, INSERT ON public.docs TO public;"
        )
    schema = introspect(pg_conn, schemas=["public"])
    probe = _probe(pg_url, schema, mode="cross-tenant")
    r = _result(probe, "public.docs")
    assert r.observed in ("skipped", "abstained")
    assert r.agreement in ("skipped", "abstained")
    assert "axis" in r.detail


# --- CLI -------------------------------------------------------------------


def test_probe_cli_help_lists_flags() -> None:
    result = CliRunner().invoke(main, ["verify", "--help"])
    assert result.exit_code == 0
    assert "--probe" in result.output and "--probe-role" in result.output


def test_probe_cli_requires_database_url() -> None:
    # --probe needs a live connection: without a database URL the connect helper
    # errors (exit 2, the standard "no database connection" guard).
    result = CliRunner().invoke(main, ["verify", "--probe"], env={"DATABASE_URL": ""})
    assert result.exit_code == 2
    assert "No database connection" in result.output


def test_probe_render_sarif_projects_actionable_results() -> None:
    # Offline unit test of the probe SARIF projection (F1): LEAK CONFIRMED +
    # MISMATCH → `error` results; AGREE / skipped → nothing; abstained → a `note`
    # only under --strict. (No DB — render_sarif is pure over a Probe.)
    import json as _json

    from pgrls.probe import ProbeResult, render_sarif

    probe = Probe(
        results=(
            ProbeResult("public.a", "p", "anon", "leak", "rows_visible",
                        "leak_confirmed", "static LEAK reproduced live", None),
            ProbeResult("public.b", "q", "anon", "isolated", "rows_visible",
                        "mismatch", "proof contradicts reality", None),
            ProbeResult("public.c", "r", "anon", "isolated", "no_rows",
                        "agree", "PROVEN and hidden", None),
            ProbeResult("public.d", None, "anon", "unverified", "abstained",
                        "abstained", "cannot create probe role", None),
        ),
        mode="anon",
    )
    results = _json.loads(render_sarif(probe))["runs"][0]["results"]
    # leak_confirmed + mismatch only; agree + abstained omitted by default.
    assert len(results) == 2
    assert sorted(r["level"] for r in results) == ["error", "error"]
    assert {r["ruleId"] for r in results} == {"pgrls-probe-anon"}
    # --strict surfaces the abstain as a `note`.
    strict_results = _json.loads(render_sarif(probe, strict=True))["runs"][0][
        "results"
    ]
    assert len(strict_results) == 3
    assert sum(r["level"] == "note" for r in strict_results) == 1


def test_probe_cli_emit_repro_is_usage_error() -> None:
    result = CliRunner().invoke(
        main,
        ["verify", "--probe", "--emit-repro", "/tmp/x", "--database-url",
         "postgresql://x/y"],
    )
    assert result.exit_code == 2
    assert "separately" in result.output


@requires_docker
@requires_z3
def test_probe_cli_nocreaterole_strict_exits_one(
    pg_url: str, pg_conn: psycopg.Connection
) -> None:
    # Abstain is exit 0 by default, but exit 1 under --strict.
    with pg_conn.cursor() as cur:
        cur.execute(
            "CREATE TABLE public.docs (id bigserial PRIMARY KEY, tenant_id uuid);"
            "ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;"
            "ALTER TABLE public.docs FORCE ROW LEVEL SECURITY;"
            "CREATE POLICY p ON public.docs FOR SELECT TO public USING (true);"
            "GRANT SELECT, INSERT ON public.docs TO public;"
            "DROP ROLE IF EXISTS pgrls_weak;"
            "CREATE ROLE pgrls_weak LOGIN PASSWORD 'weak' "
            "  NOSUPERUSER NOCREATEDB NOCREATEROLE;"
            "GRANT SELECT, INSERT ON public.docs TO pgrls_weak;"
        )
    info = psycopg.conninfo.conninfo_to_dict(pg_url)
    weak_url = psycopg.conninfo.make_conninfo(
        **{**info, "user": "pgrls_weak", "password": "weak"}
    )
    runner = CliRunner()
    base = ["verify", "--probe", "--database-url", weak_url, "--schemas", "public"]
    r_default = runner.invoke(main, base)
    assert r_default.exit_code == 0, r_default.output
    assert "abstained" in r_default.output
    r_strict = runner.invoke(main, [*base, "--strict"])
    assert r_strict.exit_code == 1, r_strict.output
    _drop_role(pg_conn, "pgrls_weak")


@requires_docker
@requires_z3
def test_probe_cli_write_headline_exit_one_and_json(
    pg_url: str, pg_conn: psycopg.Connection
) -> None:
    # The headline through the CLI: write mode on a reads-scoped + WITH CHECK
    # (true) schema → exit 1, JSON carries a leak_confirmed agreement, and the
    # text output names the AGREE/MISMATCH/LEAK CONFIRMED verdicts.
    with pg_conn.cursor() as cur:
        cur.execute(_AUTH_STUB)
        cur.execute(
            "CREATE TABLE public.docs "
            "  (id bigserial PRIMARY KEY, tenant_id uuid NOT NULL, body text);"
            "ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;"
            "ALTER TABLE public.docs FORCE ROW LEVEL SECURITY;"
            "CREATE POLICY p_read ON public.docs FOR SELECT TO public "
            "  USING (tenant_id = auth.uid());"
            "CREATE POLICY p_write ON public.docs FOR INSERT TO public "
            "  WITH CHECK (true);"
            "GRANT SELECT, INSERT ON public.docs TO public;"
        )
    runner = CliRunner()
    args = [
        "verify", "--mode", "write", "--probe",
        "--database-url", pg_url, "--schemas", "public",
    ]
    r_text = runner.invoke(main, args)
    assert r_text.exit_code == 1, r_text.output
    assert "LEAK CONFIRMED" in r_text.output

    r_json = runner.invoke(main, [*args, "--format", "json"])
    assert r_json.exit_code == 1, r_json.output
    payload = json.loads(r_json.output)
    assert payload["probe"] is True
    assert payload["mode"] == "write"
    agreements = {t["agreement"] for t in payload["tables"]}
    assert "leak_confirmed" in agreements
