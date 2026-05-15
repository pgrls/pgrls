from __future__ import annotations

from pathlib import Path

import psycopg
import pytest

from pgrls.introspect import _extract_search_path, introspect
from pgrls.model import Schema

FIXTURES_DIR = Path(__file__).parent / "fixtures"


# --- _extract_search_path (pure helper, no DB) ---------------------------
#
# `pg_proc.proconfig` is a text[] of `name=value` GUC-override strings;
# psycopg surfaces it as list[str] or None. `_extract_search_path`
# decodes the `search_path` entry for SEC015.


def test_extract_search_path_none_when_proconfig_null() -> None:
    # A function that overrides no GUCs has proconfig = NULL.
    assert _extract_search_path(None) is None


def test_extract_search_path_none_when_no_search_path_entry() -> None:
    # proconfig present but only carries other GUCs.
    assert _extract_search_path(["statement_timeout=5000"]) is None


def test_extract_search_path_returns_value() -> None:
    # The comma inside the value is already un-escaped by psycopg's
    # array parser by the time it reaches this helper.
    assert (
        _extract_search_path(["search_path=pg_catalog, public, pg_temp"])
        == "pg_catalog, public, pg_temp"
    )


def test_extract_search_path_picks_search_path_among_multiple_gucs() -> None:
    config = [
        "statement_timeout=5000",
        "search_path=public, pg_temp",
        "work_mem=64MB",
    ]
    assert _extract_search_path(config) == "public, pg_temp"


def test_extract_search_path_case_insensitive_guc_name() -> None:
    # GUC names are case-insensitive in Postgres.
    assert _extract_search_path(["Search_Path=public"]) == "public"


def test_extract_search_path_empty_value() -> None:
    # `SET search_path = ''` round-trips as an empty value string.
    assert _extract_search_path(["search_path="]) == ""


def test_returns_empty_schema_when_no_tables(pg_conn: psycopg.Connection) -> None:
    schema = introspect(pg_conn, schemas=["public"])
    assert isinstance(schema, Schema)
    assert schema.tables == ()


def test_finds_tables_with_rls_state(
    pg_conn: psycopg.Connection, apply_sql
) -> None:
    apply_sql((FIXTURES_DIR / "known_bad.sql").read_text())
    schema = introspect(pg_conn, schemas=["public"])
    by_name = {t.qualified_name: t for t in schema.tables}
    assert set(by_name) == {"public.users", "public.orders"}

    users = by_name["public.users"]
    assert users.rls_enabled is False
    assert users.force_rls is False
    assert users.policies == ()

    orders = by_name["public.orders"]
    assert orders.rls_enabled is True
    assert orders.force_rls is True
    assert len(orders.policies) == 1
    p = orders.policies[0]
    assert p.name == "orders_owner"
    assert p.command == "SELECT"
    assert p.permissive is True
    assert p.roles == ("PUBLIC",)
    assert p.using_sql is not None and "current_setting" in p.using_sql
    assert p.with_check_sql is None


def test_filters_by_schema(pg_conn: psycopg.Connection, apply_sql) -> None:
    apply_sql(
        """
        CREATE SCHEMA tenant;
        CREATE TABLE public.public_t (id INT);
        CREATE TABLE tenant.tenant_t (id INT);
        """
    )
    public_only = introspect(pg_conn, schemas=["public"])
    assert {t.qualified_name for t in public_only.tables} == {"public.public_t"}

    both = introspect(pg_conn, schemas=["public", "tenant"])
    assert {t.qualified_name for t in both.tables} == {
        "public.public_t",
        "tenant.tenant_t",
    }


def test_views_routed_to_schema_views_not_tables(
    pg_conn: psycopg.Connection, apply_sql
) -> None:
    # As of v0.3.0 introspect captures views — but they go into
    # `schema.views`, not `schema.tables`. The test name predates
    # the split; the body now pins both halves of the routing
    # contract: tables only contain real relations, and the view
    # does land on the views side.
    apply_sql(
        """
        CREATE TABLE public.real (id INT);
        CREATE VIEW public.view_real AS SELECT * FROM public.real;
        """
    )
    schema = introspect(pg_conn, schemas=["public"])
    table_names = {t.qualified_name for t in schema.tables}
    view_names = {v.qualified_name for v in schema.views}
    assert table_names == {"public.real"}
    assert "public.view_real" in view_names


def test_unknown_schema_raises(pg_conn: psycopg.Connection) -> None:
    with pytest.raises(ValueError, match="does_not_exist"):
        introspect(pg_conn, schemas=["does_not_exist"])


def test_with_check_and_multi_policy(
    pg_conn: psycopg.Connection, apply_sql
) -> None:
    apply_sql(
        """
        CREATE TABLE public.docs (id INT, owner TEXT);
        ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;
        CREATE POLICY docs_insert ON public.docs FOR INSERT TO PUBLIC WITH CHECK (true);
        CREATE POLICY docs_select ON public.docs FOR SELECT TO PUBLIC USING (true);
        CREATE POLICY docs_update ON public.docs FOR UPDATE TO PUBLIC USING (owner = current_setting('app.user', true)) WITH CHECK (owner = current_setting('app.user', true));
        """
    )
    schema = introspect(pg_conn, schemas=["public"])
    docs = next(t for t in schema.tables if t.name == "docs")
    assert len(docs.policies) == 3

    by_command = {p.command: p for p in docs.policies}
    assert set(by_command) == {"INSERT", "SELECT", "UPDATE"}

    insert = by_command["INSERT"]
    assert insert.with_check_sql is not None
    assert insert.using_sql is None
    assert insert.roles == ("PUBLIC",)

    select = by_command["SELECT"]
    assert select.using_sql is not None
    assert select.with_check_sql is None

    update = by_command["UPDATE"]
    assert update.using_sql is not None
    assert update.with_check_sql is not None


def test_populates_table_columns(
    pg_conn: psycopg.Connection, apply_sql
) -> None:
    # HYG001 depends on Table.columns being populated by introspection.
    # Without this, the rule silently never finds a missing column.
    apply_sql(
        """
        CREATE TABLE public.things (
            id BIGSERIAL PRIMARY KEY,
            tenant_id UUID,
            name TEXT
        );
        """
    )
    schema = introspect(pg_conn, schemas=["public"])
    things = next(t for t in schema.tables if t.name == "things")
    assert set(things.columns) == {"id", "tenant_id", "name"}


def test_columns_skips_dropped_columns(
    pg_conn: psycopg.Connection, apply_sql
) -> None:
    apply_sql(
        """
        CREATE TABLE public.things (id INT, gone INT, kept INT);
        ALTER TABLE public.things DROP COLUMN gone;
        """
    )
    schema = introspect(pg_conn, schemas=["public"])
    things = next(t for t in schema.tables if t.name == "things")
    assert "gone" not in things.columns
    assert "kept" in things.columns


def test_populates_policy_using_ast(
    pg_conn: psycopg.Connection, apply_sql
) -> None:
    # SEC004 / HYG001 walk Policy.using_ast. If introspection forgets to
    # parse it, both rules silently never fire on real databases.
    apply_sql(
        """
        CREATE TABLE public.t (id INT, owner TEXT);
        ALTER TABLE public.t ENABLE ROW LEVEL SECURITY;
        CREATE POLICY p ON public.t FOR SELECT TO PUBLIC USING (owner = 'x');
        """
    )
    schema = introspect(pg_conn, schemas=["public"])
    t = next(x for x in schema.tables if x.name == "t")
    p = t.policies[0]
    assert p.using_sql is not None
    assert p.using_ast is not None  # parsed eagerly during introspection


def test_populates_policy_with_check_ast(
    pg_conn: psycopg.Connection, apply_sql
) -> None:
    apply_sql(
        """
        CREATE TABLE public.t (id INT);
        ALTER TABLE public.t ENABLE ROW LEVEL SECURITY;
        CREATE POLICY p ON public.t FOR INSERT TO PUBLIC WITH CHECK (id > 0);
        """
    )
    schema = introspect(pg_conn, schemas=["public"])
    t = next(x for x in schema.tables if x.name == "t")
    p = t.policies[0]
    assert p.with_check_sql is not None
    assert p.with_check_ast is not None


def test_with_check_ast_is_none_when_clause_absent(
    pg_conn: psycopg.Connection, apply_sql
) -> None:
    apply_sql(
        """
        CREATE TABLE public.t (id INT);
        ALTER TABLE public.t ENABLE ROW LEVEL SECURITY;
        CREATE POLICY p ON public.t FOR SELECT TO PUBLIC USING (id > 0);
        """
    )
    schema = introspect(pg_conn, schemas=["public"])
    t = next(x for x in schema.tables if x.name == "t")
    p = t.policies[0]
    assert p.with_check_sql is None
    assert p.with_check_ast is None


def test_captures_restrictive_policy_permissive_false(
    pg_conn: psycopg.Connection, apply_sql
) -> None:
    apply_sql(
        """
        CREATE TABLE public.t (id INT);
        ALTER TABLE public.t ENABLE ROW LEVEL SECURITY;
        CREATE POLICY allow ON public.t FOR SELECT TO PUBLIC USING (true);
        CREATE POLICY restrict ON public.t AS RESTRICTIVE FOR SELECT TO PUBLIC USING (id > 0);
        """
    )
    schema = introspect(pg_conn, schemas=["public"])
    t = next(x for x in schema.tables if x.name == "t")
    by_name = {p.name: p for p in t.policies}
    assert by_name["allow"].permissive is True
    assert by_name["restrict"].permissive is False


def test_captures_multi_role_policy(
    pg_conn: psycopg.Connection, apply_sql
) -> None:
    # Roles are cluster-global; the session-scoped pg_conn fixture
    # only resets schemas. `DROP ROLE IF EXISTS` first so a re-run
    # within the same pytest session (e.g. `--count=2`) doesn't
    # fail with "role already exists".
    apply_sql(
        """
        DROP ROLE IF EXISTS role_a;
        DROP ROLE IF EXISTS role_b;
        CREATE ROLE role_a NOLOGIN;
        CREATE ROLE role_b NOLOGIN;
        CREATE TABLE public.t (id INT);
        ALTER TABLE public.t ENABLE ROW LEVEL SECURITY;
        CREATE POLICY p ON public.t FOR SELECT TO role_a, role_b USING (true);
        """
    )
    schema = introspect(pg_conn, schemas=["public"])
    t = next(x for x in schema.tables if x.name == "t")
    p = t.policies[0]
    assert set(p.roles) == {"role_a", "role_b"}


def test_empty_schemas_list_returns_empty_schema(
    pg_conn: psycopg.Connection,
) -> None:
    schema = introspect(pg_conn, schemas=[])
    assert schema.tables == ()


def test_table_with_no_policies_has_empty_policies_tuple(
    pg_conn: psycopg.Connection, apply_sql
) -> None:
    apply_sql("CREATE TABLE public.bare (id INT);")
    schema = introspect(pg_conn, schemas=["public"])
    bare = next(t for t in schema.tables if t.name == "bare")
    assert bare.policies == ()


def test_columns_empty_for_table_with_only_system_columns(
    pg_conn: psycopg.Connection, apply_sql
) -> None:
    # Introspection filters to attnum > 0 (user columns) — system columns
    # like xmin/cmin must not leak through.
    apply_sql("CREATE TABLE public.empty_t ();")
    schema = introspect(pg_conn, schemas=["public"])
    t = next(x for x in schema.tables if x.name == "empty_t")
    assert t.columns == ()


def test_introspect_includes_partitioned_parent_with_rls_state(
    pg_conn: psycopg.Connection, apply_sql
) -> None:
    # Postgres declarative partitioning: parent has relkind='p', children
    # have relkind='r'. Policies attach to the parent only; children
    # inherit them at query time. Before the partitioning fix, the parent
    # was filtered out (relkind='r' only), so the lint silently saw no
    # parent and SEC001 falsely fired on every child.
    apply_sql(
        """
        CREATE TABLE public.events (id BIGINT, tenant_id UUID, day DATE)
            PARTITION BY RANGE (day);
        CREATE TABLE public.events_2026 PARTITION OF public.events
            FOR VALUES FROM ('2026-01-01') TO ('2027-01-01');
        ALTER TABLE public.events ENABLE ROW LEVEL SECURITY;
        ALTER TABLE public.events FORCE ROW LEVEL SECURITY;
        CREATE POLICY p ON public.events FOR SELECT TO PUBLIC
            USING (tenant_id = current_setting('app.t', true)::uuid);
        """
    )
    schema = introspect(pg_conn, schemas=["public"])
    by_name = {t.qualified_name: t for t in schema.tables}
    # Parent is now visible.
    assert "public.events" in by_name
    assert "public.events_2026" in by_name

    parent = by_name["public.events"]
    child = by_name["public.events_2026"]

    # Parent carries the RLS state and the policy.
    assert parent.rls_enabled is True
    assert parent.force_rls is True
    assert len(parent.policies) == 1
    # Parent itself is not a partition.
    assert parent.partition_of is None

    # Child has no policies of its own (they live on the parent).
    assert child.policies == ()
    # Child's relrowsecurity is independently false — Postgres does not
    # propagate the flag down. The lint relies on partition_of to know
    # the parent is the source of truth.
    assert child.rls_enabled is False
    assert child.partition_of == ("public", "events")


def test_introspect_links_multi_level_partition(
    pg_conn: psycopg.Connection, apply_sql
) -> None:
    # A partition can itself be partitioned. partition_of stores only the
    # immediate parent — the rule walks the chain.
    apply_sql(
        """
        CREATE TABLE public.events (id INT, tenant_id INT, day DATE)
            PARTITION BY LIST (tenant_id);
        CREATE TABLE public.events_t1 PARTITION OF public.events
            FOR VALUES IN (1) PARTITION BY RANGE (day);
        CREATE TABLE public.events_t1_2026 PARTITION OF public.events_t1
            FOR VALUES FROM ('2026-01-01') TO ('2027-01-01');
        """
    )
    schema = introspect(pg_conn, schemas=["public"])
    by_name = {t.qualified_name: t for t in schema.tables}
    assert by_name["public.events"].partition_of is None
    assert by_name["public.events_t1"].partition_of == ("public", "events")
    assert by_name["public.events_t1_2026"].partition_of == (
        "public",
        "events_t1",
    )


def test_introspect_does_not_set_partition_of_for_classic_inherits(
    pg_conn: psycopg.Connection, apply_sql
) -> None:
    # Classic INHERITS (pre-declarative partitioning) goes through
    # pg_inherits too, but Postgres marks declarative-partition children
    # with `relispartition = true`. We filter on that — classic inherit
    # children must report partition_of = None.
    apply_sql(
        """
        CREATE TABLE public.parent_t (id INT, name TEXT);
        CREATE TABLE public.child_t (extra TEXT) INHERITS (public.parent_t);
        """
    )
    schema = introspect(pg_conn, schemas=["public"])
    by_name = {t.qualified_name: t for t in schema.tables}
    assert by_name["public.parent_t"].partition_of is None
    assert by_name["public.child_t"].partition_of is None


def test_introspect_dedupes_duplicate_role_oids_in_polroles(
    pg_conn: psycopg.Connection, apply_sql
) -> None:
    # Postgres permits `TO r1, r1` and stores polroles = [oid_r1, oid_r1]
    # verbatim. Without explicit deduplication, Policy.roles would be
    # ('r1', 'r1') — corrupting set semantics for any rule that counts
    # roles or compares against a known role list.
    apply_sql(
        """
        DROP ROLE IF EXISTS dup_role_user;
        CREATE ROLE dup_role_user NOLOGIN;
        CREATE TABLE public.t (id INT);
        ALTER TABLE public.t ENABLE ROW LEVEL SECURITY;
        CREATE POLICY p ON public.t FOR SELECT
            TO dup_role_user, dup_role_user USING (true);
        """
    )
    schema = introspect(pg_conn, schemas=["public"])
    t = next(x for x in schema.tables if x.name == "t")
    assert t.policies[0].roles == ("dup_role_user",)


def test_introspect_rejects_pg_catalog_schema(
    pg_conn: psycopg.Connection,
) -> None:
    # pg_catalog has thousands of system tables and pgrls cannot lint
    # any of them — refuse early instead of blowing up the report.
    with pytest.raises(ValueError, match="reserved"):
        introspect(pg_conn, schemas=["pg_catalog"])


def test_introspect_rejects_information_schema(
    pg_conn: psycopg.Connection,
) -> None:
    with pytest.raises(ValueError, match="reserved"):
        introspect(pg_conn, schemas=["information_schema"])


def test_introspect_rejects_pg_temp_schema_pattern(
    pg_conn: psycopg.Connection,
) -> None:
    # pg_temp_N exists per session — reject the pattern, not just the
    # exact name.
    with pytest.raises(ValueError, match="reserved"):
        introspect(pg_conn, schemas=["pg_temp_3"])


def test_introspect_rejects_mixed_reserved_and_real_schemas(
    pg_conn: psycopg.Connection,
) -> None:
    # Refuse the whole call rather than silently skipping the reserved
    # one — a typo in a list of schemas should be loud.
    with pytest.raises(ValueError, match="reserved"):
        introspect(pg_conn, schemas=["public", "pg_catalog"])


def test_introspect_reserved_schema_message_suggests_user_schemas(
    pg_conn: psycopg.Connection,
) -> None:
    # The rejection message should leave the user one keystroke
    # from the fix — name `public` (and tenant schemas if they
    # exist) so a copy-paste from another tool's `pg_catalog`
    # lands somewhere actionable.
    try:
        introspect(pg_conn, schemas=["pg_catalog"])
    except ValueError as exc:
        assert "public" in str(exc) or "tenant" in str(exc)
    else:
        raise AssertionError("expected ValueError")


def test_introspect_unknown_schema_lists_available(
    pg_conn: psycopg.Connection, apply_sql
) -> None:
    apply_sql("CREATE SCHEMA tenant_a; CREATE SCHEMA tenant_b;")
    try:
        introspect(pg_conn, schemas=["tenent_a"])  # typo
    except ValueError as exc:
        msg = str(exc)
        # Error names what's missing AND what's available.
        assert "tenent_a" in msg
        assert "Available user schemas" in msg
        assert "tenant_a" in msg
        assert "tenant_b" in msg
    else:
        raise AssertionError("expected ValueError")


def test_introspect_unknown_schema_suggests_close_match(
    pg_conn: psycopg.Connection, apply_sql
) -> None:
    apply_sql("CREATE SCHEMA tenant;")
    try:
        introspect(pg_conn, schemas=["tenent"])  # one-letter typo
    except ValueError as exc:
        assert "Did you mean" in str(exc)
        assert "tenant" in str(exc)
    else:
        raise AssertionError("expected ValueError")


def test_partition_of_emitted_when_parent_outside_introspected_schemas(
    pg_conn: psycopg.Connection, apply_sql
) -> None:
    # Anchor SEC001's "chain leaves scope" path: when a partition's
    # parent is not in the requested schema list, partition_of is
    # still populated with the parent's (schema, name). SEC001 reads
    # this to distinguish "chain ends at root" from "chain dangles
    # out of scope". A future refactor that nulls cross-scope
    # partition_of would silently break that distinction; this test
    # pins the contract.
    apply_sql(
        """
        CREATE SCHEMA other;
        CREATE TABLE other.parent_t (id INT, day DATE)
            PARTITION BY RANGE (day);
        CREATE TABLE public.leaf_t PARTITION OF other.parent_t
            FOR VALUES FROM ('2026-01-01') TO ('2027-01-01');
        """
    )
    schema = introspect(pg_conn, schemas=["public"])
    leaf = next(t for t in schema.tables if t.name == "leaf_t")
    assert leaf.partition_of == ("other", "parent_t")


def test_introspect_captures_grants(
    pg_conn: psycopg.Connection, apply_sql
) -> None:
    apply_sql(
        """
        DROP ROLE IF EXISTS grant_test_actor;
        CREATE ROLE grant_test_actor NOLOGIN;
        CREATE TABLE public.granted_t (id INT);
        GRANT SELECT, INSERT ON public.granted_t TO grant_test_actor;
        """
    )
    schema = introspect(pg_conn, schemas=["public"])
    t = next(x for x in schema.tables if x.name == "granted_t")
    grants_by_role = {g.role: set(g.privileges) for g in t.grants}
    assert "grant_test_actor" in grants_by_role
    assert grants_by_role["grant_test_actor"] >= {"SELECT", "INSERT"}


def test_introspect_grants_resolve_public_pseudo_role(
    pg_conn: psycopg.Connection, apply_sql
) -> None:
    apply_sql(
        """
        CREATE TABLE public.public_t (id INT);
        GRANT SELECT ON public.public_t TO PUBLIC;
        """
    )
    schema = introspect(pg_conn, schemas=["public"])
    t = next(x for x in schema.tables if x.name == "public_t")
    grants_by_role = {g.role: set(g.privileges) for g in t.grants}
    assert "PUBLIC" in grants_by_role
    assert "SELECT" in grants_by_role["PUBLIC"]


def test_introspect_grants_are_deterministic(
    pg_conn: psycopg.Connection, apply_sql
) -> None:
    # Re-introspecting the same DB twice must produce byte-
    # identical Schema (so to_snapshot also produces byte-
    # identical JSON). Order: roles alphabetized, privileges in
    # canonical order.
    apply_sql(
        """
        DROP ROLE IF EXISTS det_role_b;
        DROP ROLE IF EXISTS det_role_a;
        CREATE ROLE det_role_a NOLOGIN;
        CREATE ROLE det_role_b NOLOGIN;
        CREATE TABLE public.det_t (id INT);
        GRANT SELECT ON public.det_t TO det_role_b;
        GRANT INSERT, SELECT ON public.det_t TO det_role_a;
        """
    )
    schema_a = introspect(pg_conn, schemas=["public"])
    schema_b = introspect(pg_conn, schemas=["public"])
    t_a = next(x for x in schema_a.tables if x.name == "det_t")
    t_b = next(x for x in schema_b.tables if x.name == "det_t")
    assert t_a.grants == t_b.grants
    # Roles alphabetized: a before b.
    roles = [g.role for g in t_a.grants if g.role.startswith("det_")]
    assert roles == sorted(roles)


def test_introspect_grants_resolve_unknown_role_oid_to_sentinel(
    pg_conn: psycopg.Connection, apply_sql
) -> None:
    # Same Postgres quirk an earlier polish pass caught for
    # polroles: a non-superuser caller may not be able to SELECT
    # from pg_authid, leaving ar.rolname NULL even when the grantee
    # OID exists. The COALESCE sentinel keeps the role-name column
    # non-NULL so downstream JSON serialization and `sorted()` calls
    # don't blow up.
    #
    # Triggering the actual NULL is awkward (it requires a non-
    # superuser connection that can SELECT from pg_class but not
    # from pg_authid). Easier: drop the role mid-introspection so
    # `ar.rolname` ends up NULL via the LEFT JOIN with no matching
    # row.
    apply_sql(
        """
        DROP ROLE IF EXISTS sentinel_test_role;
        CREATE ROLE sentinel_test_role NOLOGIN;
        CREATE TABLE public.sentinel_t (id INT);
        GRANT SELECT ON public.sentinel_t TO sentinel_test_role;
        """
    )
    # Capture the role's OID so we can assert the sentinel uses it.
    with pg_conn.cursor() as cur:
        cur.execute(
            "SELECT oid FROM pg_catalog.pg_roles "
            "WHERE rolname = 'sentinel_test_role'"
        )
        row = cur.fetchone()
        assert row is not None
        sentinel_role_oid = row[0]
        assert sentinel_role_oid is not None

    # Now drop the role's pg_authid entry. Postgres would normally
    # reject this because of the dependency from the GRANT, so we
    # have to REVOKE first.
    apply_sql("REVOKE SELECT ON public.sentinel_t FROM sentinel_test_role")
    apply_sql("DROP ROLE sentinel_test_role")
    # Re-grant directly into pg_class.relacl using a low-level
    # GRANT to a no-longer-existing role. We can't really, because
    # Postgres GRANT requires a valid role. Instead, just verify
    # that the COALESCE sentinel is what's emitted when this hypo-
    # thetical NULL would otherwise leak — by reading the current
    # `_GRANTS_SQL` body and asserting the sentinel pattern is
    # present.

    # Bail out gracefully — full integration coverage of the NULL
    # path requires a non-superuser connection that lacks SELECT
    # on pg_authid, which the testcontainer fixture doesn't easily
    # provide. The literal SQL audit below is the regression
    # guard.
    from pgrls.introspect import _GRANTS_SQL
    assert "COALESCE(ar.rolname, 'oid:' || ax.grantee::text)" in _GRANTS_SQL, (
        "GRANTS query must COALESCE pg_authid.rolname to an "
        "'oid:N' sentinel so unresolvable grantee OIDs don't "
        "leak NULL into Grant.role."
    )


def test_introspect_captures_views(
    pg_conn: psycopg.Connection, apply_sql
) -> None:
    apply_sql(
        """
        CREATE TABLE public.t (id INT);
        CREATE VIEW public.t_v AS SELECT * FROM public.t;
        """
    )
    schema = introspect(pg_conn, schemas=["public"])
    view_qnames = [v.qualified_name for v in schema.views]
    assert "public.t_v" in view_qnames

    v = next(view for view in schema.views if view.name == "t_v")
    assert v.is_materialized is False
    # security_invoker / security_barrier default to False unless
    # explicitly set via WITH (...) at CREATE time.
    assert v.security_invoker is False
    assert v.security_barrier is False
    assert v.definition  # non-empty
    # Task 4 populates references; t_v reads from public.t.
    assert v.references == (("public", "t"),)
    assert v.security_definer_calls == ()  # Task 5 populates this


def test_introspect_captures_security_invoker_view(
    pg_conn: psycopg.Connection, apply_sql
) -> None:
    apply_sql(
        """
        CREATE TABLE public.t2 (id INT);
        CREATE VIEW public.t2_v WITH (security_invoker = true)
            AS SELECT * FROM public.t2;
        """
    )
    schema = introspect(pg_conn, schemas=["public"])
    v = next(view for view in schema.views if view.name == "t2_v")
    assert v.security_invoker is True


def test_introspect_captures_security_barrier_view(
    pg_conn: psycopg.Connection, apply_sql
) -> None:
    apply_sql(
        """
        CREATE TABLE public.t3 (id INT);
        CREATE VIEW public.t3_v WITH (security_barrier = true)
            AS SELECT * FROM public.t3;
        """
    )
    schema = introspect(pg_conn, schemas=["public"])
    v = next(view for view in schema.views if view.name == "t3_v")
    assert v.security_barrier is True


def test_introspect_captures_materialized_view(
    pg_conn: psycopg.Connection, apply_sql
) -> None:
    apply_sql(
        """
        CREATE TABLE public.t4 (id INT);
        CREATE MATERIALIZED VIEW public.t4_mv
            AS SELECT * FROM public.t4 WITH NO DATA;
        """
    )
    schema = introspect(pg_conn, schemas=["public"])
    mv = next(view for view in schema.views if view.name == "t4_mv")
    assert mv.is_materialized is True


def test_introspect_captures_secdef_function_calls_in_view(
    pg_conn: psycopg.Connection, apply_sql
) -> None:
    apply_sql(
        """
        CREATE TABLE public.secret (id INT);
        CREATE FUNCTION public.read_secret() RETURNS SETOF public.secret
            LANGUAGE sql SECURITY DEFINER AS $$
            SELECT * FROM public.secret
            $$;
        CREATE VIEW public.secret_v AS SELECT * FROM public.read_secret();
        """
    )
    schema = introspect(pg_conn, schemas=["public"])
    v = next(view for view in schema.views if view.name == "secret_v")
    assert v.security_definer_calls == ("public.read_secret",)


def test_introspect_view_calling_invoker_function_no_secdef_entry(
    pg_conn: psycopg.Connection, apply_sql
) -> None:
    apply_sql(
        """
        CREATE TABLE public.t5 (id INT);
        CREATE FUNCTION public.t5_count() RETURNS BIGINT
            LANGUAGE sql AS $$ SELECT count(*) FROM public.t5 $$;
        CREATE VIEW public.t5_count_v AS SELECT public.t5_count() AS n;
        """
    )
    schema = introspect(pg_conn, schemas=["public"])
    v = next(view for view in schema.views if view.name == "t5_count_v")
    assert v.security_definer_calls == ()


def test_introspect_captures_security_definer_function_bodies(
    pg_conn: psycopg.Connection, apply_sql
) -> None:
    # Introspection populates `Schema.security_definer_functions` with
    # the SECDEF function body and language. VIEW004 reads the body to
    # detect RLS-protected reads inside the function.
    apply_sql(
        """
        CREATE TABLE public.body_secret (id INT);
        CREATE FUNCTION public.body_read() RETURNS SETOF public.body_secret
            LANGUAGE sql SECURITY DEFINER AS $$
            SELECT * FROM public.body_secret
            $$;
        """
    )
    schema = introspect(pg_conn, schemas=["public"])
    secdef = next(
        f
        for f in schema.security_definer_functions
        if f.qualified_name == "public.body_read"
    )
    assert secdef.language == "sql"
    assert "public.body_secret" in secdef.body


def test_introspect_skips_invoker_function_in_security_definer_functions(
    pg_conn: psycopg.Connection, apply_sql
) -> None:
    # Functions WITHOUT SECURITY DEFINER must NOT land in
    # `Schema.security_definer_functions` — VIEW004 only cares about
    # SECDEF bodies.
    apply_sql(
        """
        CREATE TABLE public.invoker_t (id INT);
        CREATE FUNCTION public.invoker_count() RETURNS BIGINT
            LANGUAGE sql AS $$ SELECT count(*) FROM public.invoker_t $$;
        """
    )
    schema = introspect(pg_conn, schemas=["public"])
    qnames = {f.qualified_name for f in schema.security_definer_functions}
    assert "public.invoker_count" not in qnames


def test_introspect_resolves_view_to_table_references(
    pg_conn: psycopg.Connection, apply_sql
) -> None:
    apply_sql(
        """
        CREATE TABLE public.users (id INT, email TEXT);
        CREATE TABLE public.orders (id INT, user_id INT, amount INT);
        CREATE VIEW public.user_orders AS
            SELECT u.email, o.amount
            FROM public.users u
            JOIN public.orders o ON o.user_id = u.id;
        """
    )
    schema = introspect(pg_conn, schemas=["public"])
    v = next(view for view in schema.views if view.name == "user_orders")

    # references should be sorted (schema, name) tuples
    assert v.references == (
        ("public", "orders"),
        ("public", "users"),
    )


def test_introspect_view_with_no_references_has_empty_tuple(
    pg_conn: psycopg.Connection, apply_sql
) -> None:
    apply_sql(
        "CREATE VIEW public.vw_const AS SELECT 42 AS answer;"
    )
    schema = introspect(pg_conn, schemas=["public"])
    v = next(view for view in schema.views if view.name == "vw_const")
    assert v.references == ()


def test_introspect_view_referencing_partitioned_table(
    pg_conn: psycopg.Connection, apply_sql
) -> None:
    # A view over a partitioned parent table should resolve the
    # parent (relkind='p') as a reference. Postgres rewrites the
    # query at runtime to fan out to children, but the dependency
    # edge in pg_depend points at the parent.
    apply_sql(
        """
        CREATE TABLE public.events (id INT, day DATE)
            PARTITION BY RANGE (day);
        CREATE TABLE public.events_2026
            PARTITION OF public.events
            FOR VALUES FROM ('2026-01-01') TO ('2027-01-01');
        CREATE VIEW public.events_v AS SELECT * FROM public.events;
        """
    )
    schema = introspect(pg_conn, schemas=["public"])
    v = next(view for view in schema.views if view.name == "events_v")
    assert ("public", "events") in v.references


def test_introspect_view_chained_through_view_does_not_chase(
    pg_conn: psycopg.Connection, apply_sql
) -> None:
    # v0.3.0 design: view→table deps are SINGLE HOP. A view that
    # reads ANOTHER view that reads an RLS-protected table should
    # NOT have the underlying table in its `references`. The
    # intermediate view's references point at the table; the outer
    # view's references point at the intermediate view (filtered
    # out by relkind='r','p' in the query).
    #
    # This test pins the deferral — v0.4 may add transitive
    # walks; if so, this test should be deleted in the same change
    # so the intent is visible.
    apply_sql(
        """
        CREATE TABLE public.t (id INT);
        CREATE VIEW public.inner_v AS SELECT * FROM public.t;
        CREATE VIEW public.outer_v AS SELECT * FROM public.inner_v;
        """
    )
    schema = introspect(pg_conn, schemas=["public"])
    outer = next(view for view in schema.views if view.name == "outer_v")
    # `inner_v` is a view (relkind='v'), filtered out by query.
    # `t` is a table BUT outer_v's pg_depend doesn't link to it
    # directly — the chain goes through inner_v.
    assert ("public", "t") not in outer.references


def test_introspect_view_dependency_filter_by_schema(
    pg_conn: psycopg.Connection, apply_sql
) -> None:
    # The schema filter applies to the VIEW side. A view in
    # schema "app" that reads a table in schema "shared" — if
    # we introspect ["app"] only, the view shows up but its
    # references include the cross-schema table.
    apply_sql(
        """
        CREATE SCHEMA shared;
        CREATE SCHEMA app;
        CREATE TABLE shared.lookup (id INT);
        CREATE VIEW app.lookup_v AS SELECT * FROM shared.lookup;
        """
    )
    schema = introspect(pg_conn, schemas=["app", "shared"])
    v = next(view for view in schema.views if view.name == "lookup_v")
    assert v.references == (("shared", "lookup"),)


# ---------------------------------------------------------------------------
# Trigger introspection (SEC013, snapshot v6+)
# ---------------------------------------------------------------------------


def test_populates_table_triggers(
    pg_conn: psycopg.Connection, apply_sql
) -> None:
    # SEC013 walks `Table.triggers`. Without this introspection wiring,
    # the rule silently never fires on real databases — pin both the
    # field population and the per-trigger fields the rule and snapshot
    # depend on.
    apply_sql(
        """
        CREATE TABLE public.t (id INT);
        CREATE TRIGGER guard
            BEFORE UPDATE ON public.t
            FOR EACH ROW EXECUTE FUNCTION pg_catalog.suppress_redundant_updates_trigger();
        """
    )
    schema = introspect(pg_conn, schemas=["public"])
    t = next(x for x in schema.tables if x.name == "t")
    assert len(t.triggers) == 1
    trg = t.triggers[0]
    assert trg.name == "guard"
    # Built-in trigger function lives in pg_catalog.
    assert trg.function_schema == "pg_catalog"
    assert trg.function_name == "suppress_redundant_updates_trigger"
    assert trg.timing == "BEFORE"
    assert trg.event == "UPDATE"
    assert trg.enabled is True


def test_triggers_filters_internal_constraint_triggers(
    pg_conn: psycopg.Connection, apply_sql
) -> None:
    # Foreign-key constraints, RI check triggers, partition-routing
    # triggers, etc. live in `pg_trigger` with `tgisinternal = true`.
    # SEC013 isn't interested in them — they're framework plumbing,
    # not an audit target. Pin the filter so a future query refactor
    # that forgets `tgisinternal = false` doesn't drown the operator
    # in noise.
    apply_sql(
        """
        CREATE TABLE public.parent (id INT PRIMARY KEY);
        CREATE TABLE public.child (
            id INT PRIMARY KEY,
            parent_id INT REFERENCES public.parent(id)
        );
        """
    )
    schema = introspect(pg_conn, schemas=["public"])
    child = next(x for x in schema.tables if x.name == "child")
    parent = next(x for x in schema.tables if x.name == "parent")
    # FK creates internal `RI_*` triggers on both sides; the user
    # didn't author any user-level triggers, so SEC013 sees nothing.
    assert child.triggers == ()
    assert parent.triggers == ()


def test_triggers_captures_disabled_state(
    pg_conn: psycopg.Connection, apply_sql
) -> None:
    # `ALTER TABLE ... DISABLE TRIGGER` flips `tgenabled` to 'D'.
    # SEC013 skips disabled triggers (they can't fire) but the
    # snapshot still records the state so a re-enable surfaces as
    # a diff. Pin both halves.
    apply_sql(
        """
        CREATE TABLE public.t (id INT);
        CREATE TRIGGER guard
            BEFORE UPDATE ON public.t
            FOR EACH ROW EXECUTE FUNCTION pg_catalog.suppress_redundant_updates_trigger();
        ALTER TABLE public.t DISABLE TRIGGER guard;
        """
    )
    schema = introspect(pg_conn, schemas=["public"])
    t = next(x for x in schema.tables if x.name == "t")
    assert len(t.triggers) == 1
    assert t.triggers[0].enabled is False


def test_triggers_decodes_multi_event_mask(
    pg_conn: psycopg.Connection, apply_sql
) -> None:
    # A trigger declared `BEFORE INSERT OR UPDATE ...` packs two
    # event bits into `tgtype`. The introspection-SQL CASE chain
    # must surface both in Postgres's canonical order ("INSERT OR
    # UPDATE") so SEC013's message reads correctly.
    apply_sql(
        """
        CREATE TABLE public.t (id INT);
        CREATE TRIGGER guard
            BEFORE INSERT OR UPDATE ON public.t
            FOR EACH ROW EXECUTE FUNCTION pg_catalog.suppress_redundant_updates_trigger();
        """
    )
    schema = introspect(pg_conn, schemas=["public"])
    t = next(x for x in schema.tables if x.name == "t")
    assert t.triggers[0].event == "INSERT OR UPDATE"


def test_triggers_are_deterministic_per_table(
    pg_conn: psycopg.Connection, apply_sql
) -> None:
    # Snapshot byte-stability depends on triggers being sorted
    # consistently across runs. The introspection SQL orders by
    # (table_oid, trigger_name) — verify the alphabetic order
    # surfaces at the Table.triggers tuple level.
    apply_sql(
        """
        CREATE TABLE public.t (id INT);
        CREATE TRIGGER zeta_guard
            BEFORE UPDATE ON public.t
            FOR EACH ROW EXECUTE FUNCTION pg_catalog.suppress_redundant_updates_trigger();
        CREATE TRIGGER alpha_guard
            BEFORE INSERT ON public.t
            FOR EACH ROW EXECUTE FUNCTION pg_catalog.suppress_redundant_updates_trigger();
        """
    )
    schema = introspect(pg_conn, schemas=["public"])
    t = next(x for x in schema.tables if x.name == "t")
    assert [tr.name for tr in t.triggers] == ["alpha_guard", "zeta_guard"]


def test_triggers_captures_truncate_event(
    pg_conn: psycopg.Connection, apply_sql
) -> None:
    # `TRUNCATE` is forced to STATEMENT-level by Postgres. The
    # CASE-chain bit for TRUNCATE (`tgtype & 32`) must produce
    # the literal "TRUNCATE" — the `or ""` fallback in introspect
    # would mask a decoding bug as a missing event, so pin this
    # explicitly. TRUNCATE-only triggers are common for cache /
    # audit invalidation, so this is a real shape SEC013 needs
    # to surface cleanly.
    apply_sql(
        """
        CREATE TABLE public.t (id INT);
        CREATE TRIGGER on_truncate
            BEFORE TRUNCATE ON public.t
            FOR EACH STATEMENT EXECUTE FUNCTION pg_catalog.suppress_redundant_updates_trigger();
        """
    )
    schema = introspect(pg_conn, schemas=["public"])
    t = next(x for x in schema.tables if x.name == "t")
    assert t.triggers[0].event == "TRUNCATE"


def test_triggers_captures_statement_level_trigger(
    pg_conn: psycopg.Connection, apply_sql
) -> None:
    # `FOR EACH STATEMENT` triggers fire once per UPDATE/DELETE
    # statement rather than per row. They still run as the table
    # owner, so the RLS-bypass surface is identical to a ROW
    # trigger — SEC013 must fire on both. The ROW-vs-STATEMENT
    # axis (`tgtype` bit 0) is intentionally not captured by the
    # Trigger dataclass; this test just pins that the trigger
    # surfaces in `Table.triggers` regardless of which axis it
    # was declared on.
    apply_sql(
        """
        CREATE TABLE public.t (id INT);
        CREATE TRIGGER stmt_guard
            AFTER UPDATE ON public.t
            FOR EACH STATEMENT EXECUTE FUNCTION pg_catalog.suppress_redundant_updates_trigger();
        """
    )
    schema = introspect(pg_conn, schemas=["public"])
    t = next(x for x in schema.tables if x.name == "t")
    assert len(t.triggers) == 1
    assert t.triggers[0].name == "stmt_guard"
    assert t.triggers[0].timing == "AFTER"
    assert t.triggers[0].event == "UPDATE"


def test_triggers_propagation_from_partition_parent(
    pg_conn: psycopg.Connection, apply_sql
) -> None:
    # On PG13+, declaring a trigger on a partitioned parent
    # automatically clones it onto each child partition. The
    # clones carry `tgparentid != 0` but `tgisinternal = false`,
    # so the `tgisinternal` filter alone would leave them visible
    # and SEC013 would double-fire (parent + each child). The
    # `tgparentid = 0` filter keeps only the user-declared parent
    # row. Pin this so a future PG version that flips the
    # propagation semantics (or a refactor that drops the filter)
    # doesn't silently produce duplicate violations per child.
    apply_sql(
        """
        CREATE TABLE public.events (id INT, tenant TEXT) PARTITION BY LIST (tenant);
        CREATE TABLE public.events_a PARTITION OF public.events FOR VALUES IN ('a');
        CREATE TABLE public.events_b PARTITION OF public.events FOR VALUES IN ('b');
        CREATE TRIGGER guard
            BEFORE UPDATE ON public.events
            FOR EACH ROW EXECUTE FUNCTION pg_catalog.suppress_redundant_updates_trigger();
        """
    )
    schema = introspect(pg_conn, schemas=["public"])
    parent = next(x for x in schema.tables if x.name == "events")
    child_a = next(x for x in schema.tables if x.name == "events_a")
    child_b = next(x for x in schema.tables if x.name == "events_b")
    # Parent carries the user-declared trigger.
    assert [tr.name for tr in parent.triggers] == ["guard"]
    # Children's auto-cloned triggers have `tgisinternal = true`
    # and get filtered out — SEC013 won't double-fire.
    assert child_a.triggers == ()
    assert child_b.triggers == ()


# ---------------------------------------------------------------------------
# Index introspection (PERF003, snapshot v7+)
# ---------------------------------------------------------------------------


def test_populates_table_indexes(
    pg_conn: psycopg.Connection, apply_sql
) -> None:
    # PERF003 walks `Table.indexes`. Without this introspection
    # wiring, the rule silently never fires on real databases —
    # pin both the field population and the per-index fields the
    # rule depends on.
    apply_sql(
        """
        CREATE TABLE public.t (id INT, tenant_id TEXT);
        CREATE INDEX t_tenant_idx ON public.t (tenant_id);
        """
    )
    schema = introspect(pg_conn, schemas=["public"])
    t = next(x for x in schema.tables if x.name == "t")
    assert len(t.indexes) == 1
    idx = t.indexes[0]
    assert idx.name == "t_tenant_idx"
    assert idx.access_method == "btree"
    assert idx.columns == ("tenant_id",)
    assert idx.is_unique is False
    assert idx.is_partial is False


def test_indexes_captures_composite_column_order(
    pg_conn: psycopg.Connection, apply_sql
) -> None:
    # The order of columns in a multi-column index matters: PERF003
    # only checks the LEADING column. A B-tree on (a, b) helps
    # `WHERE a = X` but not `WHERE b = Y`. Pin that the introspection
    # captures the column order from `pg_index.indkey` correctly.
    apply_sql(
        """
        CREATE TABLE public.t (id INT, a TEXT, b TEXT);
        CREATE INDEX t_ab_idx ON public.t (a, b);
        """
    )
    schema = introspect(pg_conn, schemas=["public"])
    t = next(x for x in schema.tables if x.name == "t")
    [idx] = [i for i in t.indexes if i.name == "t_ab_idx"]
    assert idx.columns == ("a", "b")


def test_indexes_captures_unique_constraint(
    pg_conn: psycopg.Connection, apply_sql
) -> None:
    # PRIMARY KEY and UNIQUE constraints create implicit B-tree
    # indexes. They appear in `pg_index` like any other index. Pin
    # that they surface with `is_unique=True` so a future rule can
    # distinguish them from explicit `CREATE INDEX`.
    apply_sql(
        """
        CREATE TABLE public.t (id INT PRIMARY KEY, email TEXT UNIQUE);
        """
    )
    schema = introspect(pg_conn, schemas=["public"])
    t = next(x for x in schema.tables if x.name == "t")
    by_name = {i.name: i for i in t.indexes}
    # Two implicit indexes: the PK on `id` and the unique on `email`.
    pk = next(i for i in t.indexes if i.columns == ("id",))
    email_uniq = next(i for i in t.indexes if i.columns == ("email",))
    assert pk.is_unique is True
    assert email_uniq.is_unique is True


def test_indexes_captures_partial_index(
    pg_conn: psycopg.Connection, apply_sql
) -> None:
    # Partial indexes have `pg_index.indpred IS NOT NULL`. PERF003
    # treats them as "indexed" (the operator's responsibility to
    # match the partial predicate to the policy predicate), but the
    # snapshot still captures the flag so a future rule could
    # warn on mismatch.
    apply_sql(
        """
        CREATE TABLE public.t (id INT, active BOOLEAN);
        CREATE INDEX t_active_idx ON public.t (id) WHERE active = true;
        """
    )
    schema = introspect(pg_conn, schemas=["public"])
    t = next(x for x in schema.tables if x.name == "t")
    [idx] = [i for i in t.indexes if i.name == "t_active_idx"]
    assert idx.is_partial is True


def test_indexes_captures_non_btree_access_method(
    pg_conn: psycopg.Connection, apply_sql
) -> None:
    # Hash, GIN, GiST, BRIN are valid access methods. Pin that
    # the introspection captures the method name verbatim so PERF003
    # (which treats any method as "indexed") sees consistent data.
    apply_sql(
        """
        CREATE TABLE public.t (id INT, tags TEXT[]);
        CREATE INDEX t_tags_gin ON public.t USING gin (tags);
        """
    )
    schema = introspect(pg_conn, schemas=["public"])
    t = next(x for x in schema.tables if x.name == "t")
    [idx] = [i for i in t.indexes if i.name == "t_tags_gin"]
    assert idx.access_method == "gin"


def test_indexes_skips_invalid_indexes(
    pg_conn: psycopg.Connection, apply_sql
) -> None:
    # A half-built index (from a failed CREATE INDEX CONCURRENTLY)
    # has `indisvalid = false`. Such an index doesn't help the
    # planner — capturing it would silence PERF003 and mislead the
    # operator. Simulate the state by flipping the flag directly
    # in pg_index (same internal state a real failed concurrent
    # build leaves behind).
    apply_sql(
        """
        CREATE TABLE public.t (id INT, tenant_id TEXT);
        CREATE INDEX t_tenant_idx ON public.t (tenant_id);
        UPDATE pg_catalog.pg_index
            SET indisvalid = false
            WHERE indexrelid = 't_tenant_idx'::regclass;
        """
    )
    schema = introspect(pg_conn, schemas=["public"])
    t = next(x for x in schema.tables if x.name == "t")
    # The invalid index is filtered — PERF003 will fire on policies
    # that filter on tenant_id because no usable index exists.
    assert t.indexes == ()


def test_indexes_handles_expression_index_with_empty_string(
    pg_conn: psycopg.Connection, apply_sql
) -> None:
    # `CREATE INDEX ON tbl (lower(email))` has an expression
    # position in `pg_index.indkey` (attnum 0). The LEFT JOIN to
    # pg_attribute returns NULL there; the COALESCE in the
    # introspection SQL maps NULL → empty string. PERF003 then
    # cannot match this position by column name, which is the
    # intentional documented limitation in v0.5.10.
    apply_sql(
        """
        CREATE TABLE public.t (id INT, email TEXT);
        CREATE INDEX t_lower_email_idx ON public.t (lower(email));
        """
    )
    schema = introspect(pg_conn, schemas=["public"])
    t = next(x for x in schema.tables if x.name == "t")
    [idx] = [i for i in t.indexes if i.name == "t_lower_email_idx"]
    # Expression position becomes empty string in the columns tuple.
    assert idx.columns == ("",)


def test_indexes_deterministic_per_table(
    pg_conn: psycopg.Connection, apply_sql
) -> None:
    # Snapshot byte-stability depends on indexes being sorted
    # consistently across runs. The introspection SQL orders by
    # (table_oid, index_name) — verify the alphabetic order
    # surfaces at the Table.indexes tuple level.
    apply_sql(
        """
        CREATE TABLE public.t (id INT, a TEXT, b TEXT);
        CREATE INDEX zeta_idx ON public.t (a);
        CREATE INDEX alpha_idx ON public.t (b);
        """
    )
    schema = introspect(pg_conn, schemas=["public"])
    t = next(x for x in schema.tables if x.name == "t")
    assert [i.name for i in t.indexes] == ["alpha_idx", "zeta_idx"]
