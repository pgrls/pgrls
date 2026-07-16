"""Use case 8: INSERT without WITH CHECK — SEC006."""
from __future__ import annotations

import psycopg
import pytest


def test_uc08_insert_without_with_check_fires_sec006(
    lint_output: str,
) -> None:
    assert "SEC006  app.invoices.invoices_insert_open\n" in lint_output


def test_uc08_using_only_update_is_closed_by_postgres(demo_db: str) -> None:
    """SEC006's SUPPRESSION premise, proven against live Postgres.

    SEC006 deliberately does NOT flag a FOR UPDATE/ALL policy that has a real
    USING and no WITH CHECK, because Postgres reuses the USING expression as
    the implicit WITH CHECK — the written row must still satisfy it, so the
    shape is closed.

    That silence is only as sound as the reuse behavior, and this is exactly
    where SEC006 was once WRONG: it flagged the shape as an open write, and
    its restrictive branch's "dead policy — remove it" remediation would have
    told people to delete a real write-side constraint. The unit tests pin our
    MODEL of the reuse; nothing pinned Postgres. This does.

    If Postgres ever stopped reusing USING, the suppression would silently
    become a false negative — a write hole we deliberately stay quiet about.
    This test fails loudly instead.

    Everything (DDL included) runs in a force-rolled-back transaction, so the
    demo schema the lint fixtures introspect is untouched.
    """
    with psycopg.connect(demo_db) as conn:
        with conn.transaction(force_rollback=True):
            with conn.cursor() as cur:
                cur.execute(
                    "CREATE TABLE app.uc08_reuse (id int PRIMARY KEY, owner text)"
                )
                cur.execute("ALTER TABLE app.uc08_reuse ENABLE ROW LEVEL SECURITY")
                cur.execute("ALTER TABLE app.uc08_reuse FORCE ROW LEVEL SECURITY")
                cur.execute("INSERT INTO app.uc08_reuse VALUES (1, 'alice')")
                # The SELECT policy is USING(true) ON PURPOSE. A column-reading
                # `UPDATE ... WHERE` re-checks the NEW row against the
                # SELECT-applicable policy too, so a scoped SELECT policy would
                # block the reassign all by itself and this test would pass even
                # if the USING-reuse under test had vanished. USING(true) removes
                # that confound: the reused UPDATE USING is then the ONLY thing
                # that can reject the write.
                cur.execute(
                    "CREATE POLICY uc08_reuse_sel ON app.uc08_reuse FOR SELECT "
                    "TO app_authenticated USING (true)"
                )
                cur.execute(
                    "CREATE POLICY uc08_reuse_upd ON app.uc08_reuse FOR UPDATE "
                    "TO app_authenticated "
                    "USING (owner = current_setting('app.owner', true))"
                )
                cur.execute("GRANT USAGE ON SCHEMA app TO app_authenticated")
                cur.execute(
                    "GRANT SELECT, UPDATE ON app.uc08_reuse TO app_authenticated"
                )
                cur.execute("SET LOCAL ROLE app_authenticated")
                cur.execute("SELECT set_config('app.owner', 'alice', true)")
                # The reassign the "forgot WITH CHECK" folk model says lands.
                # Postgres rejects it: the reused USING is the implicit check.
                # `match=` is load-bearing — 42501 is also "permission denied",
                # so a bare raises() would pass if a GRANT above had failed.
                with pytest.raises(
                    psycopg.errors.InsufficientPrivilege,
                    match="row-level security",
                ):
                    cur.execute(
                        "UPDATE app.uc08_reuse SET owner = 'bob' WHERE id = 1"
                    )
