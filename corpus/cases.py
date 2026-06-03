"""Adjudicated precision corpus — the labeled cases.

Every :class:`Case` is a small, self-contained schema applied to a fresh
``public`` schema (see :mod:`corpus.harness`). ``expect`` is the COMPLETE
set of rule IDs that should fire; for a *negative* case it is empty.

Authoring discipline
--------------------
Cases start from a **clean gold-standard base** — RLS enabled and forced,
the policy predicate wrapped in ``(SELECT …)`` (so PERF001 stays quiet,
matching ``pgrls generate`` output), the filter column ``NOT NULL`` and
indexed, a restrictive floor so the table isn't all-permissive (SEC007),
and grants to a concrete role, never ``PUBLIC`` (SEC003) — then perturb
**one** thing:

* **Positive** cases introduce exactly one violation; ``expect`` lists
  every rule that legitimately fires (usually one).
* **Negative** cases introduce an *adversarial near-miss* — a shape that
  looks like a violation but is safe (lifted from the rules' documented
  blind spots and the unit suite's ``does_not_fire`` cases) — and must
  stay silent. These are where false positives surface.
* ``known_fp`` records a firing adjudicated as a real false positive but
  not yet fixed. It still counts as an FP in the published numbers; it
  just doesn't fail the regression test. Empty unless a documented bug
  exists.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal


@dataclass(frozen=True)
class Case:
    name: str
    kind: Literal["positive", "negative"]
    expect: frozenset[str]
    sql: str
    note: str
    known_fp: frozenset[str] = field(default=frozenset())


# Wrapped, index-friendly session predicates. The `(SELECT …)` wrapper is
# what `pgrls generate` emits and what keeps PERF001 quiet.
_TENANT_PRED = "tenant_id = (SELECT current_setting('app.tenant_id', true)::uuid)"
_OWNER_PRED = "owner_id = (SELECT auth.uid())"


def _clean_tenant(table: str, *, pred: str = _TENANT_PRED, floor: bool = True) -> str:
    """A gold-standard tenant-isolation table that lints clean."""
    parts = [
        f"CREATE TABLE public.{table} "
        f"(id uuid PRIMARY KEY, tenant_id uuid NOT NULL, body text);",
        f"ALTER TABLE public.{table} ENABLE ROW LEVEL SECURITY;",
        f"ALTER TABLE public.{table} FORCE ROW LEVEL SECURITY;",
        f"CREATE POLICY {table}_iso ON public.{table} "
        f"FOR ALL TO authenticated USING ({pred}) WITH CHECK ({pred});",
    ]
    if floor:
        parts.append(
            f"CREATE POLICY {table}_floor ON public.{table} AS RESTRICTIVE "
            f"FOR ALL TO authenticated USING ({_TENANT_PRED}) WITH CHECK ({_TENANT_PRED});"
        )
    parts.append(f"CREATE INDEX ON public.{table} (tenant_id);")
    return "\n".join(parts)


def _clean_owner(table: str, *, pred: str = _OWNER_PRED, floor: bool = True) -> str:
    """A gold-standard per-user (row-owner) table that lints clean."""
    parts = [
        f"CREATE TABLE public.{table} "
        f"(id uuid PRIMARY KEY, owner_id uuid NOT NULL, shared bool NOT NULL DEFAULT false);",
        f"ALTER TABLE public.{table} ENABLE ROW LEVEL SECURITY;",
        f"ALTER TABLE public.{table} FORCE ROW LEVEL SECURITY;",
        f"CREATE POLICY {table}_own ON public.{table} "
        f"FOR ALL TO authenticated USING ({pred}) WITH CHECK ({pred});",
    ]
    if floor:
        parts.append(
            f"CREATE POLICY {table}_floor ON public.{table} AS RESTRICTIVE "
            f"FOR ALL TO authenticated USING ({_OWNER_PRED}) WITH CHECK ({_OWNER_PRED});"
        )
    parts.append(f"CREATE INDEX ON public.{table} (owner_id);")
    return "\n".join(parts)


CASES: list[Case] = [
    # ============================ negatives ============================
    # Clean gold-standard shapes and adversarial near-misses. Every one
    # must lint silent; anything that fires is a false positive.
    Case(
        name="goldstandard-tenant",
        kind="negative",
        expect=frozenset(),
        note="Canonical `pgrls generate` tenant output — the headline "
        "clean case.",
        sql=_clean_tenant("posts"),
    ),
    Case(
        name="goldstandard-owner",
        kind="negative",
        expect=frozenset(),
        note="Canonical row-owner output: `owner_id = (SELECT auth.uid())` "
        "+ restrictive floor.",
        sql=_clean_owner("docs"),
    ),
    Case(
        name="sec004-coalesce-wrapper-safe",
        kind="negative",
        expect=frozenset(),
        note="auth.uid() inside coalesce() to a sentinel uuid — not an "
        "`IS NULL` disjunct, and anonymous maps to a uuid no row owns. "
        "SEC004's documented blind spot; must stay silent.",
        sql=_clean_owner(
            "notes",
            pred="coalesce((SELECT auth.uid()), "
            "'00000000-0000-0000-0000-000000000000'::uuid) = owner_id",
        ),
    ),
    Case(
        name="sec004-is-null-under-and-safe",
        kind="negative",
        expect=frozenset(),
        note="`IS NULL` gated by AND is not a standalone anonymous hole — "
        "the AND still requires the real check (here: only rows owned by a "
        "session-configured public owner are anon-visible). flatten_or must "
        "not descend through AND. Both branches filter the indexed owner_id "
        "against wrapped session reads (no literal, no extra column), so it "
        "stays clean.",
        sql=_clean_owner(
            "memos",
            pred="owner_id = (SELECT auth.uid()) OR "
            "(owner_id = (SELECT current_setting('app.public_owner', true)::uuid) "
            "AND (SELECT auth.uid()) IS NULL)",
        ),
    ),
    Case(
        name="sec004-is-null-in-subquery-safe",
        kind="negative",
        expect=frozenset(),
        note="`IS NULL` buried inside a SubLink (EXISTS) is not a "
        "top-level disjunct; SEC004 must not descend into subqueries.",
        sql=_clean_owner(
            "shares",
            pred="owner_id = (SELECT auth.uid()) OR EXISTS "
            "(SELECT 1 FROM public.shares s2 WHERE s2.id = shares.id "
            "AND (SELECT auth.uid()) IS NULL)",
        ),
    ),
    Case(
        name="sec004-is-not-null-safe",
        kind="negative",
        expect=frozenset(),
        note="`IS NOT NULL` is the correct guard, the inverse of the "
        "vuln. Must not fire SEC004.",
        sql=_clean_owner(
            "files",
            pred="(SELECT auth.uid()) IS NOT NULL AND owner_id = (SELECT auth.uid())",
        ),
    ),
    # (The intentional-public-data FP guard — a constant / bool carve-out
    # that is satisfiable-but-not-valid under anon, so SEC038 must stay
    # silent — is exercised by the unit suite (test_sec038_clean_on_narrow
    # _public_carveout / _shared_bool_carveout) and the encoder suite
    # (test_anon_clean_on_narrow_public_carveout / _shared_bool_carveout).
    # It is omitted from the corpus because every such carve-out shape on
    # the gold-standard table co-fires an orthogonal rule — SEC021 on a
    # literal-vs-identity-column compare, PERF003 on an unindexed bool
    # discriminator — which would obscure the SEC038-stays-clean signal the
    # corpus negative is meant to isolate. The existing negatives below
    # already prove SEC038 stays silent on real safe shapes.)
    # ============================ positives ============================
    Case(
        name="sec001-no-rls",
        kind="positive",
        expect=frozenset({"SEC001"}),
        note="Plain table, row security never enabled.",
        sql="CREATE TABLE public.audit (id uuid PRIMARY KEY, msg text NOT NULL);",
    ),
    Case(
        name="sec002-rls-not-forced",
        kind="positive",
        expect=frozenset({"SEC002"}),
        note="RLS enabled but not FORCEd — the table owner bypasses every "
        "policy. Otherwise gold-standard.",
        sql=_clean_tenant("ledger").replace(
            "ALTER TABLE public.ledger FORCE ROW LEVEL SECURITY;\n", ""
        ),
    ),
    Case(
        name="sec003-policy-to-public",
        kind="positive",
        expect=frozenset({"SEC003"}),
        note="Permissive policy granted to PUBLIC — applies to every role "
        "including anonymous.",
        sql=_clean_tenant("orders").replace("TO authenticated", "TO PUBLIC"),
    ),
    Case(
        name="sec004-inverted-auth",
        kind="positive",
        expect=frozenset({"SEC004", "SEC038"}),
        note="Lovable CVE shape: `(SELECT current_setting()) IS NULL OR …` "
        "top-level disjunct. Wrapped so PERF001 stays quiet; SEC004 still "
        "fires (it descends into the SubLink). SEC038 (semantic, Z3-backed) "
        "co-fires here — under anon the current_setting is NULL, so the IS "
        "NULL disjunct is TRUE for every row (anon-valid). Two independent "
        "detectors agreeing on the same catastrophic leak.",
        sql=_clean_owner(
            "accounts",
            pred="(SELECT current_setting('app.user_id', true))::uuid IS NULL "
            "OR owner_id = (SELECT auth.uid())",
        ),
    ),
    Case(
        name="sec038-not-wrapped-auth",
        kind="positive",
        expect=frozenset({"SEC038"}),
        note="Semantic-only anon-read: `NOT ((SELECT auth.uid()) IS NOT "
        "NULL)` is `auth.uid() IS NULL` — but SEC004's literal "
        "`auth() IS NULL` matcher misses the NOT-wrapped form (verified: "
        "SEC004 stays silent here, SEC038 fires). Under anon the disjunct "
        "is TRUE for every row → anon-valid → SEC038 fires. The headline "
        "value of the semantic check; the second disjunct is the real owner "
        "check (no literal) so SEC021 stays quiet and SEC038 is the only "
        "finding. (The `::bool`-cast variant is covered by the unit + "
        "encoder suites, where the predicate is parsed directly; Postgres "
        "elides the redundant `::bool` on a round-trip, collapsing it to "
        "the plain `IS NULL` shape SEC004 already catches.)",
        sql=_clean_owner(
            "vaults",
            pred="NOT ((SELECT auth.uid()) IS NOT NULL) "
            "OR owner_id = (SELECT auth.uid())",
        ),
    ),
    Case(
        # Re-adjudicated (was a stale `positive` expecting SEC006). An
        # UPDATE policy with USING only and no WITH CHECK LOOKS like a
        # missing-write-check hole, but Postgres reuses the USING expression
        # as the implicit WITH CHECK on UPDATE, so the written row must still
        # satisfy `tenant_id = <session>`; the restrictive floor's WITH CHECK
        # reinforces it. Verified on live PG16: a cross-tenant UPDATE is
        # rejected ("new row violates row-level security policy"). This is the
        # documented reused-USING shape SEC006 must NOT flag — the FP closed
        # in the SEC006 false-positive fixes — so it belongs here as the
        # adversarial near-miss, not as a positive.
        name="sec006-update-using-reused-as-check",
        kind="negative",
        expect=frozenset(),
        note="UPDATE policy with USING only, no WITH CHECK. Safe: Postgres "
        "reuses the USING as the implicit WITH CHECK on UPDATE (write side "
        "closed), reinforced by the restrictive floor. SEC006 must NOT fire.",
        sql="""
CREATE TABLE public.invoices (id uuid PRIMARY KEY, tenant_id uuid NOT NULL, amount int);
ALTER TABLE public.invoices ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.invoices FORCE ROW LEVEL SECURITY;
CREATE POLICY inv_sel ON public.invoices FOR SELECT TO authenticated
    USING (tenant_id = (SELECT current_setting('app.tenant_id', true)::uuid));
CREATE POLICY inv_upd ON public.invoices FOR UPDATE TO authenticated
    USING (tenant_id = (SELECT current_setting('app.tenant_id', true)::uuid));
CREATE POLICY inv_floor ON public.invoices AS RESTRICTIVE FOR ALL TO authenticated
    USING (tenant_id = (SELECT current_setting('app.tenant_id', true)::uuid))
    WITH CHECK (tenant_id = (SELECT current_setting('app.tenant_id', true)::uuid));
CREATE INDEX ON public.invoices (tenant_id);
""",
    ),
    Case(
        # The GENUINE SEC006 hole (replaces the positive coverage the
        # re-adjudicated case above used to provide): a permissive INSERT
        # policy with no WITH CHECK. INSERT carries no USING for Postgres to
        # reuse, so the missing WITH CHECK leaves the policy's write side
        # unconstrained — exactly the open shape SEC006 flags. Verified on
        # live PG16 that this fires SEC006 and nothing else.
        name="sec006-insert-no-with-check",
        kind="positive",
        expect=frozenset({"SEC006"}),
        note="Permissive INSERT policy with no WITH CHECK — INSERT has no "
        "USING to reuse, so the missing write check is the genuine open "
        "shape SEC006 flags (the inverse of the reused-USING UPDATE above).",
        sql="""
CREATE TABLE public.orders (id uuid PRIMARY KEY, tenant_id uuid NOT NULL, body text);
ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.orders FORCE ROW LEVEL SECURITY;
CREATE POLICY orders_sel ON public.orders FOR SELECT TO authenticated
    USING (tenant_id = (SELECT current_setting('app.tenant_id', true)::uuid));
CREATE POLICY orders_ins ON public.orders FOR INSERT TO authenticated;
CREATE POLICY orders_floor ON public.orders AS RESTRICTIVE FOR ALL TO authenticated
    USING (tenant_id = (SELECT current_setting('app.tenant_id', true)::uuid))
    WITH CHECK (tenant_id = (SELECT current_setting('app.tenant_id', true)::uuid));
CREATE INDEX ON public.orders (tenant_id);
""",
    ),
    Case(
        name="perf001-unwrapped-current-setting",
        kind="positive",
        expect=frozenset({"PERF001"}),
        note="Discriminator predicate calls current_setting() unwrapped — "
        "evaluated per row. Otherwise gold-standard.",
        sql=_clean_tenant(
            "events",
            pred="tenant_id = current_setting('app.tenant_id', true)::uuid",
        ).replace(
            # also unwrap the floor so PERF001 is the only finding and the
            # floor doesn't double as a second clean predicate
            "USING (tenant_id = (SELECT current_setting('app.tenant_id', true)::uuid)) "
            "WITH CHECK (tenant_id = (SELECT current_setting('app.tenant_id', true)::uuid))",
            "USING (tenant_id = current_setting('app.tenant_id', true)::uuid) "
            "WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::uuid)",
        ),
    ),
    Case(
        name="perf003-no-index",
        kind="positive",
        expect=frozenset({"PERF003"}),
        note="Gold-standard policy but the discriminator column has no "
        "btree index — the policy filter can't use one.",
        sql=_clean_tenant("metrics", floor=True).replace(
            "CREATE INDEX ON public.metrics (tenant_id);", ""
        ),
    ),
    Case(
        name="sec032-dormant-policies",
        kind="positive",
        expect=frozenset({"SEC032"}),
        note="A complete, correctly-scoped policy exists but RLS was never "
        "enabled — the policy is inert (dormant). SEC032 is the specific "
        "finding; it supersedes SEC001, and the WITH CHECK keeps SEC006 "
        "quiet so SEC032 is the only signal.",
        sql="""
CREATE TABLE public.drafts (id uuid PRIMARY KEY, tenant_id uuid NOT NULL);
CREATE POLICY drafts_iso ON public.drafts FOR ALL TO authenticated
    USING (tenant_id = (SELECT current_setting('app.tenant_id', true)::uuid))
    WITH CHECK (tenant_id = (SELECT current_setting('app.tenant_id', true)::uuid));
""",
    ),
    # ---- more clean negatives (real-world shapes that must stay silent) ----
    Case(
        name="per-command-policies-clean",
        kind="negative",
        expect=frozenset(),
        note="Real apps split policies per command (SELECT/INSERT/UPDATE/"
        "DELETE). Each is correctly scoped and a restrictive floor is "
        "present — SEC006 must NOT fire (INSERT has WITH CHECK, UPDATE has "
        "both).",
        sql="""
CREATE TABLE public.tickets (id uuid PRIMARY KEY, tenant_id uuid NOT NULL, body text);
ALTER TABLE public.tickets ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.tickets FORCE ROW LEVEL SECURITY;
CREATE POLICY tickets_sel ON public.tickets FOR SELECT TO authenticated
    USING (tenant_id = (SELECT current_setting('app.tenant_id', true)::uuid));
CREATE POLICY tickets_ins ON public.tickets FOR INSERT TO authenticated
    WITH CHECK (tenant_id = (SELECT current_setting('app.tenant_id', true)::uuid));
CREATE POLICY tickets_upd ON public.tickets FOR UPDATE TO authenticated
    USING (tenant_id = (SELECT current_setting('app.tenant_id', true)::uuid))
    WITH CHECK (tenant_id = (SELECT current_setting('app.tenant_id', true)::uuid));
CREATE POLICY tickets_del ON public.tickets FOR DELETE TO authenticated
    USING (tenant_id = (SELECT current_setting('app.tenant_id', true)::uuid));
CREATE POLICY tickets_floor ON public.tickets AS RESTRICTIVE FOR ALL TO authenticated
    USING (tenant_id = (SELECT current_setting('app.tenant_id', true)::uuid))
    WITH CHECK (tenant_id = (SELECT current_setting('app.tenant_id', true)::uuid));
CREATE INDEX ON public.tickets (tenant_id);
""",
    ),
    Case(
        name="jwt-claim-tenant-clean",
        kind="negative",
        expect=frozenset(),
        note="Supabase JWT-claim tenancy: discriminator compared to a "
        "claim read from auth.jwt(), wrapped in (SELECT …). A common real "
        "shape that must lint clean.",
        sql=_clean_tenant(
            "comments",
            pred="tenant_id = (SELECT (auth.jwt() ->> 'tenant_id')::uuid)",
        ),
    ),
    Case(
        name="hyg002-placeholder-name",
        kind="positive",
        expect=frozenset({"HYG002"}),
        note="Policy named `tmp` — a forgotten migration scaffold. "
        "Otherwise gold-standard.",
        sql=_clean_tenant("widgets").replace("widgets_iso", "tmp"),
    ),
    Case(
        name="sec005-session-state-only",
        kind="positive",
        expect=frozenset({"SEC005"}),
        note="Policy gates on a session GUC with no own-column reference — "
        "admits/denies whole row sets by config alone. A restrictive floor "
        "(which does reference the column) keeps SEC007 quiet so SEC005 is "
        "the only signal.",
        sql="""
CREATE TABLE public.flags (id uuid PRIMARY KEY, tenant_id uuid NOT NULL, body text);
ALTER TABLE public.flags ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.flags FORCE ROW LEVEL SECURITY;
CREATE POLICY flags_gate ON public.flags FOR ALL TO authenticated
    USING ((SELECT current_setting('app.enabled', true)) = 'true')
    WITH CHECK ((SELECT current_setting('app.enabled', true)) = 'true');
CREATE POLICY flags_floor ON public.flags AS RESTRICTIVE FOR ALL TO authenticated
    USING (tenant_id = (SELECT current_setting('app.tenant_id', true)::uuid))
    WITH CHECK (tenant_id = (SELECT current_setting('app.tenant_id', true)::uuid));
CREATE INDEX ON public.flags (tenant_id);
""",
    ),
]
