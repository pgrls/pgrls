# pgrls + Supabase

Supabase projects enable RLS per-table from the dashboard, author
policies against `auth.uid()` / `auth.role()` / `auth.jwt()`, and lean
on the anon / authenticated / service_role roles for the heavy
lifting. The bugs that ship past code review are remarkably
consistent across projects. This recipe shows the patterns pgrls
catches and how to put it in CI.

## The signature Supabase bug

The recurring footgun is the policy that uses `auth.uid()` (or another
`auth.*` function) on the left side of an `IS NULL OR …` disjunct:

```sql
CREATE POLICY tenant_read ON public.documents
    FOR SELECT
    USING (auth.uid() IS NULL OR owner_id = auth.uid());
```

Reads like English: *"unauthenticated users see nothing, signed-in
users see their own rows."* But `auth.uid()` returns `NULL` for any
request without a valid session JWT, so the `IS NULL` branch is
`true`, the `OR` short-circuits, and the policy admits **every row**
to exactly the unauthenticated clients you meant to keep out. (If
this policy is instead bound `TO authenticated`, the same failure mode
applies to authenticated callers whose JWT lacks a `sub` claim — the
role binding narrows *who* the policy applies to, not *what the
policy means*.)

pgrls flags this as **SEC004** (severity `error`) — its default
auth-function set includes `auth.uid`, `auth.role`, `auth.jwt`, and
`current_setting`, so the same shape with any of them trips the rule.

## Within-tenant leaks (the second-biggest Supabase pattern)

Tenant-scoping is the easy half. The trickier half is per-user
scoping inside a tenant:

```sql
CREATE POLICY tenant_scope ON public.documents
    USING (tenant_id = (auth.jwt() ->> 'tenant_id')::uuid);
```

Cross-tenant access is blocked, so this passes a tenant-isolation
review. But there's an `owner_id` column on `documents` and nothing
keys on it — every user *in* a tenant reads every other user's rows.
On a `documents` table holding drafts, DMs, or private uploads, that's
the leak.

pgrls flags this as **SEC027** (severity `info`) — a "principal column
no policy scopes by" finding. The fix is a per-user predicate
(`AND owner_id = auth.uid()`), or — if the table really is intentionally
tenant-shared — allowlist it:

```toml
[lint.rules.SEC027]
allowlist = ["public.shared_documents"]
```

## Nullable discriminators

Supabase patterns often use `tenant_id uuid` without a `NOT NULL`
constraint. Under the canonical `tenant_id = auth.jwt()->>'tenant_id'`
shape, any row whose `tenant_id` is `NULL` evaluates `NULL = <value>`
to `NULL` (not `true`), so the row is invisible to every tenant. Then
the moment any policy uses a NULL-tolerant form
(`tenant_id IS NOT DISTINCT FROM …`, `… OR tenant_id IS NULL`,
`COALESCE(tenant_id, …)`), every such row becomes visible to every
tenant.

pgrls flags this as **SEC030** (severity `info`) and recommends
`SET NOT NULL` on the discriminator (after backfilling existing
`NULL`s).

## Wire it into Supabase CI

Two common patterns. Both work the same way: point pgrls at any Postgres
that holds the same schema you ship to production.

### A. Against your migration-applied CI database

If your CI applies migrations to a Postgres service container, just
lint that database after the migrations run:

```yaml
# .github/workflows/pgrls.yml
name: pgrls
on: [push, pull_request]
jobs:
  rls:
    runs-on: ubuntu-latest
    steps:
      - uses: pgrls/pgrls-action@v1
        with:
          database-url: ${{ secrets.PGRLS_CI_DATABASE_URL }}
          fail-on: error
```

### B. Against a fresh local Supabase

If you run `supabase start` in CI (or development), the local Postgres
is on `postgresql://postgres:postgres@127.0.0.1:54322/postgres`:

```bash
supabase start                           # spins the local stack
pgrls lint \
  --database-url 'postgresql://postgres:postgres@127.0.0.1:54322/postgres' \
  --schemas public \
  --fail-on error
```

The `--schemas public` filter keeps pgrls out of Supabase's internal
schemas (`auth`, `storage`, `realtime`, `pgsodium`, …) — those are
managed by Supabase, not your code, and policies there aren't yours
to lint.

## Adopting on an existing Supabase project

Don't have to clear the backlog first. `--baseline` records what's
currently flagged so CI only fails on *new* findings:

```bash
pgrls lint --schemas public --baseline .pgrls-baseline.json
git add .pgrls-baseline.json
git commit -m "pgrls: baseline current Supabase RLS findings"
```

`pgrls lint --update-baseline` refreshes the file after an intentional
clean-up pass.

## Beyond SEC004 / SEC027 / SEC030

Other Supabase-relevant rules to know about (see
[AGENTS.md](../../AGENTS.md) for the full reference paragraph on each):

- **SEC001** — RLS not enabled on a table in scope (a table that's
  never had `ALTER TABLE … ENABLE ROW LEVEL SECURITY`, with no
  policies defined on it; the policy-bearing variant is **SEC032**).
- **SEC002** — `FORCE ROW LEVEL SECURITY` missing; without it the
  role that *owns* the table (typically your migration role —
  `postgres` on a default Supabase setup, or whichever role your CI
  applies migrations as) bypasses RLS when it queries the table.
  Supabase's `service_role` bypasses RLS via the `BYPASSRLS` role
  attribute, which is a different mechanism (caught by SEC016) — so
  SEC002 is the rule for the *migration*-side bypass, not for
  `service_role`.
- **SEC008** — policy with literal `USING (true)`: no scoping at all
  (the top-level constant-true case).
- **SEC009** — table has RLS enabled but **no policies** defined
  (default-deny; the table is invisible to non-owner roles, which
  is sometimes intentional and often a silent deny-all that
  surprises in production).
- **SEC011** — same effect as SEC008, but the `OR true` branch is
  buried inside an otherwise-scoped policy (`tenant_id = X OR true`).
- **SEC032** — table has policies but RLS is disabled — the
  policies are dormant and do nothing (the
  `CREATE POLICY`-without-`ENABLE ROW LEVEL SECURITY` case).
- **PERF001** — `auth.uid()` evaluated per row instead of once per
  query (wrap in a sub-select: `(SELECT auth.uid())`).
- **PERF003** — policy filters on a column with no leading-column
  index; a multi-tenant `documents` table with millions of rows and
  no index on `tenant_id` sequential-scans on every query.

## See also

- [`docs/QUICKSTART.md`](../QUICKSTART.md) — the 5-minute first-run.
- [`README.md`](../../README.md) — the full feature tour.
- [`AGENTS.md`](../../AGENTS.md) — every rule with its reference
  paragraph and fix recipe.
