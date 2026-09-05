# pgrls + PostgREST

PostgREST exposes a Postgres database as a REST API and relies on
Row-Level Security as its only authorization layer — the role
configured for `db-anon-role` is what unauthenticated requests run as,
and JWT-bearing requests `SET LOCAL ROLE` to whatever the token's
`role` claim says. This is a clean model, *and* it puts a lot of weight
on the policies being correct.

This recipe shows the PostgREST-specific patterns pgrls catches and how
to put it in CI.

## The signature PostgREST bug

PostgREST exposes the JWT to SQL via the GUC
`request.jwt.claims` (and individual claims via
`request.jwt.claim.<name>`). The recurring footgun is the policy that
uses `current_setting(..., true)` on the left of an `IS NULL OR …`
disjunct:

```sql
CREATE POLICY tenant_read ON api.documents
    FOR SELECT
    USING (
        current_setting('request.jwt.claims', true) IS NULL
        OR (current_setting('request.jwt.claims', true)::json ->> 'tenant_id') = tenant_id::text
    );
```

Reads like *"if no JWT, allow anyone; otherwise scope by tenant."*
But `current_setting('request.jwt.claims', true)` returns `NULL`
whenever the GUC is unset — which is true for every PostgREST request
without a `Bearer` header. So the `IS NULL` branch is `true`, the
`OR` short-circuits, and the policy admits every row to the anon role.

pgrls flags this as **SEC004** (severity `error`); its default
auth-function set includes `current_setting`, so this exact shape
trips the rule regardless of the column name or schema.

## Nullable discriminator columns

A `tenant_id` column on a multi-tenant PostgREST table is often
declared without `NOT NULL`. Under the canonical scoping shape

```sql
USING (tenant_id = current_setting('request.jwt.claim.tenant_id', true)::uuid)
```

(`current_setting(...)` always returns `text`; if `tenant_id` is
`uuid` / `int` / `bigint` you need a matching cast, or Postgres
raises `operator does not exist: <coltype> = text` at query time.)
A row whose `tenant_id` is `NULL` evaluates `NULL = <value>` to `NULL`
(not `true`), so the row is invisible to every tenant. That's already
a bug — the row belongs to no one. The worse failure mode is one
edit away: the moment any policy on the table uses a NULL-tolerant
form of the same key (`tenant_id IS NOT DISTINCT FROM …`,
`… OR tenant_id IS NULL`, `COALESCE(tenant_id, …)`), every NULL row
becomes visible to **every** tenant at once. A `NOT NULL`
discriminator makes that whole failure mode unreachable.

pgrls flags this as **SEC030** (severity `info`) — *"policy scopes
by a nullable discriminator column"*. The remedy is
`ALTER COLUMN tenant_id SET NOT NULL` after backfilling existing
`NULL`s, plus a `DEFAULT` or trigger so the column is always
populated.

## The role-as-discriminator pitfall

PostgREST examples sometimes compare an own-column directly to
`current_user`:

```sql
USING (owner_role = current_user)
```

`current_user` is the Postgres role the connection ran the query as.
Under PostgREST connection pooling all signed-in users share a small
pool of roles (typically just `authenticated`), so `current_user`
collapses across users and the policy lets everyone see everyone
else's rows.

pgrls flags this as **SEC018** (severity `warning`) — "Policy compares a
column against current_user / session_user". The discriminator is the role
identity, not a per-request auth value.
The fix is to scope by `current_setting('request.jwt.claim.<id>', true)`
(or `auth.uid()` on Supabase), which IS per-request.

## Wire it into PostgREST CI

PostgREST projects tend to be migration-driven (sqitch, Flyway,
golang-migrate, plain `psql`). Apply the migrations to a Postgres
service container in CI, then lint:

```yaml
# .github/workflows/pgrls.yml
name: pgrls
on: [push, pull_request]
jobs:
  rls:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:16-alpine
        env: { POSTGRES_PASSWORD: ci, POSTGRES_DB: ci }
        ports: ["5432:5432"]
        options: >-
          --health-cmd pg_isready --health-interval 10s --health-retries 5
    env:
      DATABASE_URL: postgres://postgres:ci@localhost:5432/ci
    steps:
      - uses: actions/checkout@v4
      - name: Apply migrations
        run: psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f migrations/all.sql
      - uses: pgrls/pgrls-action@v1
        with:
          database-url: ${{ env.DATABASE_URL }}
          schemas: api,public
          fail-on: error
```

`--schemas` keeps pgrls focused on the schemas you actually expose
through PostgREST (typically `api`, sometimes `public`); it won't
complain about `pg_catalog` or other internal schemas.

## A note on `pre-request` functions

PostgREST runs a `db-pre-request` SQL function before every request,
typically to `SET LOCAL ROLE` from the JWT or stash request metadata in
GUCs. That function isn't a policy and isn't subject to RLS analysis,
but the GUCs it sets ARE what RLS keys on — so if the function silently
fails to set them (e.g. an exception swallowed inside a nested
function), every policy that compares against
`current_setting('request.jwt.claim.<x>', true)` evaluates `NULL = …`
→ `NULL` and the row is hidden. The mirror pattern — a policy with
`IS NULL OR …` over the same GUC — then *exposes* every row instead of
hiding it. The takeaway: keep the pre-request function tight,
make GUC-setting errors loud, and let pgrls flag any policy that
trusts the GUC is present.

## Adopting on an existing PostgREST project

`--baseline` records what's currently flagged so CI fails only on
*new* findings:

```bash
pgrls lint --schemas api,public --baseline .pgrls-baseline.json
```

## See also

- [`docs/QUICKSTART.md`](../QUICKSTART.md) — the 5-minute first-run.
- [`README.md`](../../README.md) — the full feature tour.
- [`docs/RULES.md`](../RULES.md) — every rule with its reference
  paragraph and fix recipe.
- PostgREST docs on roles & RLS:
  https://docs.postgrest.org/en/stable/references/auth.html
