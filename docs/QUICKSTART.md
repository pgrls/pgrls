# Quickstart

5 minutes from `pip install` to finding (and fixing) a real Row-Level
Security bug in CI. For the comprehensive feature tour see
[README.md](../README.md); for the full rule catalogue see [AGENTS.md](../AGENTS.md).

## 1. Install

```bash
pip install pgrls
```

Requires Python 3.11+ and Postgres 15+ (tested on PG 15, 16, 17).

## 2. Try it on a throwaway database

If you don't already have a Postgres handy, spin up a one-shot with the
canonical "policy that ships past code review" baked in:

```bash
docker run -d --name pgrls-demo -e POSTGRES_PASSWORD=demo -p 5432:5432 postgres:16
sleep 3
psql 'postgres://postgres:demo@localhost/postgres' -v ON_ERROR_STOP=1 <<'SQL'
CREATE TABLE documents (id SERIAL PRIMARY KEY, owner uuid, body text);
ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_read ON documents
    FOR SELECT
    USING (current_setting('app.uid', true) IS NULL
           OR owner::text = current_setting('app.uid'));
SQL

export DATABASE_URL='postgres://postgres:demo@localhost/postgres'
pgrls lint --explain
```

You should see an `ERROR  SEC004` finding on `public.documents.tenant_read`.
Tear the demo down when you're done: `docker rm -f pgrls-demo`.

To run pgrls against your own database, just point `DATABASE_URL` at it (or
pass `--database-url`); `pgrls lint` is read-only.

## 3. What pgrls just caught

The policy reads like the correct English sentence — *"anyone without a
session sees nothing, signed-in users see their own rows"* — and would
pass code review. But `current_setting('app.uid', true)` returns `NULL`
for any connection that hasn't set the GUC, so the `IS NULL` branch is
true, the `OR` short-circuits, and the policy returns **every row** to
exactly the connections you meant to keep out. (The same pattern with
`auth.uid() IS NULL OR …` is the recurring Supabase / PostgREST
foot-gun.) `pgrls lint --explain` prints the rule's reference paragraph
inline so the *why* travels with the *where*.

## 4. Auto-fix the mechanical findings

15 of the 47 rules are mechanically fixable. `pgrls fix` emits the
remediation to stdout or to a migration-ready `.sql`:

```bash
pgrls fix --output 001_rls_fixes.sql
```

The non-mechanical findings (like SEC004 above — pgrls can't author your
real auth check) need human judgement; `pgrls fix --check` lists what
would and wouldn't be fixed without writing anything.

## 5. Wire it into CI

The published Action is the quickest path — on the
[GitHub Marketplace](https://github.com/marketplace/actions/pgrls-postgres-rls-linter):

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
          database-url: ${{ secrets.PGRLS_DATABASE_URL }}
          fail-on: error
```

The Action accepts every flag `pgrls lint` does — see the
[Marketplace listing](https://github.com/marketplace/actions/pgrls-postgres-rls-linter)
for the full input table. If you'd rather control the install yourself or
spin up Postgres as a job service in the same workflow, the
[README's "GitHub Actions" section](../README.md#github-actions) has the
manual recipe.

## 6. Adopt on a legacy database

Don't have to fix the whole backlog to start. `pgrls lint --baseline`
records existing findings, and CI then fails only on *new* ones:

```bash
pgrls lint --baseline .pgrls-baseline.json
git add .pgrls-baseline.json && git commit -m "pgrls: record current findings"
```

`pgrls lint --update-baseline` refreshes the file when you intentionally
re-baseline after a clean-up pass.

## Where to go next

- **[README.md](../README.md)** — the full feature tour: every output
  format (text / JSON / SARIF / Markdown / GitHub-PR-comment / GitHub
  annotations / JUnit), `pgrls diff` for semantic CI gating, the
  `pgrls.testing` pytest plugin for RLS isolation tests, the JSON
  Schema for `pgrls.toml`.
- **[AGENTS.md](../AGENTS.md)** — every rule with its full rationale,
  worked examples (bad / good), and remediation recipe.
- **`pgrls explain <RULE>`** — print a rule's reference paragraph from
  the CLI (e.g. `pgrls explain SEC004`); add `--format json` for tooling
  or `--format markdown` for PR comments.
- **`pgrls init`** — scaffold a commented `pgrls.toml` with the
  `#:schema` directive (gives editor autocomplete via SchemaStore-aware
  TOML extensions).
