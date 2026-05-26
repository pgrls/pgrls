# Running pgrls as a pre-commit hook

`pgrls` ships a `.pre-commit-hooks.yaml` at the repo root, so any
project using the [pre-commit](https://pre-commit.com/) framework
can add it as a one-line entry.

## Caveat — `pgrls` reads a *live database*, not source files

The `pre-commit` framework was designed around hooks that read
files in the commit. `pgrls` reads the catalog of a running
Postgres database. That means:

- The hook fires on **every commit**, not only when SQL files
  changed. The schema state lives in the database, which any commit
  can have changed via a separately-applied migration. The hook
  config sets `always_run: true` to make this explicit.
- The hook needs a reachable Postgres at hook time. Most teams
  point at a local stack (`supabase start`, a `docker-compose` dev
  database, or a CI-only service); pre-commit is most useful in
  CI-bound hooks where the database is always up.
- A typical `pre-commit-config.yaml` should set
  `stages: [pre-push, manual]` rather than the default `commit`
  if developers don't have a local DB running on every commit.

## Minimal `.pre-commit-config.yaml`

```yaml
repos:
  - repo: https://github.com/pgrls/pgrls
    rev: v0.6.4   # pin a release
    hooks:
      - id: pgrls-lint
        args:
          - --schemas
          - public
        # Skip the hook on every commit; only fire when explicitly
        # invoked (`pre-commit run pgrls-lint --all-files`) or in CI
        # on the `pre-push` stage.
        stages: [pre-push, manual]
```

## Supabase-friendly variant

If you develop against a local Supabase stack (`supabase start`),
the database URL is well-known; the hook can derive it inline.

```yaml
repos:
  - repo: https://github.com/pgrls/pgrls
    rev: v0.6.4
    hooks:
      - id: pgrls-lint
        args:
          - --database-url
          - postgres://postgres:postgres@localhost:54322/postgres
          - --schemas
          - public
        stages: [pre-push, manual]
```

(Port 54322 is Supabase CLI's default for the local Postgres.)

## CI-only variant (recommended)

The most reliable wiring is **pre-commit in CI** rather than per-
developer-machine. Drop a `pre-commit` step in GitHub Actions that
fires on every PR; the workflow's service container guarantees a
fresh database is up.

```yaml
# .github/workflows/lint.yml
name: lint
on: [pull_request]

jobs:
  lint:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:16
        env:
          POSTGRES_PASSWORD: postgres
        ports: ["5432:5432"]
        options: >-
          --health-cmd pg_isready --health-interval 5s
          --health-timeout 5s --health-retries 5
    env:
      DATABASE_URL: postgres://postgres:postgres@localhost:5432/postgres
    steps:
      - uses: actions/checkout@v4
      - run: psql "$DATABASE_URL" -f schema.sql
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - uses: pre-commit/[email protected]
```

This runs *every* pre-commit hook your repo has, including pgrls,
against a freshly-applied schema. No per-developer database setup
required.

## When to prefer the GitHub Action instead

For most projects, the [`pgrls/pgrls-action`](https://github.com/marketplace/actions/pgrls-postgres-rls-linter)
is the cleaner GitHub-native path — it composes with `actions/upload-sarif`
for Code Scanning ingest, supports every output format, and doesn't
need pre-commit configured at all. Pre-commit shines when your team
already uses it for *other* linters (ruff, shellcheck, etc.) and
wants pgrls to compose into the same `pre-commit run --all-files`
invocation.
