# Running pgrls as a pre-commit hook

`pgrls` ships a `.pre-commit-hooks.yaml` at the repo root with **two hooks**,
so any project using the [pre-commit](https://pre-commit.com/) framework can
add one as a one-line entry:

| hook | reads | needs | fires |
|---|---|---|---|
| `pgrls-lint-sql` | your DDL (`--sql-file`, repeatable) or a `pgrls snapshot` (`--snapshot`) | nothing — no database, no Docker | when any `*.sql` file changes |
| `pgrls-lint` | a **live database** (`$DATABASE_URL` or `[database].url`) | a reachable Postgres | every invocation (`always_run`) |

Both are whole-schema (`pass_filenames: false`): RLS is cross-file — a table
may be created in one migration and its policy in another — so pgrls needs
the complete schema, not the individual changed files.

## Minimal `.pre-commit-config.yaml` — offline (the usual choice)

```yaml
repos:
  - repo: https://github.com/pgrls/pgrls
    rev: v0.55.0   # pin a release
    hooks:
      - id: pgrls-lint-sql
        args: ["--sql-file", "schema.sql", "--fail-on", "error"]
```

This runs at commit time with no infrastructure. Declare tables before the
policies and grants that reference them (`--sql-file` is repeatable and the
files are concatenated in order). Rules that need catalog state an offline
file cannot carry — `BYPASSRLS` roles, `SECURITY DEFINER` functions,
triggers, indexes, foreign keys — are reported as inert, so an absence of
findings offline is not a proof of safety; keep a live run in CI.

## Live-database variant — `pgrls-lint`

`pgrls-lint` reads the catalog of a running Postgres instead of files. That
changes how it fits pre-commit:

- It fires on **every commit**, not only when SQL files changed — the schema
  state lives in the database, which any commit can have changed via a
  separately-applied migration. The hook sets `always_run: true` to make this
  explicit.
- It needs a reachable Postgres at hook time. Most teams point it at a local
  stack (`supabase start`, a `docker-compose` dev database) and scope it to
  `stages: [pre-push, manual]` rather than the default `commit`, so
  developers without a local DB running are not blocked on every commit.

```yaml
repos:
  - repo: https://github.com/pgrls/pgrls
    rev: v0.55.0
    hooks:
      - id: pgrls-lint
        args:
          - --schemas
          - public
        # Only fire when explicitly invoked
        # (`pre-commit run pgrls-lint --all-files`) or on `pre-push`.
        stages: [pre-push, manual]
```

## Supabase-friendly variant (live)

If you develop against a local Supabase stack (`supabase start`),
the database URL is well-known; the live hook can take it inline.

```yaml
repos:
  - repo: https://github.com/pgrls/pgrls
    rev: v0.55.0
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
is the cleaner GitHub-native path — it composes with `github/codeql-action/upload-sarif`
for Code Scanning ingest, supports every output format, and doesn't
need pre-commit configured at all. Pre-commit shines when your team
already uses it for *other* linters (ruff, shellcheck, etc.) and
wants pgrls to compose into the same `pre-commit run --all-files`
invocation.
