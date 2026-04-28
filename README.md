# pgrls

Framework-agnostic linter and testing toolkit for Postgres Row-Level Security.

> **Status: 0.0.7** — fifteen rules (SEC001–SEC011, PERF001–PERF002, HYG001–HYG002) and a `pgrls fix` subcommand that auto-remediates SEC002 and PERF001. Text, JSON, and SARIF output for CI integrations. The `test` / `diff` commands are on the roadmap below.

## Install

```bash
pip install pgrls
```

Requires Python 3.11+ and Postgres 10+. pgrls is tested in CI against PostgreSQL 10–17 (see [`.github/workflows/test.yml`](.github/workflows/test.yml) for the matrix). The demo suite uses some features that require PG 12+ (declarative partitions, generated columns) and PG 14+ (uc36's `pg_read_all_data` predefined role) — but `pgrls lint` and `pgrls fix` themselves work on PG10 and up.

## Usage

Point `pgrls` at any Postgres database:

```bash
export DATABASE_URL="postgres://user:pass@host:5432/db"
pgrls lint
```

Or pass the URL directly:

```bash
pgrls lint --database-url "postgres://user:pass@host:5432/db"
```

Limit the scan to specific schemas:

```bash
pgrls lint --schemas public,tenant
```

Point at a non-default config file, or pick an output format:

```bash
pgrls lint --config ./config/pgrls.toml --format text    # human-readable (default)
pgrls lint --config ./config/pgrls.toml --format json    # machine-readable for CI
pgrls lint --config ./config/pgrls.toml --format sarif   # GitHub Code Scanning
```

### Example output

Text (default):

```
  ERROR  SEC001  public.users
         Table public.users does not have row-level security enabled.
         Add ENABLE ROW LEVEL SECURITY or include the table in
         [lint.rules.SEC001].allowlist if it is a public reference table.

pgrls: 1 error.
```

JSON (`--format json`):

```json
{
  "violations": [
    {
      "rule_id": "SEC001",
      "severity": "error",
      "title": "RLS not enabled on table",
      "message": "Table public.users does not have row-level security enabled. Add ENABLE ROW LEVEL SECURITY or include the table in [lint.rules.SEC001].allowlist if it is a public reference table.",
      "location": "public.users"
    }
  ],
  "summary": { "errors": 1, "warnings": 0, "infos": 0, "total": 1 }
}
```

The JSON shape is the public CI contract — top-level keys, per-violation keys, and summary keys are stable across releases. Pipe through `jq` to filter, count, or transform; ship to a dashboard; upload as a build artifact.

SARIF (`--format sarif`) emits a SARIF v2.1.0 document. GitHub Code Scanning, Azure DevOps, and other static-analysis aggregators consume it directly — see the GitHub Actions recipe below for the upload step that puts findings inline on PRs.

Exit codes follow the standard linter convention:

- `0` — clean (or findings below `fail_on`)
- `1` — findings met or exceeded `fail_on` (default `warning`); your schema has an RLS issue
- `2` — `pgrls` itself failed to run (bad config, DB unreachable, fixer SQL rolled back, etc.). Distinct from `1` so CI alerts can route "schema bug" differently from "tool error."

### Auto-remediation: `pgrls fix`

`pgrls fix` generates SQL for the rules whose remediation is mechanical. Default mode is dry-run — it prints the SQL but does not modify the database. Pass `--apply` to execute.

```bash
# Dry-run: print what would change.
pgrls fix --database-url "$DATABASE_URL"

# Apply for real.
pgrls fix --database-url "$DATABASE_URL" --apply

# Only fix one rule.
pgrls fix --database-url "$DATABASE_URL" --rule SEC002 --apply
```

Currently fixable: **SEC002** (emits `ALTER TABLE … FORCE ROW LEVEL SECURITY;`) and **PERF001** (rewrites unwrapped auth calls as `(SELECT auth.uid())` and emits `ALTER POLICY … USING (…);`). Other rules need human intent (which role? which column? which policy?) and are not auto-fixed.

## Configuration

Drop a `pgrls.toml` next to your project. See `pgrls.example.toml` in the repo for a fully commented version.

```toml
[database]
url = "$DATABASE_URL"
schemas = ["public"]

[lint]
disable = []
fail_on = "warning"

[lint.rules.SEC001]
allowlist = ["countries", "currencies"]
```

## Rules

`pgrls lint` ships these rules:

| ID | Severity | Catches |
|---|---|---|
| [SEC001](AGENTS.md#rule-sec001) | error | Tables in scanned schemas with RLS disabled |
| [SEC002](AGENTS.md#rule-sec002) | error | Tables with RLS enabled but FORCE ROW LEVEL SECURITY off |
| [SEC003](AGENTS.md#rule-sec003) | error | Permissive policies granted to PUBLIC |
| [SEC004](AGENTS.md#rule-sec004) | error | Inverted auth check (Lovable CVE pattern) in USING |
| [SEC005](AGENTS.md#rule-sec005) | warning | Policy expression has no own-column reference |
| [SEC006](AGENTS.md#rule-sec006) | error | INSERT/UPDATE/ALL policies with no WITH CHECK |
| [SEC007](AGENTS.md#rule-sec007) | info | All policies on a table are permissive (no RESTRICTIVE floor) |
| [SEC008](AGENTS.md#rule-sec008) | warning | Policy USING clause is constant `true` |
| [SEC009](AGENTS.md#rule-sec009) | warning | RLS enabled but no policies defined (silent deny-all) |
| [SEC010](AGENTS.md#rule-sec010) | warning | Policy `USING`/`WITH CHECK` clause is constant `false` (deny-all anti-pattern) |
| [SEC011](AGENTS.md#rule-sec011) | warning | Policy expression has an `OR true` branch (debug bypass left in) |
| [PERF001](AGENTS.md#rule-perf001) | warning | Auth function called per-row in policy USING (unwrapped) |
| [PERF002](AGENTS.md#rule-perf002) | warning | Policy expression uses a VOLATILE function (`random()`, `clock_timestamp()`, …) |
| [HYG001](AGENTS.md#rule-hyg001) | error | Policies referencing columns that don't exist on the table |
| [HYG002](AGENTS.md#rule-hyg002) | warning | Policy named like a placeholder (`todo`, `fixme`, `tmp`, …) |

For canonical SQL fixes per rule, see [AGENTS.md](AGENTS.md). For per-rule
configuration options (allowlists, etc.), see `pgrls.example.toml`.

For per-release changes, see [CHANGELOG.md](CHANGELOG.md).

## CI integration

pgrls is designed to live in your CI alongside any other linter. It
needs a Postgres database with your schema applied; it then connects,
introspects, and exits non-zero if any rule at or above
`fail_on` (default `warning`) fires.

### pre-commit

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/pgrls/pgrls
    rev: v0.0.7
    hooks:
      - id: pgrls-lint
        # pgrls hits a real database, so most teams scope this to
        # `pre-push` rather than every commit.
        stages: [pre-push]
        args:
          - --database-url=$DATABASE_URL
          - --config=pgrls.toml
```

### GitHub Actions

```yaml
# .github/workflows/pgrls.yml
name: pgrls
on: [push, pull_request]
jobs:
  lint:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:16-alpine
        env:
          POSTGRES_USER: ci
          POSTGRES_PASSWORD: ci
          POSTGRES_DB: ci
        ports: ["5432:5432"]
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-retries 5
    env:
      DATABASE_URL: postgres://ci:ci@localhost:5432/ci
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: pip install pgrls
      - name: Apply schema
        run: psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f migrations/all.sql
      - name: Lint RLS
        run: pgrls lint --format sarif > pgrls.sarif
      - name: Upload SARIF for code scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: pgrls.sarif
```

The SARIF upload puts findings inline on the PR as code-scanning
alerts — no extra dashboard plumbing. Use `--format json` instead
of `--format sarif` if you want to pipe to `jq`, build your own
dashboard, or keep the report as a build artifact.

## Roadmap

- **More lint rules.** Continued expansion of the SEC / PERF / HYG catalog. Markdown output. Polished error messages.
- **`pgrls test`.** Code-first RLS test DSL for Python, TypeScript, and Go.
- **`pgrls diff`.** Semantic policy diff between branches with DANGEROUS / BREAKING / SAFE classification.

## License

MIT — see `LICENSE`.
