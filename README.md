# pgrls

Framework-agnostic linter and testing toolkit for Postgres Row-Level Security.

> **Status: 0.0.4** — ten rules across error, warning, and info severities (SEC001–SEC008, PERF001, HYG001). The `test` / `diff` commands are on the roadmap below.

## Install

```bash
pip install pgrls
```

Requires Python 3.11+.

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
pgrls lint --config ./config/pgrls.toml --format text
```

### Example output

```
  ERROR  SEC001  public.users
         Table public.users does not have row-level security enabled.
         Add ENABLE ROW LEVEL SECURITY or include the table in
         [lint.rules.SEC001].allowlist if it is a public reference table.

pgrls: 1 error.
```

Exit code is `1` when any violation meets or exceeds `fail_on` (default `warning`).

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
| SEC001 | error | Tables in scanned schemas with RLS disabled |
| SEC002 | error | Tables with RLS enabled but FORCE ROW LEVEL SECURITY off |
| SEC003 | error | Permissive policies granted to PUBLIC |
| SEC004 | error | Inverted auth check (Lovable CVE pattern) in USING |
| SEC005 | warning | Policy expression has no own-column reference |
| SEC006 | error | INSERT/UPDATE/ALL policies with no WITH CHECK |
| SEC007 | info | All policies on a table are permissive (no RESTRICTIVE floor) |
| SEC008 | warning | Policy USING clause is constant `true` |
| PERF001 | warning | Auth function called per-row in policy USING (unwrapped) |
| HYG001 | error | Policies referencing columns that don't exist on the table |

For canonical SQL fixes per rule, see [AGENTS.md](AGENTS.md). For per-rule
configuration options (allowlists, etc.), see `pgrls.example.toml`.

## Roadmap

- **More lint rules.** Continued expansion of the SEC / PERF / HYG catalog. JSON, SARIF, and Markdown output. Polished error messages.
- **`pgrls test`.** Code-first RLS test DSL for Python, TypeScript, and Go.
- **`pgrls diff`.** Semantic policy diff between branches with DANGEROUS / BREAKING / SAFE classification.

## License

MIT — see `LICENSE`.
