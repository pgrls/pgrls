# pgrls

Framework-agnostic linter and testing toolkit for Postgres Row-Level Security.

> **Status: 0.0.1** — first lint rule (SEC001) shipped. The full rule catalog and the `test` / `diff` commands are on the roadmap below.

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

## Roadmap

- **More lint rules.** Full SEC / PERF / HYG catalog, including the marquee SEC004 (inverted auth check / Lovable CVE pattern). JSON, SARIF, and Markdown output. Polished error messages.
- **`pgrls test`.** Code-first RLS test DSL for Python, TypeScript, and Go.
- **`pgrls diff`.** Semantic policy diff between branches with DANGEROUS / BREAKING / SAFE classification.

## License

MIT — see `LICENSE`.
