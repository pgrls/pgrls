# `pgrls` benchmark harness

Tiny end-to-end benchmark for `pgrls lint`. Generates a synthetic
schema with `N` policies on `M` tables, applies it to an ephemeral
Postgres (via `testcontainers`), and times the lint run.

## Why this exists

Lint perf matters as policy counts grow; 10k-policy schemas exist in
multi-tenant SaaS. The harness gives us:

1. **A baseline number to quote.** "`pgrls lints N policies in T ms`"
   only means something if we measured it the same way every time.
2. **A regression guard.** Future PRs that touch the AST walker or the
   rule registry can re-run this and see if they shifted the curve.
3. **A demo prop.** Useful for the docs site / DEV.to posts to back
   up perf claims.

The harness is intentionally minimal — no `pytest-benchmark`
dependency, no plot generation, no CI integration in the first cut.
Just a script that prints JSON. Add the rest when there's a reason to.

## Running

```bash
# Requires Docker + the `dev` extra (which pulls in testcontainers).
pip install -e '.[dev]'
python -m bench.lint_perf --table-count 10 --policy-count 100
```

Output (real run on a stock M-series laptop):

```json
{
  "table_count": 10,
  "policy_count": 100,
  "schema_apply_ms": 63,
  "introspect_ms": 32,
  "rules_ms": 29,
  "lint_ms": 61,
  "violation_count": 415,
  "rules_fired_count": 8,
  "rules_fired": ["HYG003", "PERF001", "PERF003", "SEC002",
                  "SEC003", "SEC006", "SEC007", "SEC022"],
  "pgrls_version": "0.6.0",
  "postgres_image": "postgres:16-alpine"
}
```

For a curve, run a sweep:

```bash
for n in 10 100 1000 10000; do
  python -m bench.lint_perf --table-count "$((n / 10))" --policy-count "$n"
done | jq -s '.'
```

## What it does NOT measure

- **Fix-emit perf.** Only `lint`, not `fix`. (Same harness shape would
  apply; left for when there's a reason.)
- **Cold-start vs warm-start.** Each invocation starts a fresh
  Postgres container; the timing covers a single warm `pgrls lint`
  run against a fully-applied schema. The schema-apply time is
  reported separately so you can subtract it if you only care about
  the lint.
- **Memory.** Wall-clock time only.
