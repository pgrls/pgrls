# pgrls demo

A self-contained walkthrough of every rule pgrls 0.0.4 ships, plus the
partition-aware paths. 15 use cases in one fixture.

## Layout

```
demo/
├── docker-compose.yml   # local Postgres on port 5433 (optional)
├── pgrls.toml           # demo config (allowlists app.countries)
├── README.md            # this file
├── run.sh               # bring up DB + apply fixture + run pgrls
├── setup.sql            # the 15-use-case fixture
└── test_demo.py         # pytest assertions per use case
```

## Use cases

| # | Pattern | Rule(s) | Outcome |
|---|---------|---------|---------|
| 01 | Multi-tenant SaaS table — canonical clean shape | (none) | passes |
| 02 | Reference data, no RLS | SEC001 (allowlisted) | passes |
| 03 | Tenant table, RLS forgotten | SEC001 | fires |
| 04 | RLS enabled but no FORCE | SEC002 | fires |
| 05 | Permissive PUBLIC policy | SEC003 + SEC005/7/8 | fires |
| 06 | Inverted-auth (Lovable CVE shape) | SEC004 + PERF001 | fires |
| 07 | Session-state-only predicate | SEC005 + PERF001 | fires |
| 08 | UPDATE policy missing WITH CHECK | SEC006 | fires |
| 09 | All policies permissive (no RESTRICTIVE floor) | SEC007 | fires |
| 10 | `USING (true)` policy | SEC008 + SEC005 | fires |
| 11 | Unwrapped auth call in USING | PERF001 | fires |
| 12 | Orphaned column reference | HYG001 | fires |
| 13 | Partitioned parent with RLS — clean | (none) | passes (children suppressed by ancestor walk) |
| 14 | Cross-schema partition (parent unscoped) | SEC001 differentiated | fires with "leaves the scanned schemas" message |
| 15 | Partition family with no RLS anywhere | SEC001 visible-root variant | fires; child message names the parent |

## Running

### Option A — quick demo (Docker)

```bash
cd demo
./run.sh
```

Spins up Postgres on `localhost:5433`, applies `setup.sql`, runs
`pgrls lint --config pgrls.toml`, and prints the result. The DB stays
running so you can `psql postgres://demo:demo@localhost:5433/demo` to
poke around.

Tear down:

```bash
docker compose down -v
```

### Option B — apply to an existing DB

```bash
cd demo
DATABASE_URL=postgres://user:pass@host/db ./run.sh
```

The script honors `DATABASE_URL` and skips Docker.

### Option C — programmatic, via pytest

```bash
pytest demo/test_demo.py -v
```

Spins up an isolated Postgres via `testcontainers` (no port
collisions), applies `setup.sql`, and runs 17 assertions — one per
use case plus a few summary checks. Each test is named
`test_uc<NN>_<what_it_does>` for top-to-bottom readability.

To run the tests against a long-running DB you started with `run.sh`:

```bash
DATABASE_URL=postgres://demo:demo@localhost:5433/demo \
    pytest demo/test_demo.py -v
```

## Expected lint output

Twenty-three violations across all three severities. Key lines:

```
ERROR  SEC001  app.legacy_orders         (use case 03)
ERROR  SEC001  app.bare_metrics_2026     (use case 15 — names the parent)
ERROR  SEC001  app.audit_log_2026        (use case 14 — unscoped chain)
ERROR  SEC002  app.notes                 (use case 04)
ERROR  SEC003  app.posts.everyone_reads  (use case 05)
ERROR  SEC004  app.accounts.allow_unset_user  (use case 06)
ERROR  SEC006  app.invoices.update_without_check  (use case 08)
ERROR  HYG001  app.comments.archived_filter  (use case 12)
WARN   SEC005  app.singletons.admin_only  (use case 07)
WARN   SEC008  app.feature_flags.public_flags  (use case 10)
WARN   PERF001 app.messages.messages_owner  (use case 11)
INFO   SEC007  app.tags                   (use case 09)
```

Several rules cross-fire — `USING (true)` triggers SEC005 + SEC008 +
(if PERMISSIVE PUBLIC) SEC003 simultaneously. That's realistic, not a
flaw: a single bad policy usually breaks several rules at once. The
`test_uc<NN>_*` tests assert the *primary* rule per use case; cross-
fires show up as additional lines in the lint output.

## Wiring this into CI

```toml
# pgrls.toml in your repo
[database]
url = "$DATABASE_URL"
schemas = ["public", "app"]  # adjust

[lint]
fail_on = "error"

[lint.rules.SEC001]
allowlist = ["public.countries", "public.currencies"]
```

```yaml
# .github/workflows/lint.yml
- name: Lint RLS
  run: pgrls lint --config pgrls.toml
  env:
    DATABASE_URL: ${{ secrets.LINT_DATABASE_URL }}
```

`fail_on = "error"` blocks the build on SEC001/2/3/4/6/HYG001. Bump
to `warning` to also block on SEC005/8/PERF001, or to `info` to also
block on SEC007.
