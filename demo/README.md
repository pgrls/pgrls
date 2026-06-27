# pgrls demo

A self-contained walkthrough of every rule pgrls ships, plus the
partition-aware paths, the JSON / SARIF output contracts, the
`pgrls fix` auto-remediation flow, the `pgrls.testing` pytest plugin,
and the four `pgrls diff` classifications (DANGEROUS / SAFE /
REQUIRES_REVIEW / BREAKING). 88 use cases.

## Layout

```
demo/
├── conftest.py            # session-scoped fixtures
├── docker-compose.yml     # local Postgres on port 5433 (optional)
├── pgrls.toml             # demo config (allowlists app.countries)
├── README.md              # this file
├── run.sh                 # bring up DB + apply fixtures + run pgrls
├── test_summary.py        # whole-fixture sanity checks
└── cases/
    ├── _shared.sql        # auth schema + auth.uid/role/jwt stubs
    ├── 01-multi-tenant-saas-table/
    │   ├── setup.sql      # the SQL for this case
    │   └── test_uc01.py   # the assertions for this case
    ├── 02-reference-data/
    │   ├── setup.sql
    │   └── test_uc02.py
    ├── ...
    ├── 80-pgrls-test-pytest-plugin/      # pgrls.testing smoke test
    │   ├── setup.sql
    │   └── test_uc80.py
    ├── 81-pgrls-diff-end-to-end/         # diff DANGEROUS path
    ├── 82-pgrls-diff-safe-restrictive-add/        # diff SAFE
    ├── 83-pgrls-diff-column-dropped-referenced/   # diff REQUIRES_REVIEW
    ├── 84-pgrls-diff-breaking-permissive-drop/    # diff BREAKING
    ├── 85-view001-non-invoker-view/      # VIEW001
    ├── 86-view002-non-barrier-view/      # VIEW002
    ├── 87-view003-matview-over-rls/      # VIEW003
    └── 88-view004-view-thru-secdef/      # VIEW004
```

Each case folder is self-contained — open it to read the SQL
fixture and the test assertions side by side. `pytest demo/`
discovers every `cases/NN-*/test_uc<NN>.py` and shares one
session-scoped Postgres testcontainer across them all (the conftest
applies `_shared.sql` first, then every case's `setup.sql` in
numeric order).

## Use cases

| # | Pattern | Rule(s) | Outcome |
|---|---------|---------|---------|
| 01 | Multi-tenant SaaS table — canonical clean shape | (none) | passes |
| 02 | Reference data, no RLS | SEC001 (allowlisted) | passes |
| 03 | Tenant table, RLS forgotten | SEC001 | fires |
| 04 | RLS enabled but no FORCE | SEC002 | fires |
| 05 | Permissive PUBLIC policy | SEC003 + SEC005/7/8 | fires |
| 06 | Inverted-auth (`current_setting() IS NULL`) | SEC004 + PERF001 | fires |
| 07 | Session-state-only predicate | SEC005 + PERF001 | fires |
| 08 | UPDATE policy missing WITH CHECK | SEC006 | fires |
| 09 | All policies permissive (no RESTRICTIVE floor) | SEC007 | fires |
| 10 | `USING (true)` policy | SEC008 + SEC005 | fires |
| 11 | Unwrapped auth call in USING | PERF001 | fires |
| 12 | Orphaned column reference (in USING) | HYG001 | fires |
| 13 | Partitioned parent with RLS — clean | (none) | passes (children suppressed by ancestor walk) |
| 14 | Cross-schema partition (parent unscoped) | SEC001 differentiated | fires with "leaves the scanned schemas" message |
| 15 | Partition family with no RLS anywhere | SEC001 visible-root variant | fires; child message names the parent |
| 16 | Correlated EXISTS membership join | (none) | passes (C2-fix scenario — must NOT trip SEC005) |
| 17 | Asymmetric USING / WITH CHECK | (none) | passes (read team's, write own) |
| 18 | Soft-delete pattern (`deleted_at IS NULL`) | (none) | passes (column-IS-NULL is not auth-IS-NULL) |
| 19 | Supabase `auth.uid() IS NULL` (Lovable CVE shape) | SEC004 + PERF001 | fires |
| 20 | Supabase `auth.uid()` unwrapped | PERF001 | fires |
| 21 | `auth.uid()` in WITH CHECK only | PERF001 | fires (rule walks both clauses) |
| 22 | Orphaned column referenced only in WITH CHECK | HYG001 | fires (rule walks both clauses) |
| 23 | Three-level partition with RLS at root | (none) | passes (multi-level ancestor walk) |
| 24 | RLS pushed down to leaf only | SEC001 | fires on parent only; leaf clean |
| 25 | View on top of RLS-enabled table — clean (both flags set) | (none) | passes |
| 26 | Blog with PERMISSIVE admin override granted to PUBLIC | SEC003 | fires; uc31 demonstrates the canonical fix |
| 27 | DELETE policy without WITH CHECK | (none) | passes (SEC006 doesn't apply to DELETE) |
| 28 | Tenant via JWT claim (`auth.jwt() ->> 'tenant_id'`, wrapped) | (none) | passes |
| 29 | `is_public OR tenant_id = ...` mix | (none) | passes |
| 30 | Composite tenant key (`tenant_id` AND `env`) | (none) | passes |
| 31 | PERMISSIVE policy granted to a specific role (NOT PUBLIC) | (none) | passes (canonical fix for uc26's SEC003) |
| 32 | `CASE` expression in policy USING clause | (none) | passes (extract walks CASE branches) |
| 33 | Classic non-declarative `INHERITS` parent + child | SEC001 | fires on both with classic message; partition_of stays None |
| 34 | SEC004's `IS NULL` test nested under top-level AND | (none) | passes (rule fires only on top-level OR) |
| 35 | `USING (1=1)` literal | SEC005 | fires; SEC008 specifically does NOT (asymmetric Boolean detection) |
| 36 | `pg_has_role(...)` admin escape | (none) | passes (function not in PERF001 default set) |
| 37 | Two policies, one orphaned column ref | HYG001 | fires only on the offending policy |
| 38 | Unwrapped `auth.jwt() ->> 'sub'` (JSON-text via `->>`) | PERF001 | fires |
| 39 | Custom auth function detected via `auth_functions` override | PERF001 (config) | fires only when config adds the function |
| 40 | Admin audit silenced by `[SEC005].allowlist` | SEC005 (config) | fires by default; allowlist clears it |
| 41 | `[lint].disable = ["SEC007"]` | SEC007 (config) | rule is skipped entirely |
| 42 | Multi-schema scan via `--schemas app,tenant` | SEC001 | only fires when `tenant` is in scanned schemas |
| 43 | SEC003 allowlist for intentional public-read policy | SEC003 (config) | fires by default; allowlist clears it |
| 44 | `current_user` in policy | (none) | passes (SQLValueFunction not in PERF001 default set) |
| 45 | `PARTITION OF parent DEFAULT` | (none) | passes (default partition walks ancestor chain) |
| 46 | Generated column referenced in policy | (none) | passes (generated cols are real attributes) |
| 47 | `<scalar> = ANY(array_col)` | (none) | passes (extract walks ArrayExpr) |
| 48 | E-commerce orders + items via FK + EXISTS | (none) | passes (2-table tenant join) |
| 49 | GDPR-style classification (ARRAY + CASE composite) | (none) | passes (rule walks both branches) |
| 50 | Read-replica style (SELECT-only policies, no PUBLIC permissive) | (none) | passes |
| 51 | ROW comparison `(a,b) = (c,d)` | (none) | passes (extract walks RowExpr) |
| 52 | Two PERMISSIVE PUBLIC policies on one table | SEC003 ×2 + SEC007 | each policy fires its own line |
| 53 | `auth_func() IS NULL` buried inside a nested OR | (none) | passes — documented false negative pin |
| 54 | `email::text = ...` (TypeCast over column) | (none) | passes (extract walks TypeCast.arg) |
| 55 | `USING (NOT false)` | SEC005 | fires; SEC008 specifically does NOT (literal-only detection) |
| 56 | `gone IS TRUE` (BoolTest) on dropped column | HYG001 | fires (extract walks BoolTest.arg) |
| 57 | `auth.uid()::text` (TypeCast over auth call) | PERF001 | fires (find_func_calls walks TypeCast.arg) |
| 58 | `COALESCE(auth.uid(), default)` | PERF001 | fires (find_func_calls walks function args) |
| 59 | `fail_on = "warning"` | gates (config) | exit code 1 on PERF001 |
| 60 | `fail_on = "info"` | gates (config) | exit code 1 on SEC007 |
| 61 | `--format json` machine-readable output | (config) | parses to a dict with `violations[]` + `summary{}`; sarif still rejects cleanly |
| 62 | `[lint].disable = ["SEC005", "SEC008"]` | disabled (config) | both rules skipped |
| 63 | `allowlist = "..."` (string, not list) | error (config) | clean ClickException, no traceback |
| 64 | `app."MixedCase Table"` quoted identifier | (none) | passes (round-trips through pg_class as plain string) |
| 65 | SEC001 allowlist by unqualified name | silenced (config) | works for `legacy_orders` (no schema prefix) |
| 66 | `payload->>'visibility'` JSON access | (none) | passes (HYG001 doesn't confuse JSON keys with column names) |
| 67 | `BETWEEN now() - INTERVAL ... AND now()` | (none) | passes (extract walks AEXPR_BETWEEN) |
| 68 | `--format json` end-to-end shape | (CI contract) | top-level keys + per-violation keys + summary keys all match |
| 69 | JSON `summary` matches `violations[]` body | (invariant) | per-severity counts and total agree |
| 70 | Every JSON `rule_id` is in the shipping catalog | (catalog) | catches accidental rule typos before they reach a consumer |
| 71 | JSON empty case via `[lint].disable = [...]` | (CI contract) | `violations: []`, all-zero summary — pin for downstream parsers |
| 72 | JSON allowlist diff (default → allowlisted) | (CI contract) | summary errors drop by exactly the allowlisted policy count |
| 73 | RLS enabled, no policies defined | SEC009 | fires (silent deny-all that looks RLS-protected) |
| 74 | `USING (false)` deny-all anti-pattern | SEC010 + SEC005 | fires (deny-via-policy is misleading; REVOKE is the right primitive) |
| 75 | `--format sarif` end-to-end shape | (CI contract) | top-level $schema, single run, rule descriptors deduped, severity → level (info → note), `fullyQualifiedName` per result |
| 76 | `OR true` debug branch buried in policy | SEC011 | fires |
| 77 | Policy named `todo_replace_me_later` | HYG002 | fires (identifier tokenizer matches `todo`) |
| 78 | `random()` in USING | PERF002 + SEC005 | fires |
| 79 | `pgrls fix` end-to-end against the demo DB | (CLI behavior) | dry-run prints SEC002 ALTER TABLE + PERF001 ALTER POLICY; --rule SEC002 filters PERF001 out |
| 80 | `pgrls.testing` pytest plugin smoke | (test DSL) | seed + fetchall round-trip via PgrlsTestClient |
| 81 | `pgrls diff`: dropped RESTRICTIVE policy | DIFF_POLICY_DROPPED_RESTRICTIVE | DANGEROUS classification, severity=error, exit 1 |
| 82 | `pgrls diff`: added RESTRICTIVE policy | DIFF_POLICY_ADDED_RESTRICTIVE | SAFE classification, severity=info, exit 0 |
| 83 | `pgrls diff`: dropped column referenced by policy | DIFF_COLUMN_DROPPED_REFERENCED | REQUIRES_REVIEW, severity=warning, gated by --fail-on requires-review |
| 84 | `pgrls diff`: dropped PERMISSIVE policy | DIFF_POLICY_DROPPED_PERMISSIVE | BREAKING classification, severity=warning, gated by --fail-on breaking |
| 85 | Non-`security_invoker` view over RLS table | VIEW001 | fires |
| 86 | Non-`security_barrier` view over RLS table | VIEW002 | fires |
| 87 | Materialized view over RLS table | VIEW003 | fires |
| 88 | View calling SECDEF function reading RLS table | VIEW004 | fires |

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
pytest demo/ -v
```

Spins up an isolated Postgres via `testcontainers` (no port
collisions), applies `_shared.sql` plus every case's `setup.sql`,
and runs 94 assertions — one or more per use case plus
configuration-driven scenarios that exercise per-test `--config`
overrides (allowlist, disable, custom `auth_functions`,
multi-schema, fail_on, format), the JSON / SARIF output
contracts, the `pgrls.testing` plugin, and the four `pgrls diff`
classifications. Each test is named `test_uc<NN>_<what_it_does>`
for top-to-bottom readability.

To run the tests against a long-running DB you started with `run.sh`:

```bash
DATABASE_URL=postgres://demo:demo@localhost:5433/demo \
    pytest demo/ -v
```

## Expected lint output

Around 68 violations across all three severities (`27 errors,
35 warnings, 6 infos.`). The fixture is intentionally noisy — most
violations come from cross-fires where one bad policy trips several
rules at once (`USING (true)` → SEC005 + SEC008 + SEC003 if PUBLIC; a
Supabase `auth.uid() IS NULL OR ...` → SEC004 + PERF001). Each
`test_uc<NN>_*` test asserts the *primary* rule for its use case;
cross-fires show up as additional lines in the lint output.

A few representative lines:

```
ERROR  SEC001  app.legacy_orders                 (use case 03)
ERROR  SEC001  app.audit_log_2026                (use case 14 — unscoped chain)
ERROR  SEC001  app.bare_metrics_2026             (use case 15 — names the parent)
ERROR  SEC001  app.leaf_metrics                  (use case 24 — leaf has its own RLS)
ERROR  SEC001  app.legacy_parent / legacy_child  (use case 33 — classic INHERITS, no partition_of)
ERROR  SEC003  app.blog_posts.blog_admin_or_author_read  (use case 26)
ERROR  SEC003  app.public_metadata.metadata_read         (use case 43 — until allowlisted)
ERROR  SEC004  app.profiles.allow_anon           (use case 19 — Supabase shape)
ERROR  HYG001  app.partial_orphan.orphan_filter  (use case 37 — isolated to the offending policy)
WARN   SEC005  app.always_open.trivially_open    (use case 35 — `1=1`)
WARN   PERF001 app.todos.todos_owner             (use case 20 — auth.uid unwrapped)
WARN   PERF001 app.jwt_unwrapped.jwt_unwrapped_owner  (use case 38 — auth.jwt() ->>)
INFO   SEC007  app.tags                          (use case 09)
```

Tables that must stay silent (clean cases 01, 02 via allowlist, 13,
16-18, 21, 23, 25, 27-32, 34, 36, 44-51, 53, 54, 64-67) never appear
in any violation line. The clean tests assert this directly. The
configuration-driven cases (39-43, 59-63) verify behavior under
specific `--config` overrides — see `conftest.py::lint` for the
helper that drives those.

## Wiring this into CI

The repo root [README.md](../README.md#ci-integration) has a full
GitHub Actions recipe with a Postgres service container and a JSON
report artifact. Two demo-relevant snippets:

**Block the build on errors only:**

```toml
# pgrls.toml
[lint]
fail_on = "error"
```

`fail_on = "error"` blocks on SEC001/2/3/4/6/HYG001. Bump to
`warning` to also block on SEC005/8/PERF001, or `info` to also block
on SEC007.

**Extract specific rules from the JSON output via `jq`:**

```bash
# Count violations per rule:
pgrls lint --format json | jq '.violations | group_by(.rule_id) |
    map({rule: .[0].rule_id, count: length})'

# List every SEC001 location:
pgrls lint --format json | jq '.violations[] |
    select(.rule_id == "SEC001") | .location'

# Fail the build only if SEC004 or HYG001 fires (overrides fail_on):
pgrls lint --format json | jq -e '
    .violations | map(select(.rule_id == "SEC004" or .rule_id == "HYG001")) | length == 0'
```
