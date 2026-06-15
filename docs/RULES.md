# Rules reference

Every built-in `pgrls` rule, with full detection logic, severity,
fix guidance, and configuration. Cross-linked from the
[README](../README.md) rule table; also available from the command
line as `pgrls explain <RULE>` (e.g. `pgrls explain SEC033`).

This file is the canonical rule reference. The
[AGENTS.md](../AGENTS.md) file in the repo root is the high-level
project orientation (what pgrls is, when to suggest it, the quick
start, config schema) — it links here for the per-rule details
instead of duplicating them.

`pgrls report` is the rule-free counterpart: it prints each table's
RLS posture — RLS enabled / `FORCE`'d / policy counts plus a coarse
`protected` / `not-forced` / `no-policies` / `covered-by-parent` /
`rls-off` status (`covered-by-parent` credits a partition child whose
RLS-enabled ancestor is among the scanned schemas; `no-policies` covers
zero policies *and* restrictive-only tables, both default-deny) — and
an aggregate summary, in text / JSON / Markdown / HTML. The HTML
format is self-contained (embedded CSS, no external assets) for
archiving as an audit artefact, printing to PDF, or emailing to a
reviewer who doesn't run pgrls. A snapshot for audits and onboarding;
it runs no rules and emits no findings.

<a id="rule-sec001"></a>

## SEC001 — RLS not enabled on table

**Severity:** error.

**What it catches:** a table in a scanned schema where
`pg_class.relrowsecurity` is false **and the table has no policies** —
a table with RLS simply never turned on. The closely related case
where a table *does* carry policies but RLS is off (the policies are
dormant and the table is wide open) is ceded to **SEC032**, which
gives that higher-confidence footgun its own pointed message; SEC001
and SEC032 are disjoint, so a given RLS-off table trips exactly one.

**Standard fix.** For a tenant-scoped table:

```sql
ALTER TABLE public.invoices ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.invoices FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON public.invoices
    FOR ALL
    TO authenticated
    USING (tenant_id = (SELECT current_setting('app.tenant_id')::uuid))
    WITH CHECK (tenant_id = (SELECT current_setting('app.tenant_id')::uuid));
```

Key points when generating the fix:

- Always pair `ENABLE` with `FORCE`. Without `FORCE`, the table owner (often
  the migration role) bypasses RLS, which masks bugs in development and CI.
- Always include `WITH CHECK` on writable policies. Without it, a tenant could
  `INSERT` or `UPDATE` rows belonging to another tenant.
- Match `WITH CHECK` to `USING` unless there is an intentional asymmetry
  (e.g., readable but not writable). If they differ, leave a comment on the
  policy explaining why.
- Do not use `TO PUBLIC` for tenant policies. Restrict to the application
  role(s) that actually serve user requests.
- The tenant key (`tenant_id`, `org_id`, `current_setting(...)`) must be set
  by the application on every connection. Document where that happens.

**When the table really is shared.** Reference data such as country lists,
currency codes, or feature flags is intentionally world-readable. Allowlist it
rather than enabling RLS:

```toml
[lint.rules.SEC001]
allowlist = ["countries", "currencies"]
```

Add a one-line comment in `pgrls.toml` explaining why each entry is exempt —
future maintainers (human and otherwise) need that context.

**Partitioned tables.** Postgres does not propagate `relrowsecurity` from a
partitioned parent down to its children, but queries that go through the
parent DO apply the parent's policies. SEC001 walks each child's
`PARTITION OF` chain and suppresses the violation when any ancestor has
RLS enabled — otherwise SEC001 would fire on every partition of every
RLS-enabled parent.

The rule emits one of three messages so the maintainer can fix the right
table at the right level:

- **Standalone or partition root, no RLS** — classic message: "Add
  `ENABLE ROW LEVEL SECURITY` or include the table in the allowlist."
- **Partition child of a visible RLS-less parent** — names the root:
  "is a partition of `<root>`, which also lacks row-level security.
  Enable RLS on the parent…" Steers the fix to the level that covers
  every sibling in one shot.
- **Partition child whose chain leaves the scanned schemas** — "ancestor
  chain leaves the scanned schemas before pgrls could verify RLS
  coverage." Fix by adding the parent's schema to `database.schemas`
  (or `--schemas`).

The trade-off is real: a direct query against a partition (e.g.
`SELECT FROM events_2026` rather than `SELECT FROM events`) bypasses the
parent's policies. If direct child access is part of the application's
threat model, do NOT rely on inherited parent policies — push the policy
down to every child via `CREATE POLICY ... ON public.events_2026` so
each child carries its own protection. Allowlisting children is the
wrong tool here: it removes the SEC001 check entirely, which is the
opposite of what you want.

<a id="rule-sec002"></a>

## SEC002 — FORCE ROW LEVEL SECURITY missing

**Severity:** error.

**What it catches:** tables with `relrowsecurity = true` but
`relforcerowsecurity = false`. Without `FORCE`, the table owner role
bypasses RLS entirely. Migration tools and seed scripts often run as the
owner, which lets them write rows that production roles wouldn't be
allowed to write — a class of bug that only manifests when a regular
application connection finally sees the data.

**Standard fix.**

```sql
ALTER TABLE public.invoices FORCE ROW LEVEL SECURITY;
```

If a specific role legitimately needs to bypass (e.g. a maintenance role
that runs vacuum-style work), grant `BYPASSRLS` on that role rather than
turning `FORCE` off table-wide. SEC016 then flags that role; allowlist it
in `[lint.rules.SEC016]` once the need is confirmed.

<a id="rule-sec003"></a>

## SEC003 — Permissive policy grants access to PUBLIC

**Severity:** error.

**What it catches:** policies where `permissive = true` AND `PUBLIC` is
in the role list. Permissive policies stack with `OR`; granting them to
`PUBLIC` means any role — including unauthenticated connections — gets
the policy's `USING` clause as the gate, regardless of any role-specific
policies that might exist on the same table.

**Standard fix.** Restrict the policy to the role that should actually
have it:

```sql
DROP POLICY public_read ON public.invoices;
CREATE POLICY tenant_read ON public.invoices
    FOR SELECT
    TO authenticated
    USING (tenant_id = (SELECT current_setting('app.tenant_id')::uuid));
```

If the table is genuinely public-readable (reference data), use a
`RESTRICTIVE` policy instead of a `PERMISSIVE` one — restrictive policies
narrow rather than expand access.

**Allowlisting individual policies.** Use `[lint.rules.SEC003].allowlist`
with qualified policy IDs of the form `schema.table.policy_name` —
e.g. `["public.feature_flags.public_read"]`. Prefer this over
`[lint].disable = ["SEC003"]`, which silences the rule globally.

<a id="rule-sec004"></a>

## SEC004 — Inverted auth check (Lovable CVE pattern)

**Severity:** error. **The marquee rule** — this is the pattern that
caused real CVEs across hundreds of AI-generated apps.

**What it catches:** policies whose `USING` clause contains a top-level
`OR` disjunct shaped as `auth_func() IS NULL` for one of: `auth.uid`,
`auth.role`, `auth.jwt`, `current_user`, `session_user`, or
`current_setting`. The intent was usually "let unauthenticated requests
through to a downstream check"; the bug is that the disjunct evaluates
to `true` for anonymous connections, satisfying the `OR` and exposing
every row.

**The bad pattern:**

```sql
CREATE POLICY broken ON public.invoices
    FOR SELECT TO PUBLIC
    USING (
        auth.uid() IS NULL                       -- ← exposes every row
        OR user_id = auth.uid()
    );
```

**Standard fix.** Drop the `IS NULL` disjunct entirely. Authentication
should be enforced upstream (PostgREST refuses unauth, the application
fails before the query, etc.); RLS is the *last* line of defense, not a
fallback for missing auth.

```sql
CREATE POLICY scoped ON public.invoices
    FOR SELECT TO authenticated
    USING (user_id = (SELECT auth.uid()));
```

(The `(SELECT auth.uid())` wrap is the same one PERF001 recommends —
keeping it here means the SEC004 fix doesn't itself trigger PERF001.)

If anonymous read access is intentional for a specific table, model it
explicitly with a separate policy granted to `anon` — don't bake the
"anonymous → see everything" behavior into a tenant policy.

**Configuring the auth function set.** If your stack uses a custom auth
helper, replace the default function set in `pgrls.toml`. The override
REPLACES the default — list every function you want covered, including
the stock ones if you still use them:

```toml
[lint.rules.SEC004]
# Includes the stock set (auth.uid, auth.role, auth.jwt, current_setting,
# current_user, session_user) plus the custom helper.
auth_functions = [
    "auth.uid", "auth.role", "auth.jwt", "current_setting",
    "current_user", "session_user", "my.current_user_id",
]
```

The default set already covers Supabase (`auth.*`), session GUCs
(`current_setting`), and stock Postgres (`current_user`,
`session_user`).

<a id="rule-sec005"></a>

## SEC005 — Policy expression has no own-column reference

**Severity:** warning.

**What it catches:** policies whose `USING` and `WITH CHECK` clauses
contain no reference to any column on the table they protect. A policy
that only checks session state (`auth.uid()`, `current_setting(...)`)
or constants gates the table by *who is asking*, not by *which row*.
Every authorized caller sees every row — usually not the intent for a
multi-tenant table.

**The bad pattern:**

```sql
-- No tenant_id check — any authenticated user sees every row.
CREATE POLICY tenant_read ON public.invoices
    FOR SELECT TO authenticated
    USING (auth.uid() IS NOT NULL);
```

**Standard fix.** Reference the column that scopes access:

```sql
CREATE POLICY tenant_read ON public.invoices
    FOR SELECT TO authenticated
    USING (tenant_id = (SELECT current_setting('app.tenant_id')::uuid));
```

The rule walks the entire expression in both `USING` and `WITH CHECK`,
including inside subqueries. That's deliberate so correlated patterns
like `EXISTS (SELECT 1 FROM members m WHERE m.tenant_id = tenant_id)`
— where the policy's own column is referenced via correlation — don't
trip a false positive. The trade-off is a rare false negative when a
subquery references a column with the same bare name as one on the
policy's own table. Policies on tables with no introspected columns
are skipped.

**When the warning is acceptable.** A few tables really are gated by
session state alone — e.g. an audit log read by a single admin role,
or a singleton settings row keyed by no tenant. Allowlist the policy
explicitly:

```toml
[lint.rules.SEC005]
allowlist = ["public.audit_log.admin_read"]
```

<a id="rule-sec006"></a>

## SEC006 — Write-side policy missing WITH CHECK

**Severity:** error.

**What it catches:** policies whose `command` is `INSERT`, `UPDATE`, or
`ALL` and whose `WITH CHECK` clause is absent. `USING` filters reads;
`WITH CHECK` validates writes.

For **permissive** write policies the failure is read-write asymmetry:
without `WITH CHECK` the policy admits every write, including ones
that violate the policy's own `USING` predicate — silent cross-tenant
data poisoning.

For **restrictive** write policies the failure is different: Postgres
defaults the missing `WITH CHECK` to `true` and AND-combines it into
the restrictive group, so the policy imposes no constraint on new
rows. The author wrote a restrictive intending to forbid something;
they're forbidding nothing — a dead policy. SEC006 fires on both
shapes; the violation message branches so the diagnosis matches the
actual problem (security hole vs. dead policy).

**Standard fix.** Add a `WITH CHECK` clause that matches `USING`. Wrap
the auth-style call in `(SELECT …)` so it doesn't itself fire PERF001
(per-row re-evaluation of stable functions):

```sql
CREATE POLICY tenant_write ON public.invoices
    FOR UPDATE
    TO authenticated
    USING (tenant_id = (SELECT current_setting('app.tenant_id')::uuid))
    WITH CHECK (tenant_id = (SELECT current_setting('app.tenant_id')::uuid));
```

Asymmetric `USING` and `WITH CHECK` are valid (e.g. read your own and
your team's, write your own only) but should carry an explanatory
comment — the asymmetry is rarely accidental and rarely obvious.

**Allowlisting individual policies.** Use `[lint.rules.SEC006].allowlist`
with qualified policy IDs of the form `schema.table.policy_name`.

<a id="rule-sec007"></a>

## SEC007 — All policies on table are permissive

**Severity:** info.

**What it catches:** tables where every policy has `permissive = true`
and no `RESTRICTIVE` policy is defined. Permissive policies stack with
`OR` — adding one only ever broadens access. Without a `RESTRICTIVE`
floor, there is no single predicate every caller must satisfy, so a
loose permissive policy added later (e.g. `TO PUBLIC USING (true)`)
quietly opens the table to everyone.

A `RESTRICTIVE` policy that all callers must satisfy in addition to
the permissive set anchors the access surface. Common shape: one
restrictive `tenant_id` floor plus permissive policies for read/write
specifics.

**Standard fix.** Add a tenant-scoping `RESTRICTIVE` policy that
applies to every command:

```sql
CREATE POLICY tenant_floor ON public.invoices
    AS RESTRICTIVE
    FOR ALL
    TO authenticated
    USING (tenant_id = (SELECT current_setting('app.tenant_id')::uuid))
    WITH CHECK (tenant_id = (SELECT current_setting('app.tenant_id')::uuid));
```

The rule skips tables with RLS disabled (SEC001's surface) and tables
with zero policies (deny-by-default — adding a permissive policy is
the next step, not a finding).

**When the info is acceptable.** Reference tables that really are
universally readable, or single-policy tables where the lone
permissive policy *is* the intentional surface. Allowlist by table:

```toml
[lint.rules.SEC007]
allowlist = ["public.countries", "public.feature_flags"]
```

<a id="rule-sec008"></a>

## SEC008 — Permissive policy USING clause is constant true

**Severity:** warning.

**What it catches:** **permissive** policies whose `USING` clause is a
literal `true`. Detection is intentionally narrow — only the AST
pattern `A_Const(Boolean(true))` matches. Semantic tautologies like
`1 = 1` are not detected (a real tautology checker is significant
infrastructure for marginal value, and most disguised tautologies
also fail SEC005).

A permissive `USING (true)` admits every row to every caller in the
policy's role list (permissive policies OR-combine, so a constant-true
branch passes everything). It is almost always scaffolding left in by
accident. A *restrictive* `USING (true)` is the opposite failure — it
AND-combines to a no-op floor — and is covered by **SEC031** with an
accurate message, so SEC008 is scoped to permissive policies only.

**Standard fix.** Replace the literal with a real predicate, or drop
the policy:

```sql
-- Before
CREATE POLICY public_read ON public.invoices
    FOR SELECT TO authenticated USING (true);

-- After
CREATE POLICY tenant_read ON public.invoices
    FOR SELECT TO authenticated
    USING (tenant_id = (SELECT current_setting('app.tenant_id')::uuid));
```

If `USING (true)` is intentional (e.g. a deliberately public
reference table), pair it with a `RESTRICTIVE` policy that enforces
the actual surface, or allowlist the policy. The allowlist accepts
qualified policy IDs of the form `schema.table.policy_name`:

```toml
[lint.rules.SEC008]
allowlist = ["public.countries.public_read"]
```

<a id="rule-sec009"></a>

## SEC009 — RLS enabled but no policies defined

**Severity:** warning.

**What it catches:** tables with `relrowsecurity = true` and zero
rows in `pg_policy`. Postgres treats this as deny-all — every query
returns no rows, regardless of role. Common shape: a migration
enabled RLS planning to add policies later, then the policy work
was deferred and forgotten. Symptom is "the table looks empty,"
which can take an embarrassingly long time to notice in dev.

**Standard fix.** Add the policies the migration was meant to
include:

```sql
ALTER TABLE public.invoices ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.invoices FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON public.invoices
    FOR ALL TO authenticated
    USING (tenant_id = (SELECT current_setting('app.tenant_id')::uuid))
    WITH CHECK (tenant_id = (SELECT current_setting('app.tenant_id')::uuid));
```

**When the deny-all is intentional** (an audit log read only by
superusers, a soft-deleted "tombstone" table, a temporary block
during migration), allowlist the table:

```toml
[lint.rules.SEC009]
allowlist = ["audit.events", "private.tombstones"]
```

The allowlist accepts unqualified or `schema.table` entries — same
shape as SEC001 and SEC002.

<a id="rule-sec010"></a>

## SEC010 — Policy clause is constant false

**Severity:** warning.

**What it catches:** policies whose `USING` or `WITH CHECK`
clause is a literal `false`. Detection mirrors SEC008 — only the
AST pattern `A_Const(Boolean(false))` matches. Semantic
equivalents like `NOT true` or `1 = 0` are not detected; like
SEC008 the disguised cases are usually also SEC005 findings (no
own-column reference).

`USING (false)` denies every row from the policy. As the only
policy on a table it produces deny-all (the same effect as SEC009 —
RLS enabled, no policies — just achieved through a more misleading
mechanism: the table looks "RLS protected" because it has a policy,
but the predicate makes it effectively disabled). As one of several
policies it's a no-op for permissive combinations and forces
deny-all for restrictive ones.

`WITH CHECK (false)` is the write-side mirror — every
INSERT/UPDATE through the policy fails. Same anti-pattern: the
intent ("nobody can write through this role") belongs at the
GRANT layer.

**Standard fix.** Express denial at the GRANT layer instead — that
is the right primitive:

```sql
-- Before: misleading "RLS-protected" deny.
CREATE POLICY block_all ON public.invoices
    AS RESTRICTIVE FOR SELECT TO PUBLIC USING (false);

-- After: explicit revoke at the role layer.
DROP POLICY block_all ON public.invoices;
REVOKE ALL ON TABLE public.invoices FROM PUBLIC;
```

If you really do need to express "deny" via policy form (rare but
legal — e.g., a temporary block coordinated with a feature flag),
allowlist the policy by qualified ID:

```toml
[lint.rules.SEC010]
allowlist = ["public.invoices.block_all"]
```

<a id="rule-sec011"></a>

## SEC011 — Policy expression has an `OR true` branch

**Severity:** warning.

**What it catches:** policies whose `USING` (or `WITH CHECK`)
contains an `OR true` branch anywhere in the expression tree. The
literal `true` ORed with anything else is still `true`, but a
casual reading misses the disjunction — the predicate evaluates
to true for every row regardless of the other branches.

Common shape: a debug branch left in by accident. The author
adds `OR true` to "temporarily let everything through" while
checking data, then forgets to remove it.

**Standard fix.** Remove the `OR true`:

```sql
-- Before
CREATE POLICY tenant_read ON public.invoices
    FOR SELECT TO authenticated
    USING (
        tenant_id = (SELECT current_setting('app.tenant')::uuid)
        OR true  -- forgotten debug
    );

-- After
ALTER POLICY tenant_read ON public.invoices
    USING (tenant_id = (SELECT current_setting('app.tenant')::uuid));
```

If the intent really is "admit every row" (rare in production),
drop the policy and either disable RLS on the table or REVOKE the
GRANT.

Detection is narrow on purpose — only the literal `true` `A_Const`
inside an `OR` BoolExpr counts. Semantic-equivalent tautologies
(`1 = 1`, `'a' = 'a'`, etc.) fall through to SEC005's no-own-col
framing instead. A real tautology checker is significant
infrastructure for marginal real-world value.

<a id="rule-sec012"></a>

## SEC012 — Table has only RESTRICTIVE policies (silent deny-all)

**Severity:** warning.

**What it catches:** tables where RLS is enabled, at least one
policy exists, and every policy is `RESTRICTIVE`. Postgres composes
RLS as `permissive_or | (restrictive_and & ...)`: a row is visible
iff at least one PERMISSIVE policy matches AND every RESTRICTIVE
policy matches. With zero PERMISSIVE policies the disjunction is
empty — no row passes, regardless of how many RESTRICTIVE policies
you've added or what they say.

Common shape: a developer adds a `AS RESTRICTIVE` policy thinking
it "layers on top of" an implicit permissive default. There is no
implicit default. The table is silently deny-all from the moment
RLS is enabled.

This is the same effective shape as SEC009 (RLS enabled, zero
policies) and SEC010 (`USING (false)` deny-all anti-pattern),
just achieved through a different mechanism. SEC009 catches the
explicit "no policies at all" case; SEC010 catches the explicit
`false` literal; SEC012 catches the silent "only RESTRICTIVE"
case where the user intended access but composed the policies
wrong. The three rules are disjoint by construction — a table
can't trigger more than one.

**Standard fix.** Add a PERMISSIVE policy that describes who
CAN see rows. The existing RESTRICTIVE policies will narrow
that access further:

```sql
-- Before: silent deny-all (no PERMISSIVE).
CREATE POLICY tenant_lock ON public.invoices
    AS RESTRICTIVE FOR ALL
    TO authenticated
    USING (tenant_id = (SELECT current_setting('app.tenant')::uuid));

-- After: PERMISSIVE grants access; RESTRICTIVE narrows it.
CREATE POLICY tenant_read ON public.invoices
    FOR ALL TO authenticated
    USING (true);
CREATE POLICY tenant_lock ON public.invoices
    AS RESTRICTIVE FOR ALL
    TO authenticated
    USING (tenant_id = (SELECT current_setting('app.tenant')::uuid));
```

(A bare `USING (true)` PERMISSIVE will trip SEC008 — narrow it to
the access predicate the table actually wants.)

If the deny-all is genuinely intentional — e.g., a "shadow" table
that exists only to be queried via a SECURITY DEFINER function and
should never be visible through direct `SELECT` — allowlist by
qualified or unqualified table name:

```toml
[lint.rules.SEC012]
allowlist = ["public.shadow_audit"]
```

<a id="rule-sec013"></a>

## SEC013 — Trigger on RLS-protected table can bypass policies

**Severity:** warning.

**What it catches:** every user-authored, enabled trigger on a
table with `rls_enabled = true`. Triggers fire as the table OWNER,
not as the role that ran the statement, so any `SELECT` / `INSERT`
/ `UPDATE` / `DELETE` inside the trigger function body sees the
owner's view of the database — every row, RLS bypassed — even
when the invoking role has policies that would hide or reject
those rows directly.

The bypass is silent: no SQLSTATE 42501, no error in the log.
A multi-tenant table protected by `WHERE tenant_id =
current_setting('app.tenant_id')` looks impregnable until a
`BEFORE INSERT` trigger written for an unrelated purpose
(denormalization, audit logging, cache invalidation) cross-
references another tenant's data with the same logic and quietly
leaks it into the invoking session's view.

Common leak shapes worth auditing for:

* Audit trigger writes `(NEW.id, current_setting('app.tenant_id'),
  (SELECT count(*) FROM peer_table))` into an audit table. The
  subquery runs as owner and counts every tenant's rows.
* Trigger that "syncs" a derived column reads from a peer table
  with no tenant filter, exposing peer-tenant values through the
  synced column.

The rule cannot read the trigger function body (PL/pgSQL bodies
aren't parseable by pglast as top-level statements, and
`SECURITY INVOKER` does not change the trigger-fires-as-owner
contract — `pg_proc.prosecdef` is irrelevant here), so the
warning is intentionally a prompt-to-audit rather than a proof
of leak.

Internal triggers (foreign-key check helpers, RI plumbing,
partition-routing triggers) are filtered out at the introspection
layer via `pg_trigger.tgisinternal = false`. Disabled triggers
(`tgenabled = 'D'`) are captured in the snapshot but skipped by
the rule — they can't fire under any `session_replication_role`.

**Out of scope in v0.5.8**: INSTEAD OF triggers on views. The
introspection layer only captures triggers whose `tgrelid` points
to a regular or partitioned table (`relkind IN ('r','p')`).
INSTEAD OF view-triggers are a real bypass surface — a write
routed by an INSTEAD OF trigger can land in a base table without
honoring the view's WHERE clause — and warrant a future
companion rule on the view side. Until that lands, operators
relying on view-triggers for security-sensitive writes should
audit them manually.

**Snapshot tampering**: `pgrls diff` does not yet emit
`DIFF_TRIGGER_*` change kinds — an edit to a checked-in v6
snapshot file that deletes a `triggers` entry or flips
`enabled: true → false` will not show up as a diff finding.
Treat snapshot files like any other security-relevant artifact:
review changes, sign commits, restrict write access. A future
release should add `DIFF_TRIGGER_ADDED` / `DIFF_TRIGGER_DROPPED`
/ `DIFF_TRIGGER_DISABLED` (the last classifiable as
`requires_review` since it silences SEC013).

**Standard fix.** Audit the trigger function body for:

* Reads from peer tables without a tenant filter.
* Writes the caller couldn't issue directly (insertions into
  audit / cache tables that include cross-tenant data, writes
  to a peer tenant's rows, etc.).
* Owner-visible data echoed back to the caller through derived
  columns, `RAISE NOTICE`, or `RAISE EXCEPTION` messages.

If the trigger needs cross-tenant visibility (legitimate use case
for audit / replication / global-counter triggers), rewrite the
function to take the tenant explicitly and reject rows whose
`NEW.tenant_id` doesn't match `current_setting('app.tenant_id')`.
Then allowlist the trigger by qualified ID:

```toml
[lint.rules.SEC013]
allowlist = ["public.invoices.audit_writes"]
```

The allowlist key is `schema.table.trigger_name` (three parts).
Bare `trigger_name` is rejected because two tables can carry
identically-named triggers — Postgres scopes trigger names per
table, and a name-only allowlist would silence both.

<a id="rule-sec014"></a>

## SEC014 — SECURITY DEFINER function bypasses caller's RLS

**Severity:** warning. **Auto-fix:** no (architectural choice
needs human intent).

A `SECURITY DEFINER` function runs with the privileges of the
function owner, not the calling role. Every
SELECT/INSERT/UPDATE/DELETE inside the body sees the owner's
view of the database — RLS bypassed, GRANT/REVOKE differences
flattened, the entire row set readable and mutable. A role
with EXECUTE permission on the function effectively inherits
the owner's reach into RLS-protected tables.

Two existing rules cover the SECDEF risk for *indirect* paths:

* **VIEW004** flags views whose body calls a SECDEF function
  that reads an RLS-protected table — view-mediated bypass.
* **SEC013** flags triggers on RLS-protected tables, which
  fire as the table owner regardless of the trigger function's
  `prosecdef` flag — trigger-mediated bypass.

SEC014 closes the gap for SECDEF functions called *directly*
from application code (`SELECT my_secdef(...)`, JDBC, ORM
function bindings). The rule flags *every* SECDEF function in
the introspected schemas, regardless of how it's invoked. The
intent isn't to detect free-standing-vs-trigger-vs-view via
call-graph analysis (which would require app-level context
pgrls doesn't have) — it's to surface the full SECDEF surface
to the operator so each function gets an explicit audit
decision: either rewrite as `SECURITY INVOKER` (so RLS applies
to the caller), or document why the bypass is intentional and
allowlist the function.

Detection is structural: walk
`Schema.security_definer_functions` (captured by introspection
from `pg_proc.prosecdef = TRUE` since snapshot v4). No body
parsing — VIEW004 already does that for the view-mediated path,
and re-doing it here would either duplicate work or under-report
(e.g. a function that writes to an RLS table via dynamic SQL
pglast can't parse).

The allowlist key is `schema.function` (two parts).
Bare `function_name` is rejected because two same-named
functions in different schemas would otherwise both be silenced
— Postgres allows the cross-schema collision, and a
name-only allowlist would mask it.

```toml
[lint.rules.SEC014]
allowlist = [
    "audit.refresh_cache",      # reviewed 2026-05-15 — owner is a
                                # restricted audit role, no RLS-table
                                # reads in the body.
    "public.tenant_signup",     # legitimate cross-tenant write under
                                # admin approval; documented in
                                # docs/runbooks/signup.md.
]
```

**Language coverage.** SEC014 flags every SECDEF function
regardless of `pg_proc.prolang` (`sql`, `plpgsql`, `c`, etc.).
The language is included in the violation message so the
operator's triage can prioritize parseable bodies (where
VIEW004 may already have flagged the leak via view path) over
opaque ones (where SEC014 is the only signal).

Out of scope (intentional):

* **Argument signatures** are not part of the allowlist shape.
  A function with two overloads (e.g. `do_thing(int)` vs
  `do_thing(text)`) is flagged once and allowlisted once —
  introspection captures `proname` only. Operators who need
  per-overload granularity should `ALTER FUNCTION` one of
  them to a different name.
* **Function-body reachability of RLS tables** is not gated
  here. VIEW004 already analyses bodies for RLS-table reads;
  SEC014 is an "audit every SECDEF surface" prompt, not a
  proof-of-leak.
* **Cross-scope SECDEF functions.** A SECDEF function in a
  schema outside `--schemas` is invisible to SEC014 (same
  false-negative path VIEW004 documents). To audit such
  functions, expand `--schemas` to include the function's
  home schema.

<a id="rule-sec015"></a>

## SEC015 — SECURITY DEFINER function exposed to pg_temp shadowing

**Severity:** warning. **Auto-fix:** yes (`pgrls fix` emits one
`ALTER FUNCTION <schema>.<name>(<signature>) SET search_path = …`
per flagged overload, pinning `pg_temp` as the last token).

A `SECURITY DEFINER` function runs as its owner. When the body
references a relation or data type — a table, view, sequence,
or type — by an **unqualified** name, Postgres resolves that
name against the function's effective `search_path`. The danger
is the default: Postgres searches `pg_temp`, the per-session
temporary schema that **every** connected role can write to,
*first* — ahead of even `pg_catalog` — for relation and data
type names (it is never searched for function or operator
names), *unless* `pg_temp` is named explicitly in
`search_path`. An attacker creates a same-named object in their
session's `pg_temp`; the privileged function silently resolves
the unqualified reference
to the attacker's object and executes attacker-controlled SQL
with the owner's privileges. This is the CVE-2018-1058
search-path privilege-escalation class.

SEC015 fires when a SECDEF function's effective `search_path`
does not end with an explicit `pg_temp` token:

* **No `SET search_path` clause** — the function inherits the
  *caller's* search_path. The caller is the attacker; `pg_temp`
  is implicitly first.
* **`SET search_path` present but `pg_temp` absent** — e.g. the
  common `SET search_path = pg_catalog, public`. `pg_temp` isn't
  named, so the default (searched first) still applies.
* **`pg_temp` named but not last** — e.g.
  `SET search_path = pg_temp, public`. It's searched at the
  written position, ahead of the legitimate schemas.

The only structurally-safe shape — `pg_temp` named as the
**last** entry of a pinned `search_path` — passes. This is the
pattern the Postgres documentation prescribes for SECURITY
DEFINER functions: naming `pg_temp` last forces the temp schema
to be searched last.

The introspector decodes the function's `search_path` from
`pg_proc.proconfig` (snapshot v8+). The fix is mechanical, and
`pgrls fix` applies it: per flagged overload it emits
`ALTER FUNCTION <schema>.<name>(<signature>) SET search_path = …`,
rewriting the path so `pg_temp` is pinned last with exactly one
occurrence. When the function already pins a path, the existing
entries are preserved (case-intact) and any earlier `pg_temp`
tokens are stripped so it ends up last; when no path is pinned at
all, the fixer emits the minimal-but-safe default
`SET search_path = pg_catalog, pg_temp` — strictly tighter than
the caller's path, so a function whose body needs unqualified
names from another schema needs the operator to insert that
schema before `pg_temp` in the generated SQL (the Fix description
prompts this). The fixer **abstains** in two cases: a pre-v12
snapshot whose captured `signature` is empty (a bare
`ALTER FUNCTION name()` would target the wrong overload — re-snapshot
against v12+ to populate signatures), and a `search_path` whose raw
GUC string contains both a quote and a comma (a possible quoted
schema name with an internal comma that the naive comma-split
tokenizer can't safely rewrite). Either way you can run the
`ALTER FUNCTION` by hand, or allowlist the function after confirming
its body fully-qualifies every object reference (in which case
`search_path` is moot).

The allowlist key is `schema.function` (two parts). Bare
`function_name` is rejected for the same reason as SEC014.

```toml
[lint.rules.SEC015]
allowlist = [
    "audit.refresh_cache",  # reviewed 2026-05-15 — body fully-
                            # qualifies every table reference, so
                            # search_path is moot.
]
```

Relationship to the other SECDEF rules: SEC014 flags every
SECDEF function as a generic audit surface; SEC015 is narrower
and sharper — it doesn't say "audit this," it says "this
function has an exploitable `search_path` and here is the
one-line fix." A function flagged by both SEC014 and SEC015 is
the common case; allowlisting it in SEC015 (after the fix)
still leaves the SEC014 audit-surface finding, which the
operator clears separately.

Out of scope (intentional):

* **Body-level qualification analysis.** A SECDEF function with
  an unsafe `search_path` but a body that fully-qualifies every
  object reference is not actually exploitable. SEC015 doesn't
  parse the body to prove that — it flags on the `search_path`
  shape alone and lets the operator allowlist the audited-safe
  cases. A body-qualification proof is exactly the brittle AST
  analysis VIEW004 documents false-negatives for; the
  structural `search_path` check has no false negatives.
* **Cross-scope functions.** A SECDEF function in a schema
  outside `--schemas` is invisible to SEC015. Expand
  `--schemas` to audit it.

<a id="rule-sec016"></a>

## SEC016 — Role with the BYPASSRLS attribute bypasses all RLS

**Severity:** warning. **Auto-fix:** no (`pgrls` cannot tell a
misconfigured application role from a backup / logical-replication
/ ETL role that legitimately needs the attribute — the
`ALTER ROLE … NOBYPASSRLS` decision needs human intent).

A Postgres role granted the `BYPASSRLS` attribute skips **every**
row-level security policy on **every** table. RLS is not weakened
for that role — it is simply off. Any session whose current role
holds the attribute reads and writes every row in every
RLS-protected table as if no policy existed.

The danger is that a `BYPASSRLS` role looks ordinary. Nothing in
a table definition, a policy, or a `GRANT` reveals that a
particular role ignores all of them. An application that connects
as a `BYPASSRLS` role gets zero tenant isolation while every
policy in the schema still reads as airtight — the bypass is
invisible at every layer SEC001–SEC015 inspect.

`BYPASSRLS` is unconditional and cluster-wide. Contrast the two
other ways a session can end up not subject to RLS:

* A **table owner** implicitly bypasses RLS on its own tables —
  but only until `ALTER TABLE … FORCE ROW LEVEL SECURITY` is set,
  which is exactly what SEC002 flags. `FORCE` does **not** touch a
  `BYPASSRLS` role: it bypasses a FORCE'd table just the same.
* A **superuser** bypasses RLS via `rolsuper`, also
  unconditionally. A superuser additionally carrying `BYPASSRLS`
  gains nothing — the attribute is redundant noise on one. SEC016
  therefore **skips superuser roles** and flags only the
  non-superuser roles, where an RLS bypass is genuinely
  surprising.

SEC016 fires on every non-superuser role with `BYPASSRLS`. The
introspector reads the role's `rolbypassrls` / `rolsuper` /
`rolcanlogin` flags from `pg_roles` (snapshot v9+); only roles
`WHERE rolbypassrls` are captured, so a default cluster — where
no role has been granted the attribute — produces no findings.
The fix is one statement, `ALTER ROLE <name> NOBYPASSRLS`, but it
is not auto-applied (see **Auto-fix** above).

The violation message is tailored by the role's login status: a
`LOGIN` role can be authenticated as directly (an application
connecting as it gets no isolation); a `NOLOGIN` role is reached
only via `SET ROLE` by a member. Both bypass RLS — login status
shapes the message, not the verdict.

Roles are cluster-global, so SEC016 — unlike the schema-scoped
rules — has no out-of-scope blind spot: it sees every
`BYPASSRLS` role in the cluster regardless of `--schemas`.

The allowlist key is the bare role name (roles have no schema
component — there is nothing to qualify). Allowlist a role after
confirming its bypass is intentional.

```toml
[lint.rules.SEC016]
allowlist = [
    "logical_replication",  # reviewed 2026-05-15 — replication
                            # role legitimately needs BYPASSRLS.
]
```

Relationship to the other bypass rules: SEC002 covers the
table-owner bypass (mechanism: ownership; remedy: `FORCE`).
SEC013 / SEC014 / SEC015 cover code-mediated bypass: triggers
fire as the table owner (SEC013), and `SECURITY DEFINER`
functions run as the function owner (SEC014 / SEC015). SEC016
covers the attribute-mediated bypass — the role itself is exempt,
no code or ownership involved. It is the bluntest of the family:
where the others need a specific object to be misconfigured,
SEC016 needs only a role attribute to be set.

Out of scope (intentional):

* **Superuser roles.** Skipped — a superuser bypasses RLS via
  `rolsuper` regardless, and is a far larger finding than
  "bypasses RLS" anyway.
* **Role membership / `SET ROLE` reachability.** SEC016 flags only
  the role that *holds* `BYPASSRLS`, not every role that could reach
  it. `BYPASSRLS` is a role attribute, not an inheritable
  privilege — a member of a `BYPASSRLS` group role does not
  bypass RLS unless it actually `SET ROLE`s to that role. SEC016's
  surface is deliberately just the holder; the `SET ROLE`
  escalation path that reaches it is covered separately by SEC029.
* **The `row_security` session GUC.** `SET row_security = off` is
  a different mechanism, and not a silent one: a query that
  *would* return RLS-filtered rows raises an error instead of
  quietly widening, unless the role already owns the table or
  holds `BYPASSRLS`. SEC016 covers the attribute, not the GUC.

<a id="rule-sec017"></a>

## SEC017 — Function with the LEAKPROOF attribute bypasses the RLS barrier

**Severity:** warning. **Auto-fix:** yes (`pgrls fix` emits
`ALTER FUNCTION <schema>.<name>(<signature>) NOT LEAKPROOF` per
flagged overload). The *other* remedy — proving the function is
genuinely leakproof and keeping the marking — is human judgement
about its runtime behaviour (error paths, timing) and stays
out of scope; allowlist the function to take it.

A function marked `LEAKPROOF` carries a promise to the query
planner: it has **no side channels** — it will not reveal anything
about its arguments through an error message, through how long it
runs, or through any other observable behaviour. On the strength of
that promise the planner is allowed to evaluate the function
*below* a security barrier — ahead of a table's row-level security
qual, ahead of a `security_barrier` view's `WHERE`. A non-leakproof
function is held *above* the barrier and only ever sees rows the
caller is already entitled to.

For a genuinely side-channel-free function that is a safe, useful
optimization. The danger is a function *marked* `LEAKPROOF` that is
not actually leak-free. Applied to a column of an RLS-protected
table it runs on **every** row — including rows the caller's policy
would have hidden — and any error it raises (or argument-dependent
timing it exhibits) discloses those hidden rows' contents:

```sql
SELECT * FROM rls_protected
WHERE leaky_fn(secret_column) = 'probe';
```

If `leaky_fn` is `LEAKPROOF`, the planner may push
`leaky_fn(secret_column)` below the RLS qual; an attacker who
cannot see those rows still learns `secret_column` from the error
text or the response time.

Marking a function `LEAKPROOF` requires superuser — it is always a
deliberate act. SEC017 flags every function in the introspected
schemas whose `pg_proc.proleakproof` is true (snapshot v10+), so
each gets an explicit audit decision: confirm no error path and no
timing channel can expose an argument, or remove the marking.
`pgrls fix` automates the removal — it emits `ALTER FUNCTION
<schema>.<name>(<signature>) NOT LEAKPROOF` for **each** flagged
overload (one statement per overload, since a single `ALTER
FUNCTION` reaches only one). It **abstains** on a pre-v12 snapshot
whose captured `signature` is empty: a bare `ALTER FUNCTION name()
NOT LEAKPROOF` would target the zero-argument overload, wrong for
every function that has arguments — re-snapshot against a live
v12+ database to populate signatures, then re-run. pgrls does not
parse the body to prove leakproofness — that is the brittle analysis
the rule deliberately avoids (the stance SEC014 takes on SECDEF
bodies). Postgres's own built-in leakproof functions live in
`pg_catalog`, outside the linted schemas, so they never surface
here.

The allowlist key is `schema.function` (two parts). Bare
`function_name` is rejected for the same reason as SEC014/SEC015.
Overloads collapse: `public.f(int)` and `public.f(text)` both
marked `LEAKPROOF` are one finding and one allowlist entry —
introspection's `SELECT DISTINCT` on the qualified name does this,
matching the signature-free allowlist shape.

```toml
[lint.rules.SEC017]
allowlist = [
    "public.fast_eq",  # reviewed 2026-05-15 — no error path or
                       # timing channel exposes an argument.
]
```

Relationship to the other attribute/audit rules: SEC014 and SEC015
flag `SECURITY DEFINER` functions (which run as their owner); SEC016
flags roles with the `BYPASSRLS` attribute (which skip RLS
entirely). SEC017 is the fourth such rule — `LEAKPROOF` relaxes
*where in the plan* a function runs. All four surface a privileged
attribute and ask the operator to confirm it is intended.

Out of scope (intentional):

* **Body-level leak analysis.** SEC017 does not parse the body to
  decide whether the function actually leaks — a proof would have
  to enumerate every error path and data-dependent branch, brittle
  and defeated by dynamic SQL the same way VIEW004's body analysis
  is. The rule flags on the `proleakproof` flag alone.
* **Argument signatures.** The allowlist key carries no signature;
  overloads of a qualified name are flagged once and allowlisted
  once.
* **Cross-scope functions.** A `LEAKPROOF` function in a schema
  outside ``--schemas`` is invisible to SEC017. Expand
  ``--schemas`` to audit it.

<a id="rule-sec018"></a>

## SEC018 — Policy compares a column against current_user / session_user

**Severity:** warning. **Auto-fix:** no (replacing the
`current_user` comparison with a session-GUC predicate needs the
application's tenant-key name and is an architectural decision, not
a mechanical rewrite).

A policy whose `USING` or `WITH CHECK` expression compares one of
its **own table's columns** against `current_user` — or its aliases
`current_role` and `user` — or `session_user` is using *the
Postgres role the session runs as* as the row-matching key. That
isolates tenants only when every tenant connects as, or `SET ROLE`s
to, a **distinct** Postgres role.

Application architectures almost never do that. A connection pool
authenticates as one shared database role and serves every
tenant's requests over it. `current_user` is then identical for
tenant A and tenant B, and a policy like

```sql
CREATE POLICY p ON documents
    USING (owner_role = current_user);
```

matches the same way for every tenant and provides **no**
isolation. The policy looks like access control and passes every
other pgrls check, but the discriminator is a constant.
`session_user` (the login role, unchanged by `SET ROLE`) is the
same trap, and worse: it stays pinned to the pool's login role even
when the application does `SET ROLE` per request.

Detection is structural — the rule walks the parsed policy AST for
an `A_Expr` (operator) node with a role-identity `SQLValueFunction`
on one operand and a reference to a column of the policy's own
table on the other (the same own-column scoping SEC005 uses),
anywhere in the tree. (`A_Expr` is pglast's generic operator node;
in practice the operator pairing a role identity with a column is
`=` or another comparison.)

**What SEC018 deliberately does not flag.** A `current_user`
reference is only an isolation problem when it is the *row-matching
key* — compared against the table's own data. Three legitimate
uses are left alone:

* `current_user` passed to a role/privilege function —
  `pg_has_role(current_user, 'pg_read_all_data', 'MEMBER')`,
  `has_table_privilege(current_user, …)`. Here `current_user` is a
  function argument, not a comparison operand: it feeds a
  role/privilege check, the standard "admin escape" branch of a
  policy, not a tenant key.
* `current_user` compared only to a literal — `current_user =
  'postgres'`. That checks for one specific role (a superuser /
  admin escape); there is no column operand at all.
* `current_user` compared to a column of *another* table — a
  catalog lookup like `EXISTS (SELECT 1 FROM pg_roles WHERE
  rolname = current_user AND rolsuper)`. `pg_roles.rolname` is a
  catalog column, not a tenant key; restricting the column operand
  to the policy's own table excludes this family. (One imprecision:
  own-table membership is resolved by column *name*, so an
  unqualified sub-select column that collides with an own-table
  column name is still flagged — the same bare-name imprecision
  SEC005 carries. Qualify the sub-select column, or allowlist.)

The correct discriminator for pooled application code is a
*session-scoped* value the application sets per request: a GUC
read with `current_setting('app.tenant_id')`, or a JWT claim.
Those vary per request over a shared connection; the role identity
does not.

`current_user`-based policies are **not** universally wrong. The
"role-per-tenant" RLS pattern — one Postgres role per tenant, the
application `SET ROLE`s to the tenant's role per request — is a
legitimate, documented design, and there `current_user` is exactly
the right discriminator. pgrls cannot tell which deployment model
is in use, so SEC018 is a `warning`: a role-per-tenant project
allowlists the affected policies (by qualified policy ID
`schema.table.policy_name`) after confirming the model.

```toml
[lint.rules.SEC018]
allowlist = [
    # role-per-tenant deployment — current_user IS the tenant key.
    "public.documents.owner_is_current_user",
]
```

Relationship to SEC004: SEC004 catches the *inverted* auth check
(`current_setting(...) IS NULL OR …`) — a predicate that fails
open. SEC018 catches a predicate that matches row data against the
wrong identity. Both are policy-expression rules, but SEC004 is an
error (always wrong) while SEC018 is a warning (wrong only under a
shared pool role).

<a id="rule-sec019"></a>

## SEC019 — Policy calls current_setting() without the missing_ok argument

**Severity:** info.

`current_setting(name)` — the one-argument form — raises
`ERROR: unrecognized configuration parameter "name"` when `name` is
a GUC that has never been set in the session.
`current_setting(name, missing_ok)` — the two-argument form —
returns NULL instead when `missing_ok` is true.

RLS policies routinely read the tenant/session context from a
custom GUC the application sets per request:

```sql
CREATE POLICY p ON documents
    USING (tenant_id = current_setting('app.tenant_id'));
```

With the one-argument form, a request that reaches the database
*without* having run `SET app.tenant_id = …` does not get a quiet,
empty result — the policy expression itself raises, so **every**
query against the table errors until the GUC is set. The two-arg
form `current_setting('app.tenant_id', true)` instead yields NULL;
in the typical `column = current_setting(...)` predicate that NULL
makes the comparison match no rows — the query succeeds and returns
nothing.

Which behaviour is better is a genuine judgement call — a loud
error surfaces the missing-context bug immediately, a quiet empty
result is friendlier but can mask it. SEC019 does not assert one is
wrong. It is **info**-level: it surfaces the one-argument form so
the choice between "raise" and "return NULL on an unset GUC" is
deliberate rather than an accident of which overload the author
reached for. (The two-arg form is also what a typical policy set
converges on, so a lone one-arg call is often just an oversight.)

SEC019 fires when a policy's `USING` or `WITH CHECK` expression
contains a `current_setting` call with exactly one argument —
anywhere in the tree, including inside a `(SELECT current_setting
(...))` wrapper. It does not inspect the GUC name. Allowlist by
qualified policy ID when the raise-on-unset behaviour is the
intended, documented choice.

Relationship to SEC004: SEC004 catches the genuinely dangerous
`current_setting(...) IS NULL OR …` shape — a *fail-open* predicate
that admits every row when the GUC is unset — and is an error.
SEC019 is unrelated to fail-open: the one-arg form fails *closed*
(it raises). SEC019 only nudges toward the more robust overload; it
is info, not a security finding. A policy can trip both rules
independently.

<a id="rule-sec020"></a>

## SEC020 — Policy WITH CHECK clause is constant true but USING is not

**Severity:** warning.

A policy that governs writes — a `FOR ALL` or `FOR UPDATE` policy —
carries two predicates. `USING` filters the rows the caller may
*see* (and, for UPDATE, the existing rows it may target).
`WITH CHECK` validates the rows the caller may *write* — the new
row an INSERT produces, or the post-image of an UPDATE. When
`WITH CHECK` is omitted Postgres reuses `USING` for it, so the two
sides stay in lock-step by default.

The footgun is an explicit `WITH CHECK (true)` paired with a
restrictive `USING`:

```sql
CREATE POLICY p ON documents
    FOR ALL TO app
    USING (tenant_id = current_setting('app.tenant_id')::int)
    WITH CHECK (true);
```

The caller can only *read* its own tenant's rows, but it may
*write* any row at all — it can INSERT a row stamped with another
tenant's id, or UPDATE one of its own rows to reassign it. The
read-side isolation looks airtight while the write side is wide
open.

SEC020 fires when a policy has both clauses present, its `USING`
clause is a real predicate, and its `WITH CHECK` clause is the
literal `true`. The fix is almost always to mirror the `USING`
predicate into `WITH CHECK` — or to drop the `WITH CHECK` clause,
which makes Postgres reuse `USING` automatically. Allowlist by
qualified policy ID when an intentionally open write side is the
design.

Scope: detection matches the literal `true` only, exactly as SEC008
("USING clause is constant true") does — `1 = 1` and other semantic
tautologies are out of scope. A policy with no `WITH CHECK` at all
is SEC006's concern (write-side policy missing WITH CHECK), not
SEC020's; a `USING` that is itself constant-true is SEC008's.
SEC020 does not attempt to prove a non-trivial `WITH CHECK` is
weaker than `USING` — only the unambiguous constant-true case.

<a id="rule-sec021"></a>

## SEC021 — Policy compares an identity column against a hardcoded literal

**Severity:** info. **Auto-fix:** no (keying the policy off session
context needs the application's tenant-key name — an architectural
decision, not a mechanical rewrite).

A row-level security policy isolates tenants by keying row
visibility off a *per-request* value the application sets on every
connection — `current_setting('app.tenant_id')`, a JWT claim.
SEC021 flags a policy that instead compares the identity column
against a **literal constant**:

```sql
CREATE POLICY p ON documents
    USING (tenant_id = 1);
```

A literal pins the policy to one specific tenant: every session —
tenant A, tenant B, an anonymous request — is handed the same fixed
slice of rows, so the policy does no per-tenant scoping at all. It
is almost always a scaffolding value (`tenant_id = 1` against a
seed tenant during development) that was never swapped for the real
session lookup.

Detection is a **name heuristic**. SEC021 walks the parsed policy
AST for a plain `=` comparison where one operand is a column whose
name is in a configurable identity-column set — `tenant_id`,
`org_id`, `account_id`, `user_id`, `owner`, … — and the other
operand is a literal (`A_Const`, optionally cast: `'…'::uuid`). The
literal is the signal; the identity-ish column *name* separates the
anti-pattern from a legitimate `column = literal` policy such as
`USING (is_public = true)` or `USING (status = 'published')`, which
compare an *attribute* column to a constant on purpose.

Because the discriminator is a name heuristic, SEC021 is **info**
severity — a review nudge, not a hard finding. Override the column
set per project with `[lint.rules.SEC021].identity_columns` (the
configured list replaces the default set). Allowlist by qualified
policy ID when comparing the column to a fixed value is intentional
(a global table pinned to one tenant, an admin-only policy).

SEC021 is equality-only (`tenant_id IN (1, 2)` and `<>` are not
flagged) and does not require the column to be on the policy's own
table — a hardcoded identity comparison inside a sub-select is
worth surfacing too.

<a id="rule-sec022"></a>

## SEC022 — RLS-enabled table has no write-side policy

**Severity:** info. **Auto-fix:** no (the missing write policy's
predicate is an application decision — what may a caller INSERT,
UPDATE, or DELETE? — not a mechanical rewrite).

Postgres's RLS model is deny-by-default per command: a command is
permitted only if some policy's command list includes it. When a
table has RLS enabled and every policy is `FOR SELECT`, the write
commands have no policy at all, so for every non-owner role
`INSERT` raises `new row violates row-level security policy` and
`UPDATE` / `DELETE` silently match zero rows — no error, no
effect. That asymmetry (INSERT failing loudly, UPDATE / DELETE
failing silently) makes a forgotten write policy easy to miss in
development and painful to diagnose in production.

This is often a genuine mistake — the author wrote the read
policies and never added the write ones. But it is also a valid
intentional design: a table that is read-only for the
RLS-controlled roles, with writes performed by a privileged role
that owns the table or carries `BYPASSRLS`. pgrls cannot tell the
two apart, so SEC022 is **info** — a "did you mean this?" nudge.
Allowlist the table (bare name or `schema.table`) when the
read-only surface is intentional.

SEC022 fires only when the table also has a *permissive* policy.
A table whose policies are all restrictive denies reads too — the
permissive group is empty, so every row is filtered out and even
`SELECT` returns nothing. That is a different finding (SEC012's
"restrictive-only policy set"), and flagging it as a read-only
table would be redundant and mis-framed, so SEC022 stays quiet
and leaves it to SEC012. A single `FOR ALL` policy of any kind
counts as write coverage and silences the rule.

Out of scope (intentional): zero-policy tables (deny-by-default,
not read-only coverage), RLS-disabled tables (SEC001's surface),
and partition children (a child's writes route through the
partitioned parent, whose policies govern them).

<a id="rule-sec023"></a>

## SEC023 — Policy applies to a role that bypasses RLS

**Severity:** warning. **Auto-fix:** no (the remedy is either to
strip `BYPASSRLS` from the role or to drop the dead `TO` clause —
which one depends on the author's intent, which pgrls cannot
infer).

A `CREATE POLICY ... TO <role>` clause names the roles a policy
governs. SEC023 fires when one of those named roles carries the
`BYPASSRLS` attribute — because a `BYPASSRLS` role skips every
row-level security policy on every table. The `TO` clause is inert
for it:

```sql
CREATE ROLE etl_worker BYPASSRLS;

CREATE POLICY tenant_scope ON documents
    FOR SELECT TO etl_worker
    USING (tenant_id = current_setting('app.tenant_id'));
```

`etl_worker` reads every row of `documents` regardless of
`tenant_scope`'s predicate. The policy looks like it scopes that
role to one tenant; it does not constrain it at all.

The danger is a false sense of security. The author named the role
deliberately and wrote a predicate to scope it — nothing in the
policy reveals that the role ignores it, because the bypass lives
in a role attribute the policy never mentions. The milder reading
is that the author wanted the role unconstrained and the `TO`
clause is redundant noise; pgrls cannot tell the two apart, and
both are worth surfacing.

Detection is a cross-reference, not an AST walk: SEC023 intersects
each policy's `TO` list with the schema's set of `BYPASSRLS`
roles. The policy's `USING` / `WITH CHECK` predicate is irrelevant
— a `BYPASSRLS` role never evaluates it.

`TO PUBLIC` is not flagged: `PUBLIC` is the pseudo-role meaning
"every role", not a role that bypasses RLS, and firing on every
`TO PUBLIC` policy in any schema that contains a `BYPASSRLS` role
would be noise. SEC023 fires only when a policy *names* the
bypassing role outright. Superuser roles are skipped, mirroring
SEC016 — a policy targeting a superuser would restate a far
larger, separate finding.

Allowlist by qualified policy ID (`schema.table.policy_name`) when
naming a bypassing role in a `TO` clause is intentional.

Out of scope for SEC023 (by design): role-membership reachability —
a role whose members can `SET ROLE` to a bypassing role. `BYPASSRLS`
is a role attribute, not an inheritable privilege, so membership
grants no automatic bypass and SEC023's policy-level check stays
silent; the deliberate `SET ROLE` escalation path that *does* reach
it is covered separately by SEC029. Also out of scope: plain
superusers (a role that bypasses RLS only through `rolsuper`, with no
explicit `BYPASSRLS`, is not in the schema's `BYPASSRLS` set).

Relationship to SEC016: SEC016 flags the *role* ("this role
carries `BYPASSRLS`"); SEC023 flags the *policy* ("this policy
tries to govern a role the attribute exempts"). The two are
complementary — a schema can trip SEC016 once on the role and
SEC023 on every policy that names it.

<a id="rule-sec024"></a>

## SEC024 — Policy calls current_setting() with an unqualified parameter name

**Severity:** info. **Auto-fix:** no (the correct qualified
name — typically `app.<something>` — is application context
pgrls cannot know).

An RLS policy reads the per-request tenant/session context from a
*customized* run-time parameter the application `SET`s on every
connection. Postgres requires the name of such a parameter to be
**qualified** — `prefix.name`, containing a period — to
namespace it away from the server's own settings. An unqualified
name cannot be `SET` as a customized parameter at all, so a
policy that reads one either gets a built-in server setting or
silently gets nothing:

```sql
CREATE POLICY p ON documents
    USING (tenant_id = current_setting('tenant_id', true));
    --                                 ^^^^^^^^^^^ no prefix
```

This is almost always a dropped prefix — the application sets
`app.tenant_id` but the policy reads `tenant_id`. The failure is
quiet: with the two-argument form (`missing_ok = true`) the
unset parameter yields NULL, `tenant_id = NULL` matches no rows,
and the table simply looks empty. The one-argument form raises
on every query instead, which SEC019 separately flags.

Detection walks the parsed policy expression for
`current_setting` calls (including those inside `(SELECT
current_setting(...))`) and inspects the first argument. SEC024
fires when that argument is a string literal with no period.
Dynamic names — a column reference, a concatenation — are not
inspected. Postgres deparses a string-literal argument with an
explicit `::text` cast (`current_setting('app.x'::text, true)`),
so the introspected node is a `TypeCast` wrapping the `A_Const`;
SEC024 unwraps it before reading the literal.

Severity is **info** because a policy may genuinely key off a
built-in server parameter (e.g. `application_name`), which is
unqualified by definition. pgrls cannot tell a dropped prefix
from a deliberate built-in read, so SEC024 surfaces the
unqualified name as a review nudge rather than a hard finding.
Allowlist by qualified policy ID (`schema.table.policy_name`)
when the built-in read is intentional.

Relationship to SEC019: SEC019 flags the *arity* of a
`current_setting` call (the one-argument form raises on an
unset parameter); SEC024 flags the *name shape* (unqualified).
The two are orthogonal — a single policy can carry one without
the other, or trip both.

Out of scope (intentional):

* **Dynamic parameter names.** `current_setting(<non-literal>)`
  — a name built from a column or an expression — is not
  inspected. SEC024 reads string-literal arguments only.
* **Empty parameter names.** `current_setting('')` is a
  malformed call — Postgres errors at query time. That is a
  different class of bug from a dropped prefix; SEC024 flags an
  *unqualified* (real-but-prefix-less) name, not an absent one.
* **Parameter-value analysis.** SEC024 does not check whether a
  *qualified* name is one the application actually sets, nor
  what the value resolves to. It checks the *shape* of the name
  only.
* **`current_setting` outside policies.** A call in a view body,
  a function, or a column `DEFAULT` is not in scope — SEC024
  inspects policy `USING` / `WITH CHECK` clauses only.

<a id="rule-sec025"></a>

## SEC025 — Policy predicate references a table that has RLS disabled

**Severity:** warning. **Auto-fix:** no (the remedy is either to
enable RLS on the referenced table — an application-design
decision — or to drop the cross-table read; pgrls cannot infer
which is right).

A row-level security policy on table `T` often gates row
visibility on *another* table `T'` — typically a membership /
ACL / lookup table reached through a sub-select:

```sql
CREATE POLICY tenant_scope ON public.documents
    USING (
        tenant_id IN (
            SELECT tenant_id FROM public.team_members
            WHERE user_id = current_setting('app.user_id', true)::int
        )
    );
```

The row-level isolation on `documents` is only as strong as the
isolation on `team_members`. If `team_members` itself does **not**
have RLS enabled, every column of it is freely readable (and, if
the role has INSERT, freely writable) by the same role. An
attacker who can write to `team_members` can grant themselves
access to `documents` — the policy honours the row they planted.

Detection is structural cross-reference, not an AST pattern.
SEC025 walks the parsed policy `USING` / `WITH CHECK` for
`RangeVar` nodes (table references in sub-selects / `FROM`
clauses), resolves each against the introspected schema, and
fires when the referenced table is in scope and has
`rls_enabled = false`. The pattern is sometimes intentional —
a read-only reference table (countries, currencies, plan types,
feature flags) that every tenant is meant to read — so SEC025
is **warning** severity and allowlistable by qualified policy
ID (`schema.table.policy_name`).

What SEC025 flags — and what it deliberately does not:

* **Flagged:** a policy whose `USING` / `WITH CHECK` references
  — in a sub-select, a JOIN, anywhere `RangeVar` reaches — a
  table whose `rls_enabled` is false within the introspected
  schema set.
* **Not flagged — self-references.** A policy on `T` that
  references `T` itself in a sub-select inherits the same RLS
  gate (its own policies apply transitively), so self-references
  are skipped.
* **Not flagged — views.** Views do not carry an `rls_enabled`
  flag — their security model is `security_invoker` /
  `security_barrier`, which is VIEW001 / VIEW002's surface —
  so SEC025 stops at the table boundary rather than guess at a
  view's effective isolation.
* **Not flagged — out-of-scope references.** A reference to a
  table outside `--schemas` is not in the introspected set;
  pgrls cannot know its RLS state and would not have a reliable
  signal. The conservative call is silence — widen `--schemas`
  to include the dependent schema for SEC025 to see it. System
  catalogs (`pg_catalog.*`) are similarly skipped: they are
  never introspected.

Out of scope (intentional):

* **Predicate-implication analysis.** SEC025 does not try to
  prove the sub-select's `WHERE` clause already constrains `T'`
  to the same tenant. The structural reference is the signal;
  allowlist a policy whose cross-table read is intentionally
  safe.
* **Function references.** A policy that calls a `SECURITY
  DEFINER` function reading another RLS-off table is a separate
  surface (SEC014 / VIEW004). SEC025 inspects table references
  only.
* **Write-side enforcement.** SEC025 does not gate against an
  attacker writing to `T'`; it surfaces the structural
  dependency so the operator can decide whether `T'` needs RLS
  too, or whether writes to `T'` are locked down via `GRANT` /
  a separate workflow.

<a id="rule-sec026"></a>

## SEC026 — Policy uses LIKE / regex pattern matching against an auth context

**Severity:** warning.

A policy whose `USING` or `WITH CHECK` expression compares a value
against an **auth-context function** (`current_setting`, `auth.uid`,
`current_user`, ...) using a **pattern-matching operator** — `LIKE`,
`ILIKE`, `SIMILAR TO`, or a POSIX regex operator (`~`, `~*`, `!~`,
`!~*`) — makes the predicate's tightness depend on the *shape* of
the auth-context value rather than on its identity. A GUC set to
`%` (the empty `LIKE` pattern) or `.*` (regex match-everything)
matches every row, defeating the per-row isolation entirely.

```sql
CREATE POLICY p ON documents
    USING (user_email ILIKE current_setting('app.email'));
```

The author wanted case-insensitive email matching. But `ILIKE`
interprets `%` and `_` as wildcards. If the application ever sets
`app.email` to `%`, every row matches. The same hole opens with
POSIX regex (`user_email ~ current_setting('app.pattern')`) where
`.*` is the all-matching pattern.

**Detection** matches by *operator name* rather than `A_Expr.kind`,
so a literal `LIKE` source (`AEXPR_LIKE` with name `~~`) and a
deparsed policy from `pg_get_expr` (`AEXPR_OP` with the same `~~`
name) trip the rule the same way — pgrls introspects via
`pg_get_expr`, so name-based detection is the round-trip-stable
path. The full operator-name set is `~~`, `~~*`, `!~~`, `!~~*`,
`~`, `~*`, `!~`, `!~*`. SIMILAR TO emits as `AEXPR_SIMILAR` with
operator name `~`, identical to POSIX regex `~`; SEC026 treats them
the same.

**Auth function set.** Default mirrors PERF001's
(`auth.uid`, `auth.role`, `auth.jwt`, `current_setting`) plus the
role-identity grammar-specials (`current_user`, `current_role`,
`user`, `session_user`). Replace with a custom helper:

```toml
[lint.rules.SEC026]
auth_functions = ["auth.uid", "current_setting", "my.current_user_id"]
```

The list *replaces* the default — name every function you want
covered, including the stock ones if you still use them.

**Both operand directions fire.** `col LIKE current_setting(...)`
and `current_setting(...) LIKE col` are the same vulnerability;
whichever side carries the auth value, that side's *shape* now
drives the predicate.

**SubLink-wrapped auth values still fire.** `col LIKE (SELECT
current_setting('app.email', true))` is semantically identical to
the un-wrapped form — Postgres evaluates the scalar SubLink to a
value and feeds it to `LIKE` — so SEC026 inspects operand subtrees
including SubLink contents. The same outer walk reaches A_Expr
nodes inside a sub-select on its own (e.g. `EXISTS (SELECT 1 FROM
members WHERE m.email LIKE current_setting(...))` fires on the
inner LIKE); each policy is reported once, no double-firing.

**Allowlist by qualified policy ID** when the pattern semantics are
deliberate (an intentional wildcard query that runs only via a
specific allowlisted route):

```toml
[lint.rules.SEC026]
allowlist = ["public.deliberate_pattern_table.policy_name"]
```

**Remedy.** Switch to `=` (exact match) or normalize both sides
before comparing — `lower(email) = lower(current_setting('app.email'))`
for case-insensitive equality, not `ILIKE`. The pattern wildcards
have no place in an isolation predicate.

**No auto-fix.** Picking the right exact-match shape (case-sensitive
`=`, `lower()`-wrapped, or a different scoping column entirely) is
a design choice, not a mechanical rewrite.

**Out of scope (intentional):**

* **Pattern operator without an auth context.**
  `email LIKE '%@example.com'` is hard-coded — the predicate
  isolates by a fixed pattern, not by an attacker-controllable
  value.
* **Auth context with non-pattern operator.**
  `tenant_id = current_setting('app.tenant_id')::uuid` is a plain
  `=`; the auth value is interpreted as a UUID, not a pattern.

<a id="rule-sec027"></a>

## SEC027 — RLS table has a principal column no policy scopes by

**Severity:** info.

Row-Level Security isn't only about tenant isolation. Within a
single tenant, rows are still often *per-user*: a user's drafts,
private uploads, direct messages, personal settings. The
discriminator there is an owner / user column, not `tenant_id`.

SEC027 is the under-scoping nudge for that case. It fires when a
table has RLS enabled, carries at least one policy, has a column
whose name looks like a principal identity (`owner`, `owner_id`,
`user_id` by default), and **no policy references that column** in
its `USING` or `WITH CHECK`.

```sql
CREATE TABLE documents (id uuid, tenant_id int, owner_id uuid, body text);
ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON documents
    USING (tenant_id = current_setting('app.tenant')::int);
```

The policy scopes by tenant, so cross-tenant reads are blocked —
but every user *within* a tenant can read every other user's rows,
because nothing keys on `owner_id`. If `documents` holds
per-user-private data, that's a leak; if it's a tenant-shared table
(a catalogue, a settings table where `owner_id` is just audit
provenance), it's intentional and you allowlist it.

pgrls cannot read that intent, so SEC027 is **info** severity — it
never fails CI by default. It's a "did you mean to scope this by
user too?" prompt, deliberately conservative:

* **Only flags tables that already have a policy.** A table with
  RLS on and *no* policy is SEC009's silent-deny-all surface, not
  this rule's.
* **Treats a column as scoped if any policy references it
  anywhere**, including inside a sub-select. This under-fires
  rather than over-fires: a membership-table join
  (`owner_id IN (SELECT … )`) counts as scoping, so the rule stays
  quiet on the legitimate ACL pattern, at the cost of missing a
  case where the sub-select's column merely shares the name.
* **Default principal set is narrow** (`owner`, `owner_id`,
  `user_id`). Audit-style columns (`created_by`, `updated_by`,
  `author_id`) are deliberately NOT in the default set — they're
  usually provenance, not access boundaries.

Configure the principal-column set (replaces the default):

```toml
[lint.rules.SEC027]
principal_columns = ["owner_id", "user_id", "created_by"]
```

Allowlist tables that are intentionally tenant-shared (by bare
name or `schema.table`):

```toml
[lint.rules.SEC027]
allowlist = ["public.catalogue", "tenant_settings"]
```

**No auto-fix.** The remedy — add a per-user predicate, or confirm
the table is tenant-shared and allowlist it — is an intent decision
pgrls can't make.

Relationship to other rules: SEC005 ("no own-column reference")
fires when a policy references *no* column of its table at all;
SEC027 fires when the policy references *some* columns but not the
principal one. A tenant-only table with no owner/user column never
trips SEC027 (there's nothing to under-scope).

<a id="rule-sec028"></a>

## SEC028 — Write-side policy WITH CHECK is constant true (open write)

**Severity:** warning.

A **permissive** policy that governs writes — `FOR INSERT`,
`FOR UPDATE`, or `FOR ALL` — with a `WITH CHECK` clause of literal
`true` accepts every write the command covers. Any row the caller
submits passes the check; the `TO` clause limits *who* may write,
never *what*:

```sql
CREATE POLICY ins ON documents
    FOR INSERT TO authenticated
    WITH CHECK (true);   -- any authenticated row, any tenant, any owner
```

This is the open-write gap the other write-side rules miss:

* **SEC006** fires when `WITH CHECK` is *absent*; here it's present
  and wide open.
* **SEC008** flags a constant-true `USING`; a `FOR INSERT` policy
  has no `USING`, and SEC008 never inspects the write side.
* **SEC020** flags the *asymmetry* `WITH CHECK (true)` alongside a
  real restrictive `USING` ("reads scoped, writes open"). SEC028 is
  the complement — there's no restrictive `USING` to contrast with
  (it's absent on `FOR INSERT`, or itself constant-true), so the
  write side is open outright.

SEC028 fires when a permissive policy whose command is `INSERT`,
`UPDATE`, or `ALL` has `WITH CHECK` = literal `true` and its `USING`
is absent or itself constant-true (the asymmetry case is ceded to
SEC020). Restrictive policies are out of scope: a restrictive
`WITH CHECK (true)` is a dead clause (restrictive policies
AND-combine, so it opens nothing on its own), SEC006's restrictive
framing rather than an open-write hole.

The fix is to replace `WITH CHECK (true)` with a predicate that
validates the written row — usually the same tenant / ownership key
the read side uses. Allowlist by qualified policy ID when an open
write side is the design (an append-only audit or event table any
client may write but only an admin policy reads).

**No auto-fix** — the correct write predicate is the application's
tenant / ownership key, which pgrls can't infer.

<a id="rule-sec029"></a>

## SEC029 — Role can SET ROLE to a BYPASSRLS role (RLS-bypass path)

**Severity:** warning.

`BYPASSRLS` is a role *attribute*, and role attributes — unlike
object privileges — are **never inherited** through membership, even
with `INHERIT`. So being a member of a BYPASSRLS-carrying role does
not make you bypass RLS automatically: SEC016 (which flags roles that
hold BYPASSRLS *directly*) stays silent, and the member's own
`pg_roles` row looks clean.

But membership grants `SET ROLE`. A role that is a member — directly
or transitively — of a BYPASSRLS role can switch into it and, from
that point in the session, bypass every policy on every table:

```sql
CREATE ROLE admin BYPASSRLS NOLOGIN;
CREATE ROLE app LOGIN;
GRANT admin TO app;        -- app can `SET ROLE admin`, then bypass RLS
```

`app` has no BYPASSRLS of its own, yet a single `SET ROLE admin`
turns RLS off for the rest of the session. SEC029 surfaces that
route, naming the reachable BYPASSRLS role(s), so the membership gets
an explicit audit decision. When the member is a `LOGIN` role the
finding flags it: an application authenticating as it is one
`SET ROLE` from a full bypass.

SEC029 fires for each role that reaches a BYPASSRLS role through the
transitive `pg_auth_members` closure, does not itself hold BYPASSRLS
(SEC016's surface), and is not a superuser (superusers bypass
unconditionally). It complements the other BYPASSRLS rules: SEC016
flags the *holder* of the attribute, SEC023 flags a policy whose `TO`
role holds it (an inert `TO` clause), and SEC029 flags the *path* a
member can take to reach it.

Detection treats every membership edge as `SET ROLE`-capable. On
PostgreSQL 16+ a grant `WITH SET FALSE` does not permit `SET ROLE`,
so SEC029 can over-report there — a deliberate bias toward surfacing
a potential bypass route (allowlist a false positive) over missing
one, and it keeps the introspection query identical across PG15-17.

Allowlist the *member* role by name (roles are unqualified, as in
SEC016's allowlist) when the membership is intentional and the member
is trusted to bypass — for example an operator login expected to be
able to escalate.

**No auto-fix** — whether to revoke the membership, narrow what the
BYPASSRLS role grants, or accept the route is an operational decision
pgrls can't make.

<a id="rule-sec030"></a>

## SEC030 — Policy scopes by a nullable discriminator column

**Severity:** info.

A row-scoping policy keys visibility off a column compared to a
per-request auth value — the tenant or user discriminator. If that
column is **nullable**, two things go wrong:

```sql
CREATE TABLE documents (id uuid, tenant_id int, body text);   -- nullable!
ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON documents
    USING (tenant_id = current_setting('app.tenant')::int);
```

1. **Silent row-hiding (today).** Under plain `=`, a row whose
   `tenant_id` is `NULL` evaluates `NULL = <setting>` → `NULL`, which
   RLS treats as *not* matching. The row is invisible to every
   tenant — not leaked, but unreachable. A row that should belong to
   someone belongs to no one.
2. **Latent cross-tenant leak (one edit away).** The moment any
   policy uses a NULL-tolerant form of the same key — `tenant_id IS
   NOT DISTINCT FROM <setting>`, `tenant_id = <setting> OR tenant_id
   IS NULL`, `COALESCE(tenant_id, <setting>) = <setting>` — every
   `NULL` row becomes visible to **every** tenant at once. A `NOT
   NULL` discriminator makes that whole failure mode unreachable.

SEC030 fires when a table has RLS enabled, a policy, captured column
nullability, and a **nullable** column that some policy compares with
a plain `=` against an auth-context value (`current_setting`,
`auth.uid`, `auth.role`, `auth.jwt` by default). The remedy is
usually `ALTER TABLE … ALTER COLUMN … SET NOT NULL` (after
backfilling any existing `NULL`s), plus a `DEFAULT` or trigger so the
column is always populated.

pgrls can't know whether the `NULL`s are intentional, so SEC030 is
**info** severity — it never fails CI by default. It is the
nullable-discriminator companion to two warning-level neighbours:
**SEC018** flags the wrong *type* of discriminator (a column compared
to `current_user` / `session_user`, constant under a shared pool);
SEC030 assumes the right type (a session-GUC / JWT value) and flags
it being nullable. **SEC027** flags a principal column *no* policy
scopes by; SEC030 flags a column a policy *does* scope by, but that
is nullable. The three are disjoint.

Detection is structural and conservative:

* **Scalar equality only.** Only a plain binary `col = <auth value>`
  (`A_Expr` kind `AEXPR_OP`) counts. `col <> …`, `col > …`
  (`created_at > current_setting('app.cutoff')` is a legitimate
  non-tenant use of `current_setting`), and array-membership
  `<auth value> = ANY(tags)` (a different access model) are all out
  of scope.
* **Column is a direct operand; the auth value may be wrapped in a
  fromless sub-select.** The discriminator must be a direct operand
  of the `=`, but the auth value is detected even inside a scalar
  sub-select with no `FROM` clause — `tenant_id = (SELECT
  current_setting('app.tenant'))` fires. That wrapped form is the one
  PERF001 *recommends* (evaluated once per statement), so missing it
  would blind the rule to the best-written policies. A sub-select
  *with* a `FROM` clause is a lookup whose internal predicates are
  not the compared value, so `id = (SELECT x FROM acl WHERE m =
  current_setting(…))` does not fire on `id`.
* **Own-table columns only.** The column operand must belong to the
  policy's own table (the same resolution SEC005 / SEC018 use), so a
  sub-select join column or catalog lookup is not mistaken for the
  discriminator.
* **Needs captured nullability.** A table whose `column_details`
  weren't captured (a hand-built fixture, or a pre-v5 snapshot) is
  skipped — nullability is unknowable, so the rule stays silent until
  the schema is re-introspected.

Configure the auth-context function set (replaces the default) via
`[lint.rules.SEC030].auth_functions`. Allowlist tables where a
nullable discriminator is intentional — a public-or-tenant table
whose public rows legitimately have a `NULL` tenant, say — by table
name (bare or `schema.table`) in `[lint.rules.SEC030].allowlist`.

**Auto-fix.** `pgrls fix` emits `ALTER TABLE <schema>.<table> ALTER
COLUMN <column> SET NOT NULL` — one statement per flagged column.
**Caveat:** the ALTER scans the column and fails with `ERROR: column
contains null values` if any row is already `NULL`. Because `pgrls
fix --apply` runs every emitted Fix in a single all-or-nothing
transaction, that failure rolls back the **entire batch** (every
SEC001 / SEC002 / etc. Fix alongside is undone). pgrls cannot infer
the right tenant-id / sentinel to backfill with, so the Fix
description prompts you to backfill existing `NULL`s first (an
`UPDATE … SET <column> = <value> WHERE <column> IS NULL`), or to use
`pgrls fix --output FILE` to materialize the SQL and run the backfill
and the ALTER separately. The complementary remedy — a `DEFAULT` or
trigger so the column stays populated — is operator-specific and not
auto-emitted; allowlist the table if the `NULL`s are an intentional
sentinel.

<a id="rule-sec031"></a>

## SEC031 — Restrictive policy USING clause is constant true

**Severity:** warning.

A `RESTRICTIVE` policy is meant to be a *hard floor*: a row is visible
only if it passes **every** restrictive policy (they AND-combine) on
top of passing at least one permissive policy. It is how you add a
tenant boundary no permissive `OR` branch can widen.

A restrictive policy whose `USING` is the literal `true` adds
`AND true` to that conjunction — which restricts **nothing**:

```sql
CREATE POLICY tenant_floor ON documents
    AS RESTRICTIVE FOR SELECT TO PUBLIC
    USING (true);          -- looks like a floor, enforces nothing
```

The policy is inert: every row a permissive policy admits sails
through. The danger is the *false sense of security* — a reviewer
sees a restrictive policy named `tenant_floor` and assumes a hard
boundary the table doesn't have.

SEC031 is the restrictive counterpart of **SEC008**, which flags a
**permissive** `USING (true)`. There the constant-true *admits* every
row (permissive policies OR-combine); here it *fails to restrict* — the
opposite failure, so "admits every row" would mislead. The two are
disjoint by policy kind: SEC008 handles permissive, SEC031
restrictive, and a given policy trips at most one. The constant-true
`WITH CHECK` space is SEC020's (asymmetric write) and SEC028's (open
write) territory.

Detection mirrors SEC008: only the literal `true` matches (a real
tautology checker — `1 = 1`, `x OR NOT x` — is out of scope; those
surface as SEC005, no own-column reference). A restrictive policy with
a real `USING` and a `WITH CHECK (true)` is not flagged here — a
restrictive `WITH CHECK (true)` is a dead clause (SEC006's framing),
not a missing read floor.

The fix is to give the restrictive policy the real predicate it was
meant to enforce — the tenant / ownership key — or to drop it if it
was never needed. Allowlist by qualified policy ID when a
constant-true restrictive policy is deliberate scaffolding.

**Auto-fix.** `pgrls fix` emits `DROP POLICY` for the no-op floor: its
`USING (true)` AND-combines to nothing, so dropping it leaves access
unchanged (the same reasoning that makes HYG003's drop safe). The
fixer drops only *genuinely inert* policies: it abstains when the
policy also carries a real `WITH CHECK`, because a restrictive `WITH
CHECK` is a load-bearing write floor (it AND-combines for writes) and
dropping it WOULD change write access — that case is left for human
review. The *other* remedy — giving the read floor the real tenant /
ownership predicate — needs human intent and is not auto-fixed either.

<a id="rule-sec032"></a>

## SEC032 — Table has policies but RLS is not enabled

**Severity:** error.

Postgres stores `CREATE POLICY` rows in `pg_policy` independently of
whether the table has RLS turned on. A policy only takes effect once
the table is switched on with `ALTER TABLE ... ENABLE ROW LEVEL
SECURITY`. Until then the policies are **dormant** — they sit in the
catalog enforcing nothing, and the table is readable by every role
that holds the table-level privilege:

```sql
CREATE TABLE documents (id uuid, tenant_id int, body text);
CREATE POLICY tenant_isolation ON documents
    USING (tenant_id = current_setting('app.tenant')::int);
-- ⚠ no ENABLE ROW LEVEL SECURITY → the policy is inert, table wide open
```

This is a high-confidence footgun. A table with RLS simply *off* and
no policies might be intentional (public reference data — SEC001's
allowlist case). But a table that carries hand-written policies
**clearly intends** RLS; the missing `ENABLE` is almost certainly a
forgotten step, and the result is a table that *looks* RLS-managed in
code review while enforcing nothing.

SEC032 is the policy-bearing complement of **SEC001** (RLS off with no
policies). SEC001 cedes any table that has policies to SEC032, so the
two are disjoint and a table trips exactly one — each with the message
that fits. Like SEC001 it skips a partition child whose ancestor chain
already has RLS enabled (the child is covered for parent-routed
queries upstream, so its own dormant policies are dead weight, not a
hole).

The fix is `ALTER TABLE ... ENABLE ROW LEVEL SECURITY` (add `FORCE` if
owner access must also be governed), or dropping the policies if RLS
was never intended. Allowlist by table name (bare or `schema.table`)
when an RLS-off-with-policies table is deliberate.

**Auto-fix.** `pgrls fix` emits `ALTER TABLE <schema>.<table> ENABLE
ROW LEVEL SECURITY` for each flagged table — the same DDL SEC001's
fixer emits, the difference being that SEC032's tables already carry
policies, so enabling RLS activates them immediately (the Fix
description notes the policies go live and to re-`lint` afterward).
`FORCE` is **not** toggled — governing owner access is a separate
intent that SEC002's fixer carries (run `pgrls fix --rule SEC002`
next if owner access must also be governed). The fixer mirrors the
rule's scoping: a partition child whose ancestor chain already has
RLS enabled is skipped (it's covered for parent-routed queries
upstream). The other remedy — dropping the policies if RLS was never
intended — needs human intent and is not auto-emitted.

<a id="rule-sec033"></a>

## SEC033 — Policy scopes by user-modifiable JWT claim (`user_metadata`)

**Severity:** error.

**The vulnerability:** In the Supabase / PostgREST auth model,
`raw_user_meta_data` (a.k.a. the `user_metadata` JWT claim) is
**end-user writable** via the standard auth API:

```js
supabase.auth.updateUser({ data: { role: "admin" } })
```

The next JWT carries the user-supplied value, so any RLS policy
gating access on that field can be bypassed by the authenticated user
themselves — they set the field, the next request carries it, the
policy reads it, the check passes. This is the same hazard class as
SEC004 (anonymous access via inverted auth check): a deterministic,
single-step exploit available to any authenticated user.

The safe counterpart is **`raw_app_meta_data`** (a.k.a.
`app_metadata`), which is writable only via the service role.
`app_metadata`-scoped policies are not flagged.

**The bad pattern:**

```sql
CREATE POLICY admins_only ON public.documents
    FOR ALL TO authenticated
    USING (auth.jwt() -> 'user_metadata' ->> 'role' = 'admin');
    --                  ^^^^^^^^^^^^^^^
    -- User can set this themselves; check is self-bypassable.
```

The same shape with any JSON operator (`->`, `->>`, `#>`, `#>>`)
trips the rule, and so does a direct column reference to
`raw_user_meta_data` (typically via a `SELECT ... FROM auth.users`
sub-link).

**Standard fix.** Move the role gate into the admin-only claim:

```sql
CREATE POLICY admins_only ON public.documents
    FOR ALL TO authenticated
    USING (auth.jwt() -> 'app_metadata' ->> 'role' = 'admin');
```

Then set the claim via the service role (a server-only backend, an
admin dashboard's elevated session, or a custom auth hook) — the
end user can't write it through the client SDK.

**Configuring the key set.** Default:

```toml
[lint.rules.SEC033]
string_keys = ["user_metadata"]
column_names = ["raw_user_meta_data"]
```

`string_keys` replaces the default JSON-key match list (case-
sensitive — Postgres jsonb keys are case-sensitive). `column_names`
replaces the default column-name match list (case-insensitive —
Postgres lowercases unquoted identifiers). Both are list-replace, not
list-merge: include all the names you want flagged.

**Allowlist by `schema.table.policy`** when a policy intentionally
reads `user_metadata` for a non-authorization side-effect (logging,
display, etc.):

```toml
[lint.rules.SEC033]
allowlist = ["public.audit_log.write_metadata_snapshot"]
```

**No auto-fix** — replacing `user_metadata` with `app_metadata`
changes which claim the application writes too, not just which
claim the policy reads. That's an application-side migration that
pgrls can't make safely.

<a id="rule-sec034"></a>

## SEC034 — Policy gates on `auth.email()` (silent denial / lockout)

**Severity:** warning.

**The hazard.** A policy that scopes rows by email — typically:

```sql
USING (owner_email = auth.email())
```

— ships with three silent failure modes. None are exploits;
combined they are silent denial-of-service to legitimate users.

1. **Email change flow.** Supabase auth supports user-initiated
   email change. The new email lands in the JWT after verification;
   rows that were owned by the old email are now invisible to
   the user who owns them. Repair requires a manual UPDATE on
   every email-keyed table.
2. **Case sensitivity.** SQL `=` is case-sensitive; conventional
   email handling is case-insensitive for the local part on most
   mail providers and case-insensitive for the domain part per
   RFC. `User@Example.com` (stored) vs `user@example.com` (JWT)
   never matches — silent deny.
3. **Plus-addressing / aliasing.** `user+tag@gmail.com` and
   `user@gmail.com` reach the same inbox but compare unequal.
   Combined with apps that normalize one but not the other, rows
   become orphaned from the user who created them.

Hazard class differs from SEC033 / SEC036 (CVE-class privilege
escalation): this one is silent denial. Hence `warning` instead of
`error`, and a `--fail-on=warning` default still gates CI on it
while letting `--fail-on=error` continue.

**Standard fix.** Scope by `auth.uid()` (immutable per user, no
case folding, no aliasing) and treat email as a display field. If
the policy needs an email lookup (for example, "the row's
`owner_email` must match the calling user's email"), derive it
from `auth.users` via `auth.uid()` rather than calling
`auth.email()` directly:

```sql
USING (owner_id = auth.uid())
```

Or, when the table genuinely needs an email-typed FK:

```sql
USING (owner_email = (
    SELECT email FROM auth.users WHERE id = auth.uid()
))
```

(The latter form trips SEC036's `EXISTS`-against-`auth.users`
detection's adjacent class, but with `id = auth.uid()` binding
the sub-select it stays silent — and the lockout-on-email-change
hazard is now resolved in the application's email-update handler
rather than every downstream policy.)

**Detection.** Walks policy USING / WITH CHECK ASTs for FuncCall
nodes whose qualified name matches any of the configured email-
context functions (default: `auth.email`). One finding per policy
regardless of how many `auth.email()` references it contains —
the recommended fix is the same.

**Configuration.** `[lint.rules.SEC034]` accepts:

```toml
[lint.rules.SEC034]
# Function names whose call counts as an email-based-authz signal.
# Replaces the default `["auth.email"]`. Add project-specific
# helpers (e.g. an internal `app.user_email()`).
email_functions = ["auth.email", "app.user_email"]

# Per-policy escape hatch — `schema.table.policy_name` IDs that
# legitimately reference email for audit logging or display.
allowlist = ["public.audit_log.write_email_snapshot"]
```

**No auto-fix.** Rewriting `owner_email = auth.email()` to
`owner_id = auth.uid()` changes the column the policy keys on —
that's an application-side migration (the schema may not have an
`owner_id` column; if it does, every INSERT needs to be checked
to make sure both columns stay populated during the migration
window).

<a id="rule-sec035"></a>

## SEC035 — UNIQUE constraint not scoped to the tenant discriminator

**Severity:** warning.

A multi-tenant table whose rows are isolated by a discriminator
(`tenant_id = current_setting('app.tenant')`, `user_id = auth.uid()`)
must scope its UNIQUE constraints by that same column. A *global*
unique — `UNIQUE (email)` instead of `UNIQUE (tenant_id, email)` — has
two failure modes RLS does not prevent:

1. **Cross-tenant existence leak.** RLS hides other tenants' rows from
   `SELECT`, but a unique index is enforced across *all* rows.
   Inserting `email = 'a@b.com'` when another (invisible) tenant
   already holds it raises `duplicate key value violates unique
   constraint` — telling the caller a value is taken in a tenant they
   can't see. An enumeration oracle across the isolation boundary.
2. **Functional false-conflict.** Two tenants legitimately cannot both
   use the same email/slug/username, even though each owns its own
   namespace.

The fix is a composite unique that includes the discriminator:
`UNIQUE (tenant_id, email)`.

Detection is conservative — SEC035 flags a unique index only when the
table has RLS plus a policy that scopes a column by `=` against an
auth-context value (the discriminator; if none is found the tenancy is
unknown and the rule stays silent), the index is `UNIQUE` but **not**
the PRIMARY KEY (a surrogate PK is global by design), the index does
not include any discriminator column, and the index's columns are not
*all* `uuid` (a uuid is globally unique by construction and leaks
nothing enumerable). The discriminator search errs broad, so SEC035
under-flags rather than risk a false positive on a correctly-scoped
table.

Allowlist a table where a cluster-wide unique is intentional (a
deliberately global identifier):

```toml
[lint.rules.SEC035]
allowlist = ["public.api_tokens"]
```

No auto-fix — converting `UNIQUE (email)` to `UNIQUE (tenant_id,
email)` can fail if the existing data already holds a cross-tenant
duplicate, so the remedy needs a data audit pgrls can't perform.

<a id="rule-sec036"></a>

## SEC036 — Policy `EXISTS (SELECT FROM auth.users WHERE …)` clause has no caller binding

**Severity:** error.

**The vulnerability:** A common Supabase / PostgREST pattern is to
authorize via an `EXISTS` sub-select against `auth.users`:

```sql
-- correct (intended): "is the calling user an admin?"
CREATE POLICY admins_only ON public.documents
    FOR ALL TO authenticated
    USING (EXISTS (
        SELECT 1 FROM auth.users
        WHERE id = auth.uid()
          AND raw_app_meta_data ->> 'role' = 'admin'
    ));
```

Drop the `id = auth.uid()` clause and the policy silently degrades
to a **system-wide** check — "is there ANY admin in the system" —
that passes for every authenticated user as soon as a single admin
row exists in `auth.users`:

```sql
-- BAD: missing the caller-binding `id = auth.uid()`.
USING (EXISTS (
    SELECT 1 FROM auth.users
    WHERE raw_app_meta_data ->> 'role' = 'admin'
));
```

The SQL still parses; the test passes when an admin is present in
the test DB; the production exploit is silent. Same hazard class as
SEC033 (`user_metadata` bypass) and SEC004 (anonymous access via
inverted auth check) — deterministic, single-step, available to any
authenticated user.

**Detection.** Walks every `SubLink` node in policy USING / WITH
CHECK ASTs whose `subLinkType` is `EXISTS_SUBLINK`. For each, the
sub-select's `fromClause` is inspected for `RangeVar`s matching
the configured target tables (default: `auth.users`). When a
target matches, the sub-select's `whereClause` is searched for any
FuncCall whose name is in the configured binding-functions set —
absent any such reference, the rule fires. **One finding per
policy**, even when the policy has multiple offending sub-links.

**Standard fix.** Add the caller-binding clause to the sub-select's
WHERE:

```sql
USING (EXISTS (
    SELECT 1 FROM auth.users
    WHERE id = auth.uid()  -- <-- this line
      AND raw_app_meta_data ->> 'role' = 'admin'
));
```

The column name on the inner table is usually `id` for `auth.users`;
other user tables may use `user_id`, `sub`, etc.

**Configuration.** `[lint.rules.SEC036]` accepts:

```toml
[lint.rules.SEC036]
# `schema.table` references whose use in an EXISTS sub-select
# triggers the user-binding check. Replaces the default
# `["auth.users"]`. Schema-qualified — unqualified `users` would be
# search-path-dependent and isn't covered.
target_tables = ["auth.users", "public.profiles"]

# Function names whose presence in the sub-select's WHERE counts as
# a caller-binding signal. Replaces the default
# `{auth.uid, auth.role, auth.jwt, current_user, session_user,
# current_setting}`. Add any project-specific helper.
binding_functions = ["auth.uid", "current_setting", "app.user_id"]

# Per-policy escape hatch — `schema.table.policy_name` IDs that
# intentionally assert "any matching row exists" rather than
# "calling user matches" (rare, but legitimate for audit-trigger
# policies that don't gate by caller).
allowlist = ["public.audit_log.any_admin_exists"]
```

**No auto-fix.** The mechanical rewrite would be "add
`<user_key_column> = auth.uid() AND` to the WHERE clause", but
the user-key column name varies by schema (`id` on `auth.users`,
`user_id` / `sub` / `account_id` elsewhere), and prepending to an
arbitrary `BoolExpr` risks re-associating operator precedence. The
finding message tells the operator what to add; the edit is one
line.

**Scope note.** SEC036 covers `EXISTS (SELECT … FROM <users> WHERE …)`
specifically. The related `IN (SELECT id FROM auth.users WHERE …)` /
`ANY (SELECT id FROM auth.users WHERE …)` shape is a *different*
hazard — "show rows whose owner is any admin" rather than "show
every row if any admin exists." That variant is tracked as a future
rule; SEC036 stays silent on it.

<a id="rule-sec037"></a>

## SEC037 — Policy compares `auth.role()` to an unknown role name

**Severity:** warning.

**The hazard.** `auth.role()` in the Supabase / PostgREST auth
model returns one of a small fixed set — `anon`, `authenticated`,
or `service_role`. A policy that compares `auth.role()` to a
string outside that set silently denies every row, because the
equality never holds:

```sql
USING (auth.role() = 'admin')         -- never matches → policy denies
USING (auth.role() = 'authenticted')  -- typo, silent deny
USING (auth.role() = 'authorized')    -- wrong constant
```

The failure mode is a 100% empty result set — which masks the
broken policy because tests that seed admin data see no rows, devs
assume the policy works, the table becomes inaccessible in prod.

Severity is `warning`: not a CVE-class exploit (no data leak), but
a silent-deny footgun worth surfacing in CI.

**Standard fix.** The intent is usually a custom role check. Gate
on `app_metadata.role` instead — `app_metadata` is the
service-role-set, admin-only channel for project-specific role
attributes:

```sql
USING (auth.jwt() -> 'app_metadata' ->> 'role' = 'admin')
```

(Then promote users to admin server-side via the service role:
`auth.admin.updateUserById(id, { app_metadata: { role: 'admin' }})`.)

If you have an intentional override (e.g., a documented project
convention where `auth.role()` is redefined to return a wider set
of values), extend the known-roles list in config rather than
relying on default Supabase semantics.

**Detection.** Walks policy USING / WITH CHECK ASTs for `=`
comparisons where one side is `auth.role()` (or any configured
role-context function) and the other side is a string literal not
in the configured known-role set. Handles the
`'admin'::text` form that Postgres normalizes literals to when
storing policy expressions. Multiple comparisons in the same
policy with distinct literals yield one finding each (the fix for
each typo is usually different).

**Configuration.**

```toml
[lint.rules.SEC037]
# Role-name strings to consider valid. Replaces the default
# ["anon", "authenticated", "service_role"]. Case-sensitive
# (JWT claim values are not folded).
known_roles = ["anon", "authenticated", "service_role", "guest"]

# Function names whose call counts as an auth.role() reference.
# Replaces the default ["auth.role"]. Add current_user / session_user
# to extend the same silent-deny-typo check to the SQL keyword
# forms (a different rule, SEC018, covers current_user as a
# tenant key — orthogonal).
role_functions = ["auth.role"]

# Per-policy escape hatch
allowlist = ["public.legacy.admin_check"]
```

**No auto-fix.** The right replacement depends on application
intent — typo fix (`'authenticted'` → `'authenticated'`), shape
migration (`auth.role() = 'admin'` → `app_metadata` lookup), or
known-roles config extension. The finding message tells the
operator what to do; the choice isn't mechanical.

<a id="rule-sec038"></a>

## SEC038 — Semantic anonymous-read leak (Z3-backed)

**Severity:** error.

**The hazard.** A read-capable policy (FOR ALL or FOR SELECT)
leaks every row to anonymous if its USING predicate is provably,
unconditionally TRUE for an unauthenticated session — one where
every auth-context function (`auth.uid()` / `auth.role()` /
`auth.jwt()`, `current_user`, `session_user`, `current_setting()`)
returns NULL. Under SQL three-valued (Kleene) logic a row is
visible iff USING evaluates to exactly TRUE; NULL and FALSE both
hide the row.

SEC038 is the *semantic* sibling of [SEC004](#rule-sec004). SEC004
is purely syntactic — it flattens OR disjuncts and matches the
literal shape `auth_func() IS NULL`. SEC038 catches the
inverted-auth variants that shape misses:

```sql
USING (NOT (auth.uid() IS NOT NULL) OR owner_id = auth.uid())  -- NOT-wrapped
USING ((auth.uid() IS NULL)::bool   OR owner_id = auth.uid())  -- cast-wrapped
USING ((SELECT current_setting('app.user'))::uuid IS NULL OR …) -- coerced GUC
```

In each case, under an anonymous session the inverting disjunct is
TRUE for *every* row, so the policy reads all rows — the
Lovable-CVE catastrophic class, only obfuscated past the syntactic
matcher.

**Standard fix.** Gate on a non-null auth check and drop the
inverting disjunct:

```sql
USING (auth.uid() IS NOT NULL AND owner_id = auth.uid())
```

This is the semantic form of the SEC004 hole — see
[SEC004](#rule-sec004) for the syntactic variant and its fixer.

**Detection.** Translates the USING predicate into a Kleene
three-valued encoding (every auth function pinned to NULL) and asks
Z3 whether it is **valid** — TRUE for *every* row assignment, i.e.
`NOT(USING_anon is TRUE)` is unsatisfiable. Validity means
"anonymous unconditionally reads all rows". This is provably
zero-false-positive on safe policies:

* A tenant / owner predicate `col = (SELECT current_setting('app.x'))`
  becomes `col = NULL` under anon → Kleene U (not TRUE) → not valid
  → does **not** fire.
* A narrow / intentional public carve-out (`col = <constant> OR …`)
  is TRUE only for *some* rows → not valid → does **not** fire — no
  false positive on intentional public data.

Soundness over recall: any sub-expression the encoding cannot
translate makes the predicate's truth UNKNOWN, so validity cannot
be proven and SEC038 stays silent. A missed exotic leak is
acceptable (SEC004 still guards syntactically); a false positive is
not. Because validity means "TRUE for every row", the finding
reports an unconditional leak (all rows), not a single example row.

Only read-capable PERMISSIVE policies are inspected — RESTRICTIVE
policies can only narrow access, and INSERT/UPDATE/DELETE USING
clauses gate the rows touched, not rows exposed on SELECT.

SEC038 uses the Z3 SMT solver, a **core dependency since 0.16.0**, so it
runs on a plain `pip install pgrls`. In the unusual case where z3 can't be
imported the rule NO-OPs — it returns no findings rather than guessing.
(The [SEC004](#rule-sec004) syntactic guard runs regardless.)

**Configuration.**

```toml
[lint.rules.SEC038]
# Function names treated as anonymous-NULL under an unauthenticated
# session. Replaces the default ["auth.uid", "auth.role",
# "auth.jwt", "current_user", "session_user", "current_setting"].
# Mirrors SEC004's option so the two rules stay consistent.
auth_functions = ["auth.uid", "current_setting"]

# Per-policy escape hatch for intentional public-data tables.
allowlist = ["public.announcements.public_read"]
```

**No auto-fix.** The right replacement depends on intent — add a
non-null auth guard, remove the inverting disjunct, or (for genuine
public data) allowlist the policy. The choice isn't mechanical.

<a id="rule-sec039"></a>

## SEC039 — Permissive write policy grants the anonymous role write access

**Severity:** error.

**What it catches:** a PERMISSIVE policy for a write command — `INSERT`,
`UPDATE`, `DELETE`, or `ALL` — whose role list includes the unauthenticated
`anon` role. In Supabase / PostgREST the `anon` role serves requests carrying
no JWT, so such a policy lets an anonymous client modify rows, gated only by
that policy's clause.

```sql
-- Fires: anonymous clients can INSERT.
CREATE POLICY posts_insert ON public.posts
    FOR INSERT TO anon
    WITH CHECK (true);
```

**Why it's separate from [SEC003](#rule-sec003).** SEC003 flags the `PUBLIC`
*pseudo-role* (every connection) for any command. SEC039 covers the named
`anon` *role* — a real role SEC003's `PUBLIC` check never sees — and narrows
to *writes*: anonymous **read** (`FOR SELECT TO anon`) is a deliberate,
common public-data pattern and is intentionally not flagged. A `FOR ALL TO
PUBLIC` write is SEC003's job; a `FOR INSERT TO anon` write is SEC039's.

**Why it matters.** Unauthenticated writes are rarely intended: a public form
that should create rows through a service function instead lets anyone tamper
with, overwrite, or delete data directly. The signal is the *grant of write
intent to anon* — SEC039 fires on the role list regardless of the predicate,
mirroring SEC003.

**Configuration.**

```toml
[lint.rules.SEC039]
# Roles treated as unauthenticated. Replaces the default ["anon"] — set
# this for a deployment that renames or adds unauthenticated roles.
anon_roles = ["anon", "web_anon"]

# Per-policy escape hatch for an intentional anonymous-write table.
allowlist = ["public.contact_messages.anon_insert"]
```

**No auto-fix.** The right remediation depends on intent — restrict the policy
`TO authenticated` (or a privileged role) and revoke `anon`'s table-level write
grant, route the write through a `SECURITY DEFINER` function, or allowlist a
genuinely public-write table. The choice isn't mechanical.

<a id="rule-sec040"></a>

## SEC040 — Write-side policy WITH CHECK drops USING's row scope

**Severity:** warning.

**What it catches:** a PERMISSIVE `FOR ALL` policy whose `USING` clause scopes
rows by a tenant/owner discriminator equality (`col = <auth value>`) but whose
**explicit** `WITH CHECK` clause binds **no** tenant/owner column at all — it
validates only non-identity columns like `status`. `USING` proves the table is
tenant-scoped on the read side; `WITH CHECK` validates the *new* row image on
write, and an explicit clause **replaces** the implicit reuse of `USING` an
omitted clause would get. The escape is on **INSERT**: a `FOR ALL` insert
that does not read back the new row is governed by `WITH CHECK` alone, so a
caller can `INSERT` a row **stamped with another tenant's id** — a cross-tenant
write.

```sql
-- Fires: USING scopes by tenant_id, but WITH CHECK only validates status —
-- so a non-RETURNING `INSERT INTO documents(tenant_id, status)
-- VALUES (<other tenant>, 'draft')` is accepted (WITH CHECK alone governs it).
CREATE POLICY tenant_rw ON public.documents
    FOR ALL TO authenticated
    USING      (tenant_id = current_setting('app.tenant_id', true)::int)
    WITH CHECK (status IN ('draft', 'published'));

-- Clean: WITH CHECK re-asserts the same tenant scope.
CREATE POLICY tenant_rw ON public.documents
    FOR ALL TO authenticated
    USING      (tenant_id = current_setting('app.tenant_id', true)::int)
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::int
                AND status IN ('draft', 'published'));
```

**Why `FOR ALL` and the one escape condition.** Postgres applies the
SELECT-applicable `USING` to the *new* row whenever a statement reads it —
`INSERT … RETURNING`, and any column-reading `UPDATE` (every `WHERE`/`RETURNING`,
i.e. every PostgREST/ORM update). So `INSERT … RETURNING` and ordinary UPDATE
row-migration are **blocked**; the reachable escape is a non-`RETURNING` insert
(`Prefer: return=minimal`, bulk loads, `INSERT … ON CONFLICT DO NOTHING`; a
column-free blind `UPDATE` migrates one too). That re-check is incidental and
client-controlled — the caller chooses whether to add `RETURNING` — so it is no
substitute for a tenant-scoped `WITH CHECK`. Only a `FOR ALL` (or `FOR INSERT`)
policy carries this INSERT path. SEC040 therefore targets `FOR ALL`, where the
`USING` scope also proves the table is tenant-scoped on the read side; a bare
`FOR UPDATE`
policy is not flagged.

**Not flagged — the asymmetric "read team, write own" pattern.** When
`WITH CHECK` binds a *different* identity column than `USING` scopes by — read
your team, write rows you own — the write side still carries an ownership
binding, so it is a deliberate model and SEC040 stays silent:

```sql
-- Clean: USING scopes reads by team, WITH CHECK binds writes to the caller.
CREATE POLICY tickets_rw ON public.tickets
    FOR ALL TO authenticated
    USING      (team_id = current_setting('app.team', true)::uuid)
    WITH CHECK (user_id = current_setting('app.user', true));
```

SEC040 fires only when the write side binds **no** identity column whatsoever.
This deliberately under-reports the rarer "write side binds a *different*
tenant level than the read side" migration in exchange for not flagging the
common, legitimate asymmetric pattern. A NULL-safe re-assertion
(`WITH CHECK (tenant_id IS NOT DISTINCT FROM <session>)`) and a membership pin
to the caller's tenant set
(`WITH CHECK (tenant_id = ANY(current_setting('app.tenants')::int[]))`) are
recognized as bindings too — both genuinely constrain the write, so a hardened
policy is not flagged. A re-assertion wrapped in a form the extraction does not
unwrap (e.g. `COALESCE(tenant_id, 0) = <session>`) is not recognized; allowlist
such a policy.

**Why it's separate from the other write-side rules.**
[SEC006](#rule-sec006) fires when `WITH CHECK` is *absent* — there Postgres
reuses `USING` as the implicit check, preserving the scope, so an explicit
clause is required for SEC040. [SEC028](#rule-sec028) and
[SEC020](#rule-sec020) fire when `WITH CHECK` is constant `true`; SEC040 cedes
both constant-`true` cases to them (a constant-`false` check blocks every
write, so it is skipped too). SEC040 covers the subtler shape they all miss: a
*real* `WITH CHECK` predicate that simply forgot the tenant key.

**Why it matters.** This is the classic multi-tenant write-escape: reads are
correctly isolated, but the write side lets a caller create a row belonging to
another tenant (an INSERT stamps another tenant's id; a column-free UPDATE
re-parents an existing one). It is the lint-side companion to `pgrls verify
--mode cross-tenant`, which *proves* read isolation; SEC040 is a heuristic
catch on the write side.

**Configuration.**

```toml
[lint.rules.SEC040]
# Auth-context functions whose `=` comparison marks a column as a scope.
# Replaces the default ["auth.uid", "auth.role", "auth.jwt", "current_setting"].
auth_functions = ["auth.uid", "current_setting", "request.jwt.claim"]

# Column names treated as tenant/owner discriminators. Replaces the default
# identity set (tenant_id, user_id, org_id, …).
identity_columns = ["tenant_id", "workspace", "region"]

# Per-policy escape hatch: the discriminator is set by a trigger or
# generated column (so the caller can't stamp it), it is pinned via a form
# the extraction doesn't unwrap (e.g. COALESCE), or a restrictive floor
# covers the write side.
allowlist = ["public.documents.tenant_rw"]
```

**Known limitation.** SEC040 reasons about a single policy. If a sibling
RESTRICTIVE policy re-imposes the tenant predicate in its own `WITH CHECK`, the
cross-tenant write is in practice blocked even though the permissive policy
dropped the scope — SEC040 still flags the permissive policy (re-asserting the
scope where the read-side lives is the clearer fix). Allowlist such a case.

**No auto-fix.** The correct re-assertion is the application's own tenant /
ownership equality — the one `USING` already carries — but transplanting a
`USING` sub-expression into `WITH CHECK` across casts and boolean structure
needs a human eye, so SEC040 reports rather than edits.

<a id="rule-sec041"></a>

## SEC041 — Partition child bypasses the partitioned parent's RLS

**Severity:** warning.

**What it catches:** a declarative partition **child** whose row-level
security is **disabled** while an ancestor in its partition chain has RLS
**enabled**, *and* which is **granted directly to a non-owner role** (so it can
be queried by name). Postgres does not propagate `relrowsecurity` from a
partitioned parent to its children — it is per-table. Queries routed *through
the parent* apply the parent's policies, but a query that names a granted
partition child **directly** is governed by the child's own RLS; with none, it
returns every row, bypassing the parent.

```sql
CREATE TABLE events (tenant_id int, body text) PARTITION BY LIST (tenant_id);
CREATE TABLE events_t1 PARTITION OF events FOR VALUES IN (1);   -- no RLS!
ALTER TABLE events ENABLE ROW LEVEL SECURITY;
ALTER TABLE events FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON events
    USING (tenant_id = current_setting('app.tenant_id', true)::int);

-- as tenant 2:
SELECT * FROM events;       -- only tenant 2's rows (parent RLS applies)
SELECT * FROM events_t1;    -- ALL of tenant 1's rows — RLS bypassed
```

This is verified Postgres behaviour. It matters wherever partition children
are reachable by name — notably PostgREST/Supabase (`GET /events_t1` for any
granted child in the exposed schema) and ORMs or jobs that target a partition
directly.

**Relationship to [SEC001](#rule-sec001).** SEC001 ("RLS not enabled")
deliberately *skips* a partition child when an ancestor has RLS — it avoids a
false "enable RLS" error on the common parent-only pattern and documents the
direct-access caveat. SEC041 promotes that caveat to a checkable finding. The
two are mutually exclusive on a partition child: SEC001 fires when **no**
ancestor has RLS, SEC041 when **an** ancestor does. A child that is RLS-off
but carries its own (dormant) policies is ceded to [SEC032](#rule-sec032),
exactly as SEC001 cedes it.

**Why the direct grant matters.** A privilege grant on the partitioned
parent does **not** cascade to a child for direct access (Postgres does not
inherit privileges to partitions — a parent-granted role gets "permission
denied" on the child). So an un-granted child can only be reached *through*
the parent, where the parent's RLS applies — no bypass. SEC041 therefore
fires only when the child carries its own **row-access** grant — a table- or
column-level `SELECT`/`INSERT`/`UPDATE`/`DELETE` to a non-owner role (a
`GRANT SELECT (col)` is enough to read the whole partition by name; a grant
of only `REFERENCES`/`TRIGGER`/`TRUNCATE` is not row access and does not
count). This is also why `pgrls generate` lints clean: it secures the parent
and does not grant the children.

**Configuration.**

```toml
[lint.rules.SEC041]
# Children only ever reached through the parent (never named directly) — the
# bypass is unreachable, so silence them.
allowlist = ["public.events_t1", "public.events_t2"]
```

**Severity: warning** — like the other "RLS can be bypassed via X" rules
(SEC013, SEC014/SEC016, SEC025). The direct grant proves the child is
reachable by name; whether the application actually issues such a query is
its own behaviour, so SEC041 warns rather than errors. No auto-fix: enable
RLS and add a policy on the child (usually the parent's own scoping
predicate), which pgrls does not synthesize.

<a id="rule-perf001"></a>

## PERF001 — Auth function called per-row in policy USING

**Severity:** warning.

**What it catches:** policies whose `USING` clause calls an auth
function (default set: `auth.uid`, `auth.role`, `auth.jwt`,
`current_setting`) without wrapping the call in a subquery. Postgres
re-evaluates the call once per candidate row — on a million-row scan
that is a million calls. Wrapping as `(SELECT auth.uid())` lets the
planner cache the result for the whole statement.

The rule walks `USING` only — `WITH CHECK` runs once per modified
row regardless of wrapping, so the optimization does not apply.
Calls reached via a `SubLink` (`(SELECT ...)`, `IN (SELECT ...)`,
`EXISTS (SELECT ...)`) are skipped — those are already wrapped.

**The bad pattern:**

```sql
CREATE POLICY tenant_read ON public.invoices
    FOR SELECT TO authenticated
    USING (tenant_id = current_setting('app.tenant_id')::uuid);
    --                ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    --                Re-evaluated per row.
```

**Standard fix.** Wrap the auth call:

```sql
CREATE POLICY tenant_read ON public.invoices
    FOR SELECT TO authenticated
    USING (tenant_id = (SELECT current_setting('app.tenant_id')::uuid));
```

`auth.uid()`, `auth.role()`, `auth.jwt()` get the same treatment.
This is a mechanical rewrite — semantics are unchanged, the planner
just gets to cache.

**Configuring the auth function set.** If your stack uses a custom
helper, replace the default set:

```toml
[lint.rules.PERF001]
auth_functions = ["auth.uid", "current_setting", "my.current_user_id"]
```

Note that `auth_functions` *replaces* the default — list every
function you want covered, including the stock ones if you still use
them.

**Allowlisting individual policies.** Use the qualified policy ID:

```toml
[lint.rules.PERF001]
allowlist = ["public.tiny_table.policy_name"]
```

Reach for the allowlist sparingly — the rewrite is mechanical and
always safe.

<a id="rule-perf002"></a>

## PERF002 — Policy expression uses a VOLATILE function

**Severity:** warning.

**What it catches:** policy expressions that call a VOLATILE
function. Default set: `random`, `clock_timestamp`, `nextval`,
`gen_random_uuid`, `pg_backend_pid`. STABLE functions like `now()`
and `current_setting` are NOT in the set — those have separate
treatment via PERF001's wrap-in-subquery mechanic.

VOLATILE functions are bad in policies on two counts:

* **Non-determinism.** `random() < 0.5` admits some rows and denies
  others *unpredictably*. The predicate's truth value depends on
  call timing, not on the row data — almost never the intended
  semantics, often a security hazard.
* **No caching.** The optimizer cannot fold or cache a VOLATILE
  call; it re-runs per row regardless of `(SELECT …)` wrapping.

**Standard fix.** Move the volatility outside the policy or use a
STABLE alternative. For sampling, do it at the application layer
(or via a `LIMIT` with `ORDER BY random()` outside the RLS path).
For "current time" comparisons, prefer `now()` (STABLE within a
transaction) over `clock_timestamp()` (VOLATILE).

```toml
[lint.rules.PERF002]
# Override REPLACES the default — list every function you want covered.
# volatile_functions = ["random", "clock_timestamp", "my.volatile_helper"]
```

<a id="rule-perf003"></a>

## PERF003 — Policy predicate column without leading-column index

**Severity:** warning.

**What it catches:** policies whose `USING` or `WITH CHECK`
clauses reference a column on the protected table that has no
index where the column is the leading entry. Postgres evaluates
the policy predicate for every candidate row, so without a
leading-column index the planner does a sequential scan to
filter rows. On a multi-tenant table with millions of rows this
is the typical reason "we turned on RLS and the API timed out."

Detection is structural:

1. Walk every RLS-enabled table.
2. For each policy, collect column references in `using_ast` and
   `with_check_ast` via `extract_column_refs(exclude_sublinks=True)`
   — sublinks reference other tables and aren't this rule's concern.
3. Drop refs that don't resolve to a column on the policy's own
   table. Unqualified refs are assumed own-table; qualified refs
   (`alias.col`, `schema.table.col`) are kept only when the
   qualifier matches.
4. Drop refs to columns not in `Table.columns` (when
   `Table.columns` is populated — v5+ snapshots and all live
   introspection) — those are HYG001's territory and PERF003 has
   nothing useful to say about indexing a column that doesn't
   exist. The check is gated on a non-empty `columns` set so v3 /
   v4 baselines that legitimately have empty columns don't lose
   all PERF003 coverage.
5. For each remaining column, look up `Table.indexes` for an
   index whose leading column matches. If none, fire.

The rule treats any access method as "indexed" — B-tree, hash,
GIN, GiST, BRIN. The operator chose the index type and pgrls
doesn't second-guess. A leading-column match is the relevant
signal: a B-tree on `(tenant_id, created_at)` helps `WHERE
tenant_id = X`, but a B-tree on `(created_at, tenant_id)` does
not. Partial indexes also count — the operator is responsible
for ensuring the partial predicate is satisfied by the policy
predicate (pgrls can't statically prove that compatibility).

**Standard fix.** Add a B-tree index whose leading column
matches the policy's filter column:

```sql
-- Policy: USING (tenant_id = current_setting('app.tenant_id')::uuid)
CREATE INDEX invoices_tenant_idx ON public.invoices (tenant_id);
```

For composite predicates (`USING (tenant_id = X AND owner = Y)`),
PERF003 fires for each unindexed column independently. A composite
index `(tenant_id, owner)` silences the rule for `tenant_id` only;
add a second index on `owner` if the policy needs both columns
indexed, or live with the false-positive `owner` finding and
allowlist it.

**Known limitations in v0.5.10:**

* **Expression indexes** (`CREATE INDEX ON tbl (lower(email))`)
  are not matched. The expression list lives in
  `pg_index.indexprs` which v0.5.10's introspection doesn't
  decode. PERF003 will flag the column as un-indexed even when a
  matching expression index exists — allowlist the policy ID when
  this surfaces a false positive.
* **Composite-key policies** fire per referenced column; see the
  example above.
* **Partial indexes** are always treated as helping — pgrls
  can't verify the partial predicate matches the policy predicate.

Allowlist by qualified policy ID (`schema.table.policy_name`):

```toml
[lint.rules.PERF003]
allowlist = ["public.invoices.tenant_read"]
```

**Note on the demo**: pgrls's own demo (`demo/`) disables PERF003
globally in `demo/pgrls.toml` because the 50+ demo fixtures don't
carry indexes and PERF003 would obscure the rule that each case
is built to demonstrate. Real production schemas should KEEP
PERF003 enabled — it catches a load-bearing perf bug that's
invisible until traffic hits.

<a id="rule-perf004"></a>

## PERF004 — Policy filters on a function-wrapped column, defeating a plain index

**Severity:** warning.

**What it catches:** policies whose `USING` or `WITH CHECK` clause
wraps an own-table column in a function call — `lower(email) =
current_setting('app.email')` — while the table carries an ordinary
plain index on that column (`CREATE INDEX ON users (email)`).
Postgres can only use an index whose indexed expression matches the
query expression, so the `lower(...)` wrapper makes the plain index
unusable and the planner falls back to a sequential scan. The fix is
an *expression* index matching the predicate:

```sql
CREATE INDEX users_lower_email_idx ON public.users (lower(email));
```

…or rewrite the policy to compare the bare column.

PERF004 is the precise complement of [PERF003](#rule-perf003).
PERF003 owns the *no index at all* case; PERF004 owns the *plain
index exists but a function defeats it* case. They are disjoint on
the index condition, so a column trips at most one:

* No plain index on the wrapped column → PERF003 fires (the column
  is un-indexed), PERF004 stays silent.
* A plain leading-column index exists → PERF003 is satisfied and
  can't tell the wrapper defeats it, so it stays silent. That
  false-negative is exactly what PERF004 catches.

Detection is structural: the policy AST is walked for `FuncCall`
nodes, and any own-table column appearing inside one is
"function-wrapped". A wrapped column is flagged only when the table
has a plain leading-column index on it (the index being wasted).
Sub-select columns are excluded — they live on other tables. The
value-side case (`tenant_id = lower(current_setting(…))`) does not
fire: `tenant_id` is a bare operand and its index is usable; the
function wraps the *value*, not the column.

**Scope is `FuncCall` wrapping only** — the textbook
functional-index case (`lower(col)`, `upper(col)`,
`date_trunc(…, col)`, custom functions). Other expression forms that
also defeat a plain index — `COALESCE`/`CASE` (their own AST node
types, not `FuncCall`), operator expressions (`col || …`), and casts
(`col::text`) — are deliberately out of scope: catching every
wrapper shape is a rabbit hole, and the function-call form is the
common, high-signal one. A column wrapped only in those other forms
is not flagged.

**Known limitation** (shared with PERF003): pgrls does not decode
expression indexes (`pg_index.indexprs`), so it cannot confirm a
matching expression index already exists. In the rare case a table
has *both* a plain `(email)` index and the correct `(lower(email))`
expression index, PERF004 will fire a false positive — allowlist the
policy ID:

```toml
[lint.rules.PERF004]
allowlist = ["public.users.by_email"]
```

<a id="rule-perf005"></a>

## PERF005 — RLS-protected table observed to sequentially scan in production

**Severity:** info. **Opt-in** — fires only when lint is given a
runtime-stats artifact.

**What it catches:** [PERF003](#rule-perf003) and
[PERF004](#rule-perf004) reason *statically* — they read the schema and
*predict* a sequential scan. PERF005 reads what the database *actually
did*. `pgrls perf --snapshot .pgrls-perf.json` captures Postgres's
cumulative table statistics (`pg_stat_user_tables`); `pgrls lint --perf
.pgrls-perf.json` then fires PERF005 for every RLS-enabled table the
snapshot shows under sequential-scan pressure. It is the lint-gate face of
the `pgrls perf` command — drop it in CI next to the static rules.

Like [HYG004](#rule-hyg004) with its coverage artifact, PERF005 is inert
on a normal `pgrls lint` run (no artifact wired in, nothing observed to
judge) — it never guesses.

A table is flagged when its snapshot stats clear all three thresholds —
the same gate the `pgrls perf` command uses, so the rule and the command
never disagree:

* **`min_rows`** (default 10000 estimated live rows) — below this a
  sequential scan is cheap and often the plan the planner *should* pick.
* **`min_seq_scans`** (default 50) — a handful of scans (startup, a
  migration, an ad-hoc query) isn't steady-state cost.
* **`min_seq_pct`** (default 50) — the table must do most of its scanning
  sequentially; a mostly-index-scanned table is healthy.

Tune them per-rule, and allowlist a table whose full scans are intentional:

```toml
[lint.rules.PERF005]
min_rows = 50000
min_seq_scans = 100
allowlist = ["public.audit_log"]
```

**Honest scope:** `pg_stat_user_tables` counts *every* sequential scan on
a table, not only those an RLS policy predicate drove — a reporting query
that legitimately full-scans inflates the same counter. So PERF005 points
you at tables worth investigating; it does not *prove* RLS is the cause.
Run `pgrls perf` for the confirmed-missing-index vs index-unused breakdown
(it cross-references PERF003), or `pgrls perf --statements` to attribute the
cost to specific queries via `pg_stat_statements`. Partitioned tables are
under-covered (a parent records no direct scans; children don't carry the
parent's RLS flag). PERF005 has no auto-fix — choosing the right index
needs human judgment about the query shape.

<a id="rule-hyg001"></a>

## HYG001 — Policy references a column that doesn't exist

**Severity:** error.

**What it catches:** policies whose `USING` or `WITH CHECK` clauses
reference an unqualified column name that isn't in the table's current
column list. This usually happens when `ALTER TABLE ... DROP COLUMN`
runs without the operator realizing a policy still mentions the column.
Postgres permits the drop; the policy text persists and errors at
evaluation time.

**Standard fix.** Pick one:

- If the column was meant to be removed, drop the policy and add a new
  one that doesn't reference it.
- If the column was renamed, recreate the policy with the new name.
- If the policy is now obsolete, drop it.

There is no `pgrls.toml` option for HYG001 — every fire is a real bug.

<a id="rule-hyg002"></a>

## HYG002 — Policy named like a placeholder

**Severity:** warning.

**What it catches:** policy names that look like forgotten
scaffolding. Default placeholder vocabulary: `todo`, `fixme`,
`tmp`, `hack`, `xxx`, `debug`, `placeholder`. The match is a
case-insensitive identifier-token check that handles snake_case
(`todo_owner` → `todo`, `owner`), camelCase (`TmpReadAll` →
`tmp`, `read`, `all`), and SCREAMING_SNAKE (`TMP_POLICY` →
`tmp`, `policy`). Names containing the word as a non-token
(`stop_at_midnight` containing `top`) do not match.

The default vocabulary deliberately excludes `temp`, `draft`,
and `wip` — all are real domain words. `temp` collides with
"temperature" in IoT / sensor schemas; `draft` is a standard CMS
publish state; `wip` is the inventory accounting term ("work in
process"). Schemas that genuinely use those words as scaffolding
markers can opt back in via `placeholder_words`.

**Standard fix.** Rename the policy to describe what it actually
gates:

```sql
ALTER POLICY todo_replace_me_later ON public.tickets
    RENAME TO tenant_isolation;
```

If the placeholder name is intentional (rare — usually you want a
real name), allowlist it or override the vocabulary:

```toml
[lint.rules.HYG002]
# Allowlist a specific policy:
allowlist = ["public.tickets.todo_replace_me_later"]
# Or replace the default vocabulary entirely (override REPLACES):
# placeholder_words = ["scratch", "draft"]
```

<a id="rule-hyg003"></a>

## HYG003 — Policy duplicates another policy on the same table

**Severity:** info.

Two policies on one table that are identical in everything but
their name — same command, same role list, same permissive /
restrictive kind, same `USING` and `WITH CHECK` predicates — are
redundant. Permissive policies are OR-combined (`p OR p` is `p`);
restrictive policies are AND-combined (`p AND p` is `p`). The
extra policy changes nothing — almost always a copy-paste
leftover (`policy_v1` / `policy_v2`) or a migration that
re-created a policy it never dropped.

The redundancy is also a maintenance hazard: an operator who
edits "the" policy may touch only one of the pair and leave the
other stale, so the table's effective rule silently diverges from
the policy the operator believes is authoritative.

Detection is an EXACT match. HYG003 groups a table's policies by
`(command, role set, permissive flag, USING text, WITH CHECK
text)`; any group of two or more is a duplicate set. The `USING`
/ `WITH CHECK` strings are Postgres's own `pg_get_expr` rendering,
so two genuinely-identical predicates compare equal. Semantic
equivalence is out of scope — `USING (a = 1)` and `USING (1 = a)`
are different texts and are not flagged. The role list is
compared as a set, so `TO a, b` and `TO b, a` match.

For each duplicate group HYG003 keeps the name-sorted-first
policy as the "original" and flags the rest. Severity is **info**
— a duplicate is redundant, not unsafe. Allowlist the redundant
policy's qualified ID if keeping both is genuinely intended.

<a id="rule-hyg004"></a>

## HYG004 — Policy has no behavioral test

**Severity:** info.

`pgrls lint` proves a policy is well-*formed*; it cannot prove the
policy enforces what you intend. That is what the `pgrls.testing`
pytest plugin is for, and HYG004 closes the loop: it flags any policy
your test suite never exercised. An untested policy is the one most
likely to silently stop working — a migration narrows its `USING`
clause, a role grant drifts, and nothing fails until a tenant sees
another tenant's rows.

HYG004 is **opt-in**. A normal `pgrls lint` run does nothing; the rule
fires only when lint is given a coverage artifact:

```bash
pgrls lint --coverage .pgrls-coverage.json
```

The artifact (`.pgrls-coverage.json`) is written automatically when
your `pgrls.testing` suite runs — it records the
`(schema, relation, role, command)` tuples each test exercised. lint
loads it and injects the data into the rule (rules can't read files
themselves). A policy is **covered** when a test queried its table,
under a role the policy targets (or `PUBLIC`), with a matching command
(a `SELECT` query exercises `SELECT` and `ALL` policies; `INSERT`
exercises `INSERT`/`ALL`; etc.). Anything else is uncovered.

The model under-credits rather than over-credits — a missed match
prompts a test rather than a false "covered". Two consequences:
role inheritance is not resolved (a policy targeting role `A` tested
only via a member role `B` reads as uncovered); and an unqualified
relation in a test query (`FROM events`, resolved through
`search_path`) credits a table by bare name **only when that name is
unique across the scanned schemas**. In a one-schema-per-tenant layout
(`tenant_a.events` / `tenant_b.events`) the bare name is ambiguous, so
an unqualified query credits neither — qualify the test query
(`FROM tenant_a.events`) to record coverage for a specific tenant's
policy. Severity is **info** — an untested policy is a gap to close,
not a live vulnerability. Allowlist a policy's qualified ID to accept
it as intentionally untested. See `pgrls coverage` for the full
per-policy report.

<a id="rule-view001"></a>

## VIEW001 — View bypasses RLS without `security_invoker`

**Severity:** error.

**What it catches:** views (regular, not materialized) that read from
an RLS-protected table without `WITH (security_invoker = true)`.
Postgres 15+ defaults `security_invoker` to `false`, matching the
historical "DEFINER-style" semantics — the view runs queries with the
view *owner's* privileges, not the calling user's. RLS policies on the
underlying table are then evaluated against the owner (typically a
privileged migration / admin role), so per-tenant predicates leak past
the policy boundary every time anyone selects from the view.

**The bad pattern:**

```sql
CREATE VIEW public.user_summary AS
    SELECT id, display_name FROM public.users;
-- security_invoker defaults to false → RLS evaluated as the
-- view owner, not the caller. Every row is visible.
```

**Standard fix.** Flip the reloption — the auto-fixer emits this
exact statement:

```sql
ALTER VIEW public.user_summary SET (security_invoker = true);
```

After this, `SELECT FROM public.user_summary` evaluates the
underlying RLS policies against the calling user's role and session
GUCs, which is the modern default.

VIEW001 walks the schema's view → table dependency graph (via
`pg_depend`) and skips views whose `references` contain no
RLS-enabled tables — a view over reference data does not need
`security_invoker`. Materialized views are skipped entirely; they
are VIEW003's domain (RLS is bypassed by construction at REFRESH
time, regardless of any flag).

**When the bypass is intentional.** Some views legitimately want
DEFINER-style semantics — e.g. an admin dashboard view that
deliberately surfaces cross-tenant aggregates. Allowlist the view
by qualified ID:

```toml
[lint.rules.VIEW001]
allowlist = ["public.admin_user_summary"]
```

The allowlist requires `schema.view` (exactly two parts) — bare-name
entries are rejected so two views with the same name in different
schemas can't both be silenced by a single typo'd entry.

<a id="rule-view002"></a>

## VIEW002 — View is not a `security_barrier`

**Severity:** warning.

**What it catches:** views over RLS-protected tables that lack
`WITH (security_barrier = true)`. Without the flag, the planner is
free to push a caller-supplied predicate (a volatile or
side-effecting function in `WHERE`) *below* the view's RLS-derived
filter. The classic exploit:

```sql
SELECT * FROM v WHERE leak(secret_column);
```

The volatile `leak(...)` evaluates BEFORE the underlying RLS
predicates restrict the row set — leaking rows the calling user
should never have seen, by side-effect rather than return value.

`security_invoker` (VIEW001) and `security_barrier` (this rule) are
*independent* defenses against *different* leak vectors. A view
referencing RLS-protected tables and lacking both flags fires both
rules — neither subsumes the other.

**Standard fix.** Set the reloption — the auto-fixer emits this
exact statement:

```sql
ALTER VIEW public.user_summary SET (security_barrier = true);
```

`security_barrier` tells the planner the view is a privilege
boundary: predicates the user adds in the outer query MUST NOT be
pushed below the view's own qualifications. RLS still applies
normally; the flag closes the orthogonal "WHERE-clause function as
oracle" leak.

**When the warning is acceptable.** Views with no caller-controlled
function calls in WHERE clauses are not exposed to this attack — but
the safer posture is to set the flag anyway and forget about the
distinction. Reach for the allowlist only when the planner cost of
the barrier is measurably bad and the surface is provably safe:

```toml
[lint.rules.VIEW002]
allowlist = ["public.tiny_constant_view"]
```

Same `schema.view` shape as VIEW001.

<a id="rule-view003"></a>

## VIEW003 — Materialized view captures RLS-protected data at refresh time

**Severity:** warning.

**What it catches:** materialized views whose body reads from an
RLS-enabled table. A matview captures rows by running its body at
`REFRESH MATERIALIZED VIEW` time, with the privileges of whoever
issued the REFRESH (typically a privileged migration / cron / admin
role). The captured rows are written to the matview's own physical
heap; queries against the matview read from that heap directly —
they do NOT re-evaluate the underlying body and therefore do NOT
honor RLS on the source tables, regardless of any flag.

This is structurally different from a regular view: VIEW001 /
VIEW002 territory is about per-query evaluation hooks, which a
matview lacks by design. There is no `security_invoker` knob that
restores per-caller RLS on a matview.

**Standard fix.** No mechanical fix exists; the rule has no
auto-fixer for the same reason. Pick one of the two architectural
choices:

```sql
-- Option A: refresh as a per-tenant role so the captured rows are
-- already filtered to that tenant's view.
SET LOCAL ROLE tenant_a;
SET LOCAL app.tenant_id = '...';
REFRESH MATERIALIZED VIEW public.user_summary;

-- Option B: replicate the matview per-tenant. One physical heap per
-- tenant; queries route to the right one.
CREATE MATERIALIZED VIEW public.user_summary_tenant_a AS
    SELECT plan, count(*) FROM public.users
    WHERE tenant_id = '...' GROUP BY plan;
```

Hence: `warning`, no auto-fix. The rule's job is to flag the
architectural gap so the operator chooses one of the above
explicitly rather than discovering the leak in production.

**When the warning is acceptable.** Aggregates that are
intentionally cross-tenant (an admin dashboard counting all users,
say) belong on the allowlist:

```toml
[lint.rules.VIEW003]
allowlist = ["public.global_user_count"]
```

Same `schema.view` shape as VIEW001 / VIEW002.

<a id="rule-view004"></a>

## VIEW004 — View calls SECURITY DEFINER function reading RLS-protected table

**Severity:** warning.

**What it catches:** views whose body calls a `SECURITY DEFINER`
function that, in turn, reads from an RLS-protected table. Because
the function runs with the function owner's privileges (typically a
privileged migration / admin role), RLS on the underlying table is
evaluated against the function owner — NOT the calling user. This
bypasses the per-tenant filter even when the *view* itself is
configured with `security_invoker = true` (VIEW001's defense),
because the bypass happens one frame deeper, inside the function
call.

**The bad pattern:**

```sql
CREATE FUNCTION public.read_users()
    RETURNS SETOF public.users
    LANGUAGE sql SECURITY DEFINER
    AS $$ SELECT * FROM public.users $$;

CREATE VIEW public.user_summary
    WITH (security_invoker = true, security_barrier = true)
    AS SELECT id, email FROM public.read_users();
-- VIEW001 + VIEW002 are both satisfied; the leak happens INSIDE
-- public.read_users(), where SECURITY DEFINER hands the function
-- the owner's privileges and RLS on public.users is evaluated
-- against the owner instead of the caller.
```

**Standard fix.** No mechanical fix exists; the rule has no
auto-fixer. Pick one of the two architectural choices:

```sql
-- Option A: re-write the function as INVOKER (drop SECURITY
-- DEFINER). The function runs with the caller's privileges and
-- RLS applies normally.
CREATE OR REPLACE FUNCTION public.read_users()
    RETURNS SETOF public.users
    LANGUAGE sql  -- no SECURITY DEFINER
    AS $$ SELECT * FROM public.users $$;

-- Option B: document why the bypass is intentional (e.g. a
-- system-level function that legitimately needs to see all rows
-- for an aggregation/audit purpose) and allowlist the view.
```

Tolerance: the rule parses `pg_proc.prosrc` with pglast. Three
documented false-negative paths, each handled silently or with a
stderr warning:

* **Non-SQL language** (PL/pgSQL with `DECLARE`/`BEGIN`, PL/Python,
  etc.): skipped with a stderr warning naming the function.
* **Unparseable SQL** (e.g. dynamic SQL via `EXECUTE` constructed at
  runtime): skipped with a stderr warning naming the function.
* **Cross-scope SECDEF function**: a view whose function call
  resolves to a function in a schema outside `--schemas` is skipped
  silently. To exercise the rule against such functions, expand
  `--schemas` to include the function's home schema.

These match the existing AST-based rule convention (SEC004, PERF001,
etc.).

When a function body uses an unqualified table name and two
RLS-protected tables in different schemas share that bare name, the
rule over-reports rather than under-attributes — the message lists
all candidates and the operator decides which leak (if any) is real.

**When the bypass is intentional.** Allowlist the view by qualified
ID:

```toml
[lint.rules.VIEW004]
allowlist = ["public.admin_user_summary"]
```

Same `schema.view` shape as VIEW001 / VIEW002 / VIEW003.

