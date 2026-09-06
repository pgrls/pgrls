# pgrls test — Layer 1 protocol

**PROTOCOL_VERSION = 1**

This document specifies the Postgres-side conventions any pgrls test
client follows. The Python client (`pgrls.testing.PgrlsTestClient`)
is the reference implementation; the TypeScript port
([`pgrls-test`](https://www.npmjs.com/package/pgrls-test)) implements
this same contract, and a Go port following the same contract ships
(`go/`). All conformant clients interoperate against the same
RLS-protected schemas.

## Per-test wire sequence

For each test, on a single Postgres connection:

1. `BEGIN` — open a transaction.
2. (Optional) data setup as the connecting (admin) role.
3. For each scenario block within the test:
    1. Capture the prior role and claims so they can be restored
       on clean exit:
       `SELECT current_user, current_setting('request.jwt.claims',
       true)`. Hold the two values as `<prev_role>` and
       `<prev_claims>` for steps 5–6.
    2. `SAVEPOINT pgrls_actor_<rand>` — `<rand>` is an 8-char
       hex string from a 4-byte cryptographically-random source
       (Python: `secrets.token_hex(4)`; TS:
       `crypto.getRandomValues(new Uint8Array(4))` then
       hex-format).
       Random rather than monotonic so nested scenario blocks
       can't collide if a future client implementation forgets
       per-call counter bookkeeping; collisions in the same
       transaction are astronomically unlikely (4 billion
       options).
    3. `SET LOCAL ROLE <role>` — switch to the role under test.
    4. If a claims object is provided (including the empty
       object `{}`):
       `SELECT set_config('request.jwt.claims', $1, true)`
       with `$1` set to the JSON-encoded claims object. The
       empty object MUST be sent as `'{}'`, not skipped — it is
       a deliberate "actor with no claims" request and is
       distinct from omitting claims entirely. To skip the
       `set_config` call, the client API exposes the absent-
       claims state as `null` / `None` / `nil`.

       Values inside the claims object must be JSON-serializable
       (string / number / boolean / null / nested object / array).
       Use the language's standard JSON encoder with no custom
       `default` — `json.dumps` in Python, `JSON.stringify` in
       TS. Non-serializable values (e.g. a `Date` object, a
       Python `datetime`) are a programmer error at the
       language layer, not a protocol-level concern.
    5. Run the scenario's queries; capture results / exceptions.
    6. On clean exit:
       `RELEASE SAVEPOINT pgrls_actor_<rand>`, then explicitly restore
       prior state. Two cases:
       * `<prev_claims>` is non-NULL: issue
         `SET LOCAL ROLE <prev_role>` and
         `SELECT set_config('request.jwt.claims', <prev_claims>, true)`.
       * `<prev_claims>` is NULL: issue `SET LOCAL ROLE <prev_role>`
         and, only if the inner block set claims, issue
         `SELECT set_config('request.jwt.claims', NULL, true)` to
         clear the GUC value. (Postgres collapses NULL to `''` on
         custom GUCs once they've been touched — true-NULL is no
         longer reachable for the rest of the session — but the
         JSON content is gone, so a downstream policy doing
         `::jsonb` fails loudly instead of silently authorizing as
         the inner-block actor. If the inner block never set
         claims, skip the call entirely so the GUC stays at its
         pre-block state.)
       Required because `RELEASE SAVEPOINT` keeps the inner
       `SET LOCAL` changes merged into the outer transaction —
       a `RESET ROLE` here would clobber an outer block's role
       in the nested case.
    7. On exception:
       `ROLLBACK TO SAVEPOINT pgrls_actor_<rand>` only.
       `ROLLBACK TO SAVEPOINT` reverts the role and any GUC that
       had a prior value. A claim GUC that was UNSET comes back as
       `''`, not NULL (measured) — true-NULL is unreachable once
       touched, per step 6 — so a downstream
       `current_setting(…, true) IS NULL` gate behaves differently
       after the rollback.
4. `ROLLBACK` — drop the test's entire transaction.

Nested scenario blocks are supported by construction: every
inner block captures `<prev_role>` and `<prev_claims>` in step 1
and restores them in step 6 (or via `ROLLBACK TO SAVEPOINT` in
step 7). Nesting an inner block whose role differs from the
outer's leaves the outer's role intact after the inner block
exits.

## Why these primitives

* **`SET LOCAL ROLE`** (not session-level `SET ROLE`) is bound to
  the current transaction; the outer `ROLLBACK` resets it
  automatically.
* **`set_config(key, value, true)`** is the procedural form of
  `SET LOCAL` for GUC keys whose names contain a dot.
  `SET LOCAL request.jwt.claims = '...'` is itself valid SQL —
  dotted names are exactly how Postgres spells customized options
  (measured) — but `SET` takes no bind parameter, so a client that
  must pass the value as a parameter has to use `set_config`.
* **`SAVEPOINT` per scenario** prevents one role's GUC values from
  bleeding into the next scenario in the same test.
* **PostgREST conventions** (`request.jwt.claims` GUC) are the
  default for Supabase-style stacks, which is the dominant
  deployment pgrls targets. Non-PostgREST shops can configure
  alternative claim helpers in a future protocol version 2.

## Conformance criteria

A client conforms to v1 of the contract iff it:

1. Uses `SET LOCAL` (not session-level `SET`) so transaction
   rollback resets state. **Conformance test:** issue
   `SET LOCAL ROLE x` inside a transaction, rollback, assert
   `current_user` is back to the connecting admin role.
2. Uses `set_config(..., true)` for the `request.jwt.claims` GUC.
   **Conformance test:** set claims via the helper, rollback,
   assert `current_setting('request.jwt.claims', true)` is empty.
3. Honors PostgreSQL's `InsufficientPrivilege` error class
   (SQLSTATE `42501`) for "rejected" assertion semantics.
   **Conformance test:** insert a row that violates a
   `WITH CHECK (false)` policy, assert SQLSTATE `42501`.
4. Treats `UPDATE ... RETURNING` (or `DELETE ... RETURNING`)
   returning zero rows as "silently dropped" — `USING` filtered
   the row out before the write touched it.
   **Conformance test:** update a row whose `USING` predicate
   denies for the current role/claims; assert `RETURNING id`
   returns `[]`. (`INSERT ... RETURNING` does NOT exhibit this
   shape — Postgres enforces `WITH CHECK` on the new row and
   raises `InsufficientPrivilege` rather than silently
   filtering, by design to prevent leak-via-RETURNING.)

## What's deliberately out of contract

These are per-language idiomatic choices, not protocol invariants:

* The Postgres client library used (psycopg, pg-promise, lib/pq).
* The test framework integrated with (pytest, vitest, `testing.T`).
* Assertion helper names (`assert_visible` vs `expectVisible`).
* Seeding API (a `seed()` method, an integration with Drizzle,
  factory_boy, etc.).

## Versioning

Breaking changes to the wire sequence — new required SQL, changed
GUC name, etc. — bump `PROTOCOL_VERSION`. Adding new optional
helpers is non-breaking. The version lives in this document and in
`pgrls.testing.PROTOCOL_VERSION`; clients should assert they
understand the document's version when bootstrapping.

### Package version vs protocol version

Package versions evolve **independently per language**:

* Python `pgrls` ships via PyPI tags `v*` (see
  [`CHANGELOG.md`](../CHANGELOG.md) for the current version).
* TS `pgrls-test` ships via npm tags `ts-v*` (see
  [`ts/CHANGELOG.md`](../ts/CHANGELOG.md)).
* Go `pgrls-test` ships via tags `go/v*` (see
  [`go/CHANGELOG.md`](../go/CHANGELOG.md)).

What ties them together is `PROTOCOL_VERSION`. Any two clients
that expose the same `PROTOCOL_VERSION` are guaranteed to
interoperate against the same RLS-protected schema — the wire
sequence is identical regardless of package version.

Bumping `PROTOCOL_VERSION` requires a coordinated release of all
maintained clients. Adding wire-level additions stays at the
current version (clients on older versions ignore the new
optional steps).
