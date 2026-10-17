# Proven access map

`pgrls matrix --prove` checks every role × table read with the same Z3 provers
`pgrls verify` uses, and shows the leaking row when a read isn't safe.

```bash
./run.sh          # needs docker and `pip install pgrls`
```

It starts a throwaway Postgres, loads [`schema.sql`](schema.sql) — a small
Supabase-style schema with `anon`, `authenticated` and `service_role` — and
prints this grid, followed by the leaks, the undecided cells with their
reasons, and a summary:

```
  TABLE               anon      authenticated  service_role
  public.invoices     LEAK      LEAK           EXEMPT
  public.memberships  PROVEN    PROVEN         EXEMPT
  public.notes        LEAK      PROVEN         EXEMPT
  public.orders       POSSIBLE  PROVEN         EXEMPT
  public.profiles     PROVEN    PROVEN         EXEMPT
  public.team_docs    UNKNOWN   UNKNOWN        EXEMPT
```

It also writes the same grid, with the leaking rows, to `access-map.html`.

## What each row shows

- **`notes`** — `auth.uid() IS NULL OR tenant_id = auth.uid()`. Meant as
  "signed-in users see their own notes", it admits every row to a session
  with no JWT: **LEAK** for `anon`. A signed-in user is still scoped to their
  own tenant: **PROVEN** for `authenticated`.
- **`invoices`** — `tenant_id = auth.uid() OR is_public`. The prover shows the
  row that leaks: one with `is_public = true`, readable anonymously and by any
  tenant.
- **`orders`** — the policy is correct, but `order_summaries` is a view owned
  by the superuser, so it runs as its owner and `anon` reaches the rows through
  it. That's **POSSIBLE**, not LEAK: pgrls credits a view with its owner's
  whole reach and doesn't trace the view's own `WHERE`.
- **`team_docs`** — scoped through a sub-select on `memberships`, which the
  prover can't decide, so it says **UNKNOWN** instead of guessing.
- **`profiles`, `memberships`** — correctly scoped: **PROVEN**.
- **`service_role`** — `BYPASSRLS`, so it skips RLS by design: **EXEMPT**.

## The two questions

- **Anonymous columns** (`anon` and `PUBLIC`): can a session with no JWT read
  any row?
- **Every other column**: can a session of that role read a row belonging to
  another tenant?

A LEAK under the anonymous model means anonymous sessions read rows. On a
table you meant to publish, that's intended — the leaking row tells you which
rows.
