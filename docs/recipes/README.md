# Framework recipes

Per-stack guides showing what pgrls catches in the patterns specific to
each framework, plus a ready-to-use CI workflow. Each recipe is
self-contained and assumes you've read the
[Quickstart](../QUICKSTART.md).

- **[Supabase](supabase.md)** — `auth.uid()` / `auth.role()` /
  `auth.jwt()` patterns, the SEC004 + SEC027 + SEC030 trio that
  dominates Supabase RLS bugs, and CI against either your migration
  database or a local `supabase start` stack.
- **[PostgREST](postgrest.md)** — the JWT-claim GUC pattern, the
  `role-as-discriminator` pitfall (SEC018), nullable-discriminator
  columns (SEC030), and the `db-pre-request` gotcha that silently
  hides rows when claims aren't set (or, via the mirror `IS NULL OR …`
  shape, exposes them all — SEC004).
- **[Django](django.md)** — defense-in-depth on top of ORM filtering,
  the session-GUC middleware pattern, the `pgrls.testing` pytest plugin
  for RLS isolation tests alongside your existing test suite.

Don't see your stack? The general pattern is the same: configure pgrls
with `DATABASE_URL` pointing at your migration-applied database, and
the rules apply regardless of which framework wrote the SQL. See the
[README](../../README.md) for the full configuration surface and the
[rule catalogue](../../AGENTS.md) for every check.
