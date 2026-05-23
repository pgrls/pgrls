# pgrls + Django

Django apps usually rely on the ORM's `WHERE` clauses for authorization,
which works until something *isn't* the ORM — a raw `cursor.execute()`,
a migration script, a `manage.py shell` session, a Celery task using a
shared connection, or a missed `.filter(...)` in a complex view.
Postgres RLS gives you defense-in-depth: even if the ORM filter is
missing, the database itself refuses to return the wrong rows.

The two Django + RLS patterns in practice:

1. **Session-GUC pattern (hand-rolled or via a middleware).** A
   middleware sets a Postgres GUC like `app.user_id` /
   `app.tenant_id` on every request, and policies key on
   `current_setting('app.user_id', true)`. This is the most flexible
   setup and the one pgrls is most useful against.
2. **`django-multitenant`-style libraries** that add a `tenant_id`
   column and a session-context manager. RLS becomes the
   bottom-of-the-stack enforcement layer that the library's app-level
   filtering complements.

This recipe assumes the session-GUC pattern; the linting story is the
same either way.

## The middleware that sets the GUC

A minimal Django middleware that copies `request.user.id` into a
Postgres GUC for the lifetime of the request:

```python
# myapp/middleware.py
from django.db import connection

class RLSContextMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        user_id = (
            str(request.user.pk)
            if request.user.is_authenticated
            else ''
        )
        with connection.cursor() as cur:
            cur.execute("SELECT set_config('app.user_id', %s, true)", [user_id])
        return self.get_response(request)
```

`set_config(..., true)` is `SET LOCAL` — the value lasts only for the
current transaction. Django wraps each request in a transaction by
default (`ATOMIC_REQUESTS = True`), so the GUC scopes naturally.

## The signature Django + RLS bug

The recurring footgun is the policy that tries to permit "anonymous"
(unauthenticated) traffic with `IS NULL OR …`:

```sql
CREATE POLICY tenant_read ON app_document
    FOR SELECT
    USING (
        current_setting('app.user_id', true) IS NULL
        OR owner_id::text = current_setting('app.user_id', true)
    );
```

The middleware above sets `app.user_id` to `''` for anonymous users
(not `NULL`), but the moment the middleware is bypassed (a `manage.py
shell` session, a Celery task without the middleware, an
unauthenticated path that never goes through the middleware), the GUC
is genuinely `NULL` and the `IS NULL` branch is `true` — admitting
every row.

pgrls flags this as **SEC004** (severity `error`) — its default
auth-function set includes `current_setting`, so this shape trips the
rule.

The fix: drop the `IS NULL` branch and rely on the middleware's
empty-string sentinel:

```sql
USING (owner_id::text = current_setting('app.user_id', true))
```

`'' = owner_id::text` is false for any real owner, so anonymous
contexts get no rows — without the OR-disjunct that opens the door.

## Schema-prefixed table names

Django's default table naming is `<app_label>_<model>`. pgrls reports
findings with the schema-qualified name (`public.app_document`), so the
output line for the policy above looks like:

```
  ERROR  SEC004  public.app_document.tenant_read
```

If you use a non-default schema (`db_table = 'myschema.app_document'`
or a `search_path`-based separation), pass `--schemas` to narrow the
scan and `pg_dump --schema` to seed your CI database with the right
shape.

## Wire it into Django CI

Django's test runner builds a transient test database from your
migrations. pgrls can lint that same database:

```yaml
# .github/workflows/pgrls.yml
name: pgrls
on: [push, pull_request]
jobs:
  rls:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:16-alpine
        env: { POSTGRES_PASSWORD: ci, POSTGRES_DB: ci }
        ports: ["5432:5432"]
        options: >-
          --health-cmd pg_isready --health-interval 10s --health-retries 5
    env:
      DATABASE_URL: postgres://postgres:ci@localhost:5432/ci
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.11" }
      - run: pip install -r requirements.txt
      - name: Apply migrations
        run: python manage.py migrate --no-input
      - uses: pgrls/pgrls-action@v1
        with:
          database-url: ${{ env.DATABASE_URL }}
          fail-on: error
```

The Action installs pgrls from PyPI and runs `pgrls lint` against the
migrated database. Findings render as GitHub Actions annotations
inline on the PR.

## Testing the policies themselves

The `pgrls.testing` pytest plugin (`pip install pgrls[testing]`) lets
you write per-test RLS isolation assertions in a Django project that
already uses pytest:

```python
from pgrls.testing import PgrlsTestClient

def test_user_cant_see_other_users_documents(pgrls_db: PgrlsTestClient):
    with pgrls_db.transaction():
        pgrls_db.exec("SELECT set_config('app.user_id', %s, true)", ['alice'])
        pgrls_db.exec("INSERT INTO app_document(owner_id, body) VALUES('alice', 'A')")
        pgrls_db.exec("INSERT INTO app_document(owner_id, body) VALUES('bob', 'B')")
        rows = pgrls_db.fetchall("SELECT body FROM app_document")
        assert {r['body'] for r in rows} == {'A'}
```

It plays well alongside Django's own `TestCase` — RLS tests live in
the same suite as your view/model tests but exercise the database
constraint directly.

## Adopting on an existing Django project

`--baseline` records what's currently flagged so CI fails only on
*new* findings:

```bash
pgrls lint --baseline .pgrls-baseline.json
```

## See also

- [`docs/QUICKSTART.md`](../QUICKSTART.md) — the 5-minute first-run.
- [`README.md`](../../README.md) — the full feature tour.
- [`AGENTS.md`](../../AGENTS.md) — every rule with its reference
  paragraph and fix recipe.
