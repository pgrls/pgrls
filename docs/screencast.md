# pgrls 60-second tour — screencast recording script

The README's hero links to `docs/screencast.svg`, an inline SVG rendered
from a terminal recording (termtosvg or asciinema + svg-term both work).
This file is the recipe to record it. Target length: **60–75 seconds**. Five scenes, each
self-explanatory in 5–15 seconds.

## Prereqs

```bash
brew install asciinema           # macOS — or pipx install asciinema
npm i -g svg-term-cli            # asciinema cast → inline SVG (optional)
docker --version                 # 24+
python -m pip install --upgrade pgrls
```

## Setup (run before pressing record)

```bash
# 1) Throwaway Postgres for the demo
docker rm -f pgrls-demo 2>/dev/null
docker run -d --name pgrls-demo -p 55432:5432 \
  -e POSTGRES_DB=demo -e POSTGRES_USER=demo -e POSTGRES_PASSWORD=demo \
  postgres:17 >/dev/null
until docker exec pgrls-demo pg_isready -U demo >/dev/null 2>&1; do sleep 0.5; done

# 2) Apply a deliberately broken schema. The auth schema/function are
#    created FIRST so the documents policy can reference auth.uid()
#    when it's defined below.
cat <<'SQL' | docker exec -i pgrls-demo psql -U demo -d demo -v ON_ERROR_STOP=1 -q
CREATE SCHEMA IF NOT EXISTS auth;
CREATE FUNCTION auth.uid() RETURNS uuid LANGUAGE sql STABLE
    AS $$ SELECT NULL::uuid $$;

-- public.users: no RLS → SEC001 fires.
CREATE TABLE public.users (id uuid primary key, email text);

-- public.documents: RLS on, but USING has the Lovable CVE shape
-- (`auth.uid() IS NULL` short-circuits the OR to true for any
-- anonymous connection — auth.uid() returns NULL when no JWT is
-- present). SEC004 fires (marquee CVE pattern); the unwrapped
-- auth.uid() calls also trip PERF001 (per-row evaluation).
CREATE TABLE public.documents (id uuid primary key, owner uuid, content text);
ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_read ON public.documents
    FOR SELECT TO public
    USING (auth.uid() IS NULL OR owner = auth.uid());

-- public.audit_log: no RLS → second SEC001 finding.
CREATE TABLE public.audit_log (id bigserial primary key, actor text);

-- public.events: RLS on, but USING calls one-argument current_setting
-- (raises on an unset GUC instead of returning NULL) → SEC019 fires.
-- The unwrapped current_setting also trips PERF001.
CREATE TABLE public.events (id bigserial, tenant_id int);
ALTER TABLE public.events ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_filter ON public.events
    USING (tenant_id = current_setting('app.tenant')::int);
SQL

# 3) Point pgrls at it
export DATABASE_URL=postgres://demo:demo@localhost:55432/demo

# 4) Clear the screen, set a short prompt so the recording reads tight
clear
export PS1='$ '
```

## Record

```bash
# --idle-time-limit 1.5 caps long pauses; --cols 96 --rows 24 gives a
# README-friendly frame. Press Ctrl-D / type `exit` when done.
asciinema rec --idle-time-limit 1.5 --cols 96 --rows 24 \
  --title 'pgrls 60-second tour' \
  docs/screencast.cast
```

Then run the five scenes below. Type at human speed; **don't paste —**
asciinema captures keystrokes and the pauses make it watchable.

### Scene 1 — install (≈5s)

```
pip show pgrls | grep -E '^(Name|Version|Summary)'
```

### Scene 2 — lint a broken schema (≈15s)

```
pgrls lint
```

Output shows several findings across the four tables — most
prominently **SEC004** (inverted auth check on `documents`),
**SEC001** (RLS off on `users` and `audit_log`), **SEC019**
(one-arg `current_setting` on `events`), and **PERF001** (the
unwrapped `auth.uid()` / `current_setting()` calls).

### Scene 3 — explain the marquee finding (≈10s)

```
pgrls lint --rule SEC004 --explain
```

Inline rationale appears under the finding: the Lovable CVE pattern,
why `auth.uid() IS NULL OR …` admits every anonymous read.

### Scene 4 — auto-fix (≈15s)

```
pgrls fix --rule SEC001
pgrls fix --rule SEC001 --apply
```

The first call is the default dry-run — it prints the proposed
`ALTER TABLE … ENABLE ROW LEVEL SECURITY;` statements to stdout
without touching the database (so `pgrls fix > migration.sql`
works as a script generator). The second call applies them.
Re-lint the same rule to show it's now silent:

```
pgrls lint --rule SEC001
```

(Re-running the full `pgrls lint` here would surface a fresh
SEC009 — "RLS enabled but no policies" — on the tables we just
enabled RLS on. That's a real follow-on finding pgrls is designed
to nag about, but for the screencast we keep the focus on the
one rule the fix actually addressed; `--rule SEC001` keeps the
output tight.)

### Scene 5 — diff catches a regression (≈15s)

```
pgrls snapshot -o /tmp/base.json
docker exec pgrls-demo psql -U demo -d demo -c \
  "ALTER TABLE public.documents DISABLE ROW LEVEL SECURITY"
pgrls diff /tmp/base.json --fail-on dangerous
echo "exit=$?"
```

Output: `[DANGEROUS] Table public.documents RLS disabled.` plus
`exit=1`. The migration would have failed CI.

### Exit

```
exit
```

## Upload & embed

```bash
# 1) Upload to asciinema.org (free, unlisted by default)
asciinema upload docs/screencast.cast
# → copies a URL like https://asciinema.org/a/abc123 to stdout.
#   Note the ID (`abc123`).

# 2) Render the placeholder SVG with the actual frames
svg-term --in docs/screencast.cast \
         --out docs/screencast.svg \
         --window --width 96 --height 24

# 3) The README hero links the raw SVG directly
#    (https://raw.githubusercontent.com/pgrls/pgrls/main/docs/screencast.svg),
#    so there is no placeholder to substitute — committing the new SVG is the
#    whole update. The asciinema upload in step 1 is optional (a shareable
#    link), not something the README depends on.

# 4) Commit
git add docs/screencast.svg README.md
git commit -m 'docs: record 60-second pgrls tour for README hero'
```

## Cleanup

```bash
docker rm -f pgrls-demo
unset DATABASE_URL
```

## Notes

- **Why asciinema, not GIF.** GIFs are 5–20× the size of an
  equivalent SVG/cast, and the click-through to asciinema.org gives
  viewers play/pause/scrub controls. GitHub renders `<img src=…svg>`
  in the README natively.
- **Why a throwaway Docker container, not testcontainers.** The
  screencast is the demo; we want the viewer to see the commands
  hit a real database, not pgrls's internal test plumbing.
- **Re-record cheaply.** The whole script (setup → record → upload
  → embed) takes ~5 minutes once. The recording leaves
  `docs/screencast.cast` on disk so a re-record can be diffed against the
  prior cut; only the rendered `docs/screencast.svg` is committed.
- **Keep it short.** If the cast runs longer than 90s on first
  watch, cut Scene 1 (`pip show`) — the badges already declare the
  version.
