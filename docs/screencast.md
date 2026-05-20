# pgrls 60-second tour — screencast recording script

The README's hero links to an asciinema cast. This file is the recipe
to record it. Target length: **60–75 seconds**. Five scenes, each
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

# 2) Apply a deliberately broken schema (five real bugs in five tables)
cat <<'SQL' | docker exec -i pgrls-demo psql -U demo -d demo -q
CREATE TABLE public.users (id uuid primary key, email text);
CREATE TABLE public.documents (id uuid primary key, owner uuid, content text);
ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_read ON public.documents
    FOR SELECT TO public
    USING (auth.uid() = 'admin');                    -- SEC004: inverted auth check
CREATE TABLE public.audit_log (id bigserial primary key, actor text);
                                                     -- SEC001: RLS not enabled
CREATE TABLE public.events (id bigserial, tenant_id int);
ALTER TABLE public.events ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_filter ON public.events
    USING (tenant_id = current_setting('app.tenant')::int);
                                                     -- SEC019: missing missing_ok arg
CREATE SCHEMA IF NOT EXISTS auth;
CREATE FUNCTION auth.uid() RETURNS uuid LANGUAGE sql STABLE
    AS $$ SELECT NULL::uuid $$;
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

Output shows five findings (SEC001, SEC004, SEC009 silent-deny,
SEC019, PERF001 per-row auth call) in red/yellow.

### Scene 3 — explain the marquee finding (≈10s)

```
pgrls lint --rule SEC004 --explain
```

Inline rationale: the Lovable CVE pattern. One paragraph under the
finding.

### Scene 4 — auto-fix (≈15s)

```
pgrls fix --rule SEC001 --check
pgrls fix --rule SEC001 --apply
```

First call prints the proposed `ALTER TABLE … ENABLE ROW LEVEL
SECURITY;`. Second call applies it; SEC001 now silent on re-lint:

```
pgrls lint --rule SEC001
```

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

# 3) Update the README hero link
sed -i '' "s|REPLACE_AFTER_UPLOAD|abc123|" README.md   # macOS
# Linux: sed -i "s|REPLACE_AFTER_UPLOAD|abc123|" README.md

# 4) Commit
git add docs/screencast.cast docs/screencast.svg README.md
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
  → embed) takes ~5 minutes once. Keep `docs/screencast.cast` in
  git so future re-records can diff against the prior cut.
- **Keep it short.** If the cast runs longer than 90s on first
  watch, cut Scene 1 (`pip show`) — the badges already declare the
  version.
