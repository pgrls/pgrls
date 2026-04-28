-- ============================================================
-- Use case 77: HYG002 — placeholder-named policy
-- A policy named `todo_*`, `fixme_*`, `tmp_*`, `hack_*`, `xxx_*`,
-- `debug_*`, or `placeholder_*` is almost always a forgotten
-- scaffold from an unfinished migration. Detection handles
-- snake_case, camelCase, and SCREAMING_SNAKE so `todo_owner`,
-- `TmpReadAll`, and `TMP_POLICY` all match while names
-- containing `top` (e.g. `stop_at_midnight`) do not. The default
-- vocabulary excludes `temp`, `draft`, and `wip` — they collide
-- with real domain words (temperature, CMS draft state, WIP
-- inventory). Users can opt back in via `placeholder_words`.
-- ============================================================

CREATE TABLE app.placeholder_named (
    id BIGSERIAL,
    user_id TEXT
);
ALTER TABLE app.placeholder_named ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.placeholder_named FORCE ROW LEVEL SECURITY;
CREATE POLICY todo_replace_me_later ON app.placeholder_named
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (user_id = (SELECT current_setting('app.user', true)));
