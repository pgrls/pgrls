-- ============================================================
-- Use case 5: Permissive PUBLIC — SEC003
-- Permissive (default) policy granted to PUBLIC. Permissive
-- policies OR with every other policy on the table; this single
-- entry can wash out tenant policies that someone adds later.
-- ============================================================

CREATE TABLE app.posts (
    id BIGSERIAL PRIMARY KEY,
    author_id TEXT,
    body TEXT
);
ALTER TABLE app.posts ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.posts FORCE ROW LEVEL SECURITY;
CREATE POLICY everyone_reads ON app.posts
    FOR SELECT TO PUBLIC
    USING (true);  -- also fires SEC005, SEC007, SEC008
