-- The Supabase "RAG with Permissions" shape, reduced to the essentials.
--
-- Chunk embeddings live in `document_sections`, whose RLS restricts a row to
-- the owner of its parent document. Retrieval goes through a similarity-search
-- function. This is the architecture Supabase's own guide recommends.
--
-- Two retrieval functions are defined over the SAME table:
--   * match_document_sections       — SECURITY DEFINER, no re-filter  (LEAKS)
--   * match_document_sections_safe  — SECURITY DEFINER, re-applies RLS (SAFE)
-- A static check cannot tell them apart. `pgrls vector` executes the path.

CREATE EXTENSION IF NOT EXISTS vector;

-- The low-trust role your API connects as (Supabase: `authenticated`).
DROP ROLE IF EXISTS app_user;
CREATE ROLE app_user NOLOGIN;
GRANT USAGE ON SCHEMA public TO app_user;

CREATE TABLE documents (
  id        int PRIMARY KEY,
  owner_id  text NOT NULL           -- Supabase: auth.uid()
);

CREATE TABLE document_sections (
  id           int PRIMARY KEY,
  document_id  int NOT NULL REFERENCES documents(id),
  content      text,
  embedding    vector(3)            -- real projects use vector(1536)
);

-- RLS: a section is visible only if you own its parent document. This is
-- correct, and it is FORCE'd so even the table owner is subject to it.
ALTER TABLE document_sections ENABLE ROW LEVEL SECURITY;
ALTER TABLE document_sections FORCE ROW LEVEL SECURITY;
CREATE POLICY sections_by_owner ON document_sections
  FOR SELECT TO app_user
  USING (document_id IN (
    SELECT id FROM documents
    WHERE owner_id = current_setting('app.uid', true)   -- Supabase: auth.uid()
  ));

GRANT SELECT ON document_sections, documents TO app_user;

-- Two tenants. Alice owns a secret chunk; Bob owns an ordinary one.
INSERT INTO documents VALUES (1, 'alice'), (2, 'bob');
INSERT INTO document_sections VALUES
  (1, 1, 'ALICE PRIVATE: Q3 revenue was $4.2M', '[1,0,0]'),
  (2, 2, 'Bob''s public notes',                 '[0,1,0]');

-- ── The LEAKING retrieval function ───────────────────────────────────────
-- SECURITY DEFINER (recommended for RLS *performance*) runs as the owner, so
-- the body's read of document_sections is NOT re-checked against the caller's
-- RLS. It returns every tenant's chunks.
CREATE FUNCTION match_document_sections(query_embedding vector(3), match_count int)
RETURNS TABLE (id int, content text)
LANGUAGE sql SECURITY DEFINER AS $$
  SELECT s.id, s.content
  FROM document_sections s
  ORDER BY s.embedding <=> query_embedding
  LIMIT match_count
$$;
GRANT EXECUTE ON FUNCTION match_document_sections(vector(3), int) TO app_user;

-- ── The SAFE retrieval function ──────────────────────────────────────────
-- Same signature, same SECURITY DEFINER, but re-applies the ownership filter
-- inside its own body. A static rule sees no difference from the leaking one.
CREATE FUNCTION match_document_sections_safe(query_embedding vector(3), match_count int)
RETURNS TABLE (id int, content text)
LANGUAGE sql SECURITY DEFINER AS $$
  SELECT s.id, s.content
  FROM document_sections s
  WHERE s.document_id IN (
    SELECT id FROM documents WHERE owner_id = current_setting('app.uid', true)
  )
  ORDER BY s.embedding <=> query_embedding
  LIMIT match_count
$$;
GRANT EXECUTE ON FUNCTION match_document_sections_safe(vector(3), int) TO app_user;
