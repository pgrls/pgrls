#!/usr/bin/env bash
# Self-contained demo: stand up a throwaway pgvector database, load the
# vulnerable RAG schema, show that RLS *looks* correct, then let `pgrls vector`
# execute the retrieval path and catch the leak a table-level check misses.
#
# Requires: docker, and pgrls (`pip install "pgrls[all]"`).
set -euo pipefail

PORT="${PORT:-55432}"
NAME="pgrls-rag-demo"
URL="postgresql://postgres:demo@localhost:${PORT}/postgres"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup

echo "▸ starting pgvector on :${PORT} ..."
docker run -d --name "$NAME" -e POSTGRES_PASSWORD=demo \
  -p "${PORT}:5432" pgvector/pgvector:pg16 >/dev/null
until docker exec "$NAME" pg_isready -U postgres >/dev/null 2>&1; do sleep 1; done
sleep 1

echo "▸ loading the RAG schema (two tenants, RLS by document ownership) ..."
docker exec -i "$NAME" psql -q -U postgres < "${HERE}/schema.sql"

cat <<'EOF'

── Step 1: RLS looks correct ────────────────────────────────────────────────
As Bob, a DIRECT read of the embeddings table returns only Bob's rows —
Alice's private chunk is denied. Every table-level check is happy.
EOF
docker exec -i "$NAME" psql -U postgres <<'SQL'
SET ROLE app_user;
SELECT set_config('app.uid', 'bob', false);
SELECT id, content FROM document_sections;   -- Bob sees only his own row
SQL

cat <<'EOF'

── Step 2: the retrieval path tells a different story ───────────────────────
`pgrls vector` calls each SECURITY DEFINER match function as Bob and compares
what it returns against what a direct SELECT allows:
EOF
pgrls vector --database-url "$URL" \
  --probe-role app_user --set app.uid=bob || true

cat <<'EOF'

── What happened ────────────────────────────────────────────────────────────
match_document_sections       → LEAK: it handed Bob "ALICE PRIVATE ..." — a row
                                his own RLS denies. SECURITY DEFINER ran the
                                body as the owner, so RLS was never re-checked.
match_document_sections_safe  → NO LEAK: same signature, but it re-applies the
                                ownership filter in its own body.

Both are SECURITY DEFINER over the same RLS-protected table, so a static rule
flags them identically. Executing the path is what separates them.

Fix: re-apply the tenant predicate inside the function body (as _safe does), or
make the function SECURITY INVOKER so the caller's RLS applies.
EOF
