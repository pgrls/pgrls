#!/usr/bin/env bash
# Self-contained demo: stand up a throwaway Postgres, load a small
# Supabase-style schema, and let `pgrls matrix --prove` check every role x
# table read with the Z3 prover — writing the grid to access-map.html.
#
# Requires: docker, and pgrls (`pip install pgrls`).
set -euo pipefail

PORT="${PORT:-55433}"
NAME="pgrls-access-map-demo"
URL="postgresql://postgres:demo@127.0.0.1:${PORT}/postgres"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${HERE}/access-map.html"
ROLES="anon,authenticated,service_role"

cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup

echo "▸ starting Postgres on :${PORT} ..."
docker run -d --name "$NAME" -e POSTGRES_PASSWORD=demo \
  -p "127.0.0.1:${PORT}:5432" postgres:16 >/dev/null
until docker exec "$NAME" pg_isready -U postgres >/dev/null 2>&1; do sleep 1; done
sleep 1

echo "▸ loading the schema ..."
docker exec -i "$NAME" psql -q -v ON_ERROR_STOP=1 -U postgres < "${HERE}/schema.sql"

echo
pgrls matrix --database-url "$URL" --prove --roles "$ROLES" \
  | sed -n '/Isolation proof/,$p'

pgrls matrix --database-url "$URL" --prove --roles "$ROLES" \
  --format html --output "$OUT"
echo
echo "▸ wrote ${OUT}"
