#!/usr/bin/env bash
# Bring up a local Postgres, apply the demo fixture, and run pgrls.
#
# Two modes:
# - default: spin up Postgres in docker on port 5433
# - $DATABASE_URL set: apply the fixture to the existing DB
set -euo pipefail

cd "$(dirname "$0")"

PGRLS="${PGRLS:-pgrls}"
DEMO_OWNS_DOCKER=0

if [ -z "${DATABASE_URL:-}" ]; then
    echo "==> Starting demo Postgres in docker (port 5433)"
    docker compose up -d --wait
    export DATABASE_URL="postgres://demo:demo@localhost:5433/demo"
    DEMO_OWNS_DOCKER=1
else
    echo "==> Using existing DATABASE_URL=$DATABASE_URL"
fi

echo "==> Applying demo fixture (drops + recreates app/private schemas)"
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -q -f setup.sql

echo
echo "==> Running pgrls lint"
echo "------------------------------------------------------------"
set +e
"$PGRLS" lint --database-url "$DATABASE_URL" --config pgrls.toml
exit_code=$?
set -e
echo "------------------------------------------------------------"
echo "(pgrls lint exit code: $exit_code)"

if [ "$DEMO_OWNS_DOCKER" = "1" ]; then
    echo
    echo "==> Demo DB still running."
    echo "    Connect with: psql $DATABASE_URL"
    echo "    Tear down with: docker compose -f $(pwd)/docker-compose.yml down -v"
fi
