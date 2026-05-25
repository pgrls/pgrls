"""End-to-end perf bench for `pgrls lint`.

Spins up an ephemeral Postgres via testcontainers, applies a synthetic
schema with a parametrized number of tables + policies, runs the lint
in-process (introspect + walk every rule), and prints a single JSON
record to stdout. The CLI's argument-parser layer is bypassed in the
timed loop — we drive the library API directly so the numbers reflect
the lint work itself, not CLI-parser setup.

Usage:

    python -m bench.lint_perf --table-count 10 --policy-count 100

For a curve, run a sweep and `jq -s '.'` the results into an array:

    for n in 10 100 1000 10000; do
      python -m bench.lint_perf \\
        --table-count "$((n / 10))" --policy-count "$n"
    done | jq -s '.'

Requires the `dev` extras (which pulls in `testcontainers[postgres]`).
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from collections.abc import Iterable
from importlib.metadata import version as _pkg_version

import psycopg
from testcontainers.postgres import PostgresContainer

from pgrls.introspect import introspect
from pgrls.model import Schema
from pgrls.rules import default_registry
from pgrls.violations import Violation


# We deliberately do not pin a particular Postgres minor — the public
# README's screencast also uses postgres:16-alpine, so this matches
# what real users encounter on the GitHub Action's stock service
# container.
POSTGRES_IMAGE = "postgres:16-alpine"


def _generate_schema_sql(*, tables: int, policies: int) -> str:
    """Return SQL that creates `tables` tables and `policies` policies
    distributed across them.

    The shape is chosen so that several rules actually fire — a fast
    rule walk over a schema where no rule fires would understate the
    cost of the realistic case. We pick a mix:

    - half the tables get a policy that lacks the `(SELECT auth.uid())`
      wrap (trips PERF001),
    - all RLS-enabled tables lack FORCE (trips SEC002),
    - half lack a WITH CHECK clause on UPDATE (trips SEC006).

    Each table has a small set of columns so the column-resolution
    helpers (`_own_table_column` etc.) have realistic input.
    """
    if tables < 1:
        raise ValueError("tables must be >= 1")
    if policies < 0:
        raise ValueError("policies must be >= 0")

    # We don't need a user-defined function — the PERF001 rule
    # recognizes `current_setting(...)` directly (it's in the rule's
    # default `auth_functions` set). Using the stock helper keeps the
    # bench's "this should trip these rules" claim honest.
    stmts: list[str] = []

    for t in range(tables):
        name = f"t_{t:05d}"
        stmts.append(
            f"CREATE TABLE public.{name} ("
            "id bigserial PRIMARY KEY,"
            "owner_id uuid NOT NULL,"
            "tenant_id uuid NOT NULL,"
            "body text"
            ");"
        )
        stmts.append(
            f"ALTER TABLE public.{name} ENABLE ROW LEVEL SECURITY;"
        )

    # Distribute policies round-robin across tables. Use two
    # rule-tripping shapes so the rule walkers do realistic work.
    for p in range(policies):
        t = p % tables
        name = f"t_{t:05d}"
        pname = f"pol_{p:05d}"
        if p % 2 == 0:
            # `current_setting(...)` without `(SELECT …)` wrap trips
            # PERF001. `current_setting` is in the rule's default
            # `auth_functions` set (per src/pgrls/rules/perf001.py).
            stmts.append(
                f"CREATE POLICY {pname} ON public.{name} "
                "FOR SELECT TO public "
                "USING (owner_id::text = "
                "current_setting('app.uid', true));"
            )
        else:
            # UPDATE without WITH CHECK trips SEC006. We wrap the
            # GUC call in (SELECT …) here so the same shape does NOT
            # also trip PERF001 — the bench should exercise each
            # rule on a distinct policy so a per-rule cost change
            # shows up as a per-shape regression, not a tangled mix.
            stmts.append(
                f"CREATE POLICY {pname} ON public.{name} "
                "FOR UPDATE TO public "
                "USING (owner_id::text = "
                "(SELECT current_setting('app.uid', true)));"
            )

    return "\n".join(stmts)


def _run_all_rules(schema: Schema) -> Iterable[Violation]:
    """Iterate every rule against `schema` with empty options, exactly
    as `pgrls.cli._run_rules` does for the default `[lint]` config.
    """
    registry = default_registry()
    for rule in registry.enabled(disabled_ids=[]):
        # Per-rule options default to empty when the user has no
        # `[lint.rules.<ID>]` table — same shape as `_run_rules`.
        yield from rule.check(schema, {})


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="bench.lint_perf",
        description=__doc__,
    )
    p.add_argument(
        "--table-count",
        type=int,
        required=True,
        help="number of tables to create",
    )
    p.add_argument(
        "--policy-count",
        type=int,
        required=True,
        help="number of policies to create (distributed round-robin)",
    )
    args = p.parse_args(argv)

    schema_sql = _generate_schema_sql(
        tables=args.table_count, policies=args.policy_count
    )

    # Spin up Postgres, apply schema, time the lint.
    with PostgresContainer(POSTGRES_IMAGE) as pg:
        # `driver=None` returns the bare `postgres://...` URL psycopg
        # accepts; without it testcontainers prepends a SQLAlchemy
        # driver prefix (`postgresql+psycopg2://`) which psycopg
        # rejects. Same shape as `cli.py` and the test fixtures.
        conn_str = pg.get_connection_url(driver=None)

        t0 = time.perf_counter()
        with psycopg.connect(conn_str) as apply_conn:
            with apply_conn.cursor() as cur:
                cur.execute(schema_sql)
            # The `with psycopg.connect(...)` block commits on
            # successful exit, so no explicit `commit()` here.
        schema_apply_ms = int((time.perf_counter() - t0) * 1000)

        with psycopg.connect(conn_str) as lint_conn:
            t1 = time.perf_counter()
            schema = introspect(lint_conn, ["public"])
            introspect_ms = int((time.perf_counter() - t1) * 1000)

            t2 = time.perf_counter()
            violations = list(_run_all_rules(schema))
            rules_ms = int((time.perf_counter() - t2) * 1000)

    # `lint_ms` is the headline number: total wall-clock cost of an
    # in-process lint, excluding container boot and schema-apply.
    # Operators care about this because container boot is amortized
    # over the CI job; the rule walk runs per push.
    lint_ms = introspect_ms + rules_ms

    rules_fired = sorted({v.rule_id for v in violations})

    record = {
        "table_count": args.table_count,
        "policy_count": args.policy_count,
        "schema_apply_ms": schema_apply_ms,
        "introspect_ms": introspect_ms,
        "rules_ms": rules_ms,
        "lint_ms": lint_ms,
        "violation_count": len(violations),
        "rules_fired_count": len(rules_fired),
        "rules_fired": rules_fired,
        "pgrls_version": _pkg_version("pgrls"),
        "postgres_image": POSTGRES_IMAGE,
    }

    json.dump(record, sys.stdout)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":  # pragma: no cover - module entrypoint
    sys.exit(main())
