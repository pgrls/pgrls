"""Live-DB end-to-end for `pgrls generate` — the gold-standard guarantee.

Generate RLS for bare tenant tables, apply it, then lint: the result must
have ZERO findings. Also pins idempotency (a second run does nothing) and
the never-clobber rule (a table that already has a policy is skipped).
"""
from __future__ import annotations

import json

import psycopg
import pytest
from click.testing import CliRunner

from pgrls.cli import main


@pytest.fixture
def ensure_authenticated_role(pg_conn: psycopg.Connection) -> None:
    # Generated policies target `TO authenticated`; the role must exist for
    # CREATE POLICY to apply. Roles are cluster-global (not reset with the
    # schema), so create it idempotently and leave it — a plain NOLOGIN
    # role is benign for other tests.
    with pg_conn.cursor() as cur:
        cur.execute("SELECT 1 FROM pg_roles WHERE rolname = 'authenticated'")
        if cur.fetchone() is None:
            cur.execute("CREATE ROLE authenticated")


def _lint_violations(pg_url: str) -> list[dict]:
    result = CliRunner().invoke(
        main, ["lint", "--database-url", pg_url, "--format", "json"]
    )
    # exit 0 (no findings) or 1 (findings) are both "ran fine"; 2 is a tool
    # error. Parse the JSON either way.
    assert result.exit_code in (0, 1), result.output
    return json.loads(result.output)["violations"]


def test_generate_then_lint_is_clean(
    pg_url: str, apply_sql, ensure_authenticated_role
) -> None:
    apply_sql(
        """
        CREATE TABLE public.posts (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id uuid NOT NULL,
            body text
        );
        CREATE TABLE public.notes (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id uuid NOT NULL,
            title text
        )
        """
    )
    runner = CliRunner()

    # Bare tables: lint should currently complain (RLS off etc.).
    assert _lint_violations(pg_url), "expected findings before generate"

    gen = runner.invoke(
        main, ["generate", "--database-url", pg_url, "--apply"]
    )
    assert gen.exit_code == 0, gen.output
    assert "applied" in gen.output

    # The gold-standard guarantee: generated RLS lints with ZERO findings.
    remaining = _lint_violations(pg_url)
    assert remaining == [], remaining


def test_generate_postgrest_convention_lints_clean(
    pg_url: str, apply_sql, ensure_authenticated_role
) -> None:
    # The other convention must also hold the zero-findings guarantee — the
    # request.jwt.claim.* predicate is otherwise never proven lint-clean
    # against a real Postgres.
    apply_sql(
        "CREATE TABLE public.posts ("
        "id uuid PRIMARY KEY DEFAULT gen_random_uuid(), "
        "tenant_id uuid NOT NULL)"
    )
    gen = CliRunner().invoke(
        main,
        [
            "generate",
            "--database-url",
            pg_url,
            "--apply",
            "--convention",
            "postgrest",
        ],
    )
    assert gen.exit_code == 0, gen.output
    assert _lint_violations(pg_url) == []


def test_generate_partitioned_table_no_dup_index_lints_clean(
    pg_url: str, apply_sql, ensure_authenticated_role
) -> None:
    # A declarative-partitioned tenant table: generate must set up the
    # PARENT only (its index cascades to children, its RLS covers
    # parent-routed queries) and skip the children — so each child has
    # exactly ONE tenant_id index (the cascaded one, not a duplicate), and
    # the whole thing lints clean.
    apply_sql(
        """
        CREATE TABLE public.events (
            id uuid NOT NULL DEFAULT gen_random_uuid(),
            tenant_id uuid NOT NULL,
            created_at timestamptz NOT NULL DEFAULT now()
        ) PARTITION BY RANGE (created_at);
        CREATE TABLE public.events_2025 PARTITION OF public.events
            FOR VALUES FROM ('2025-01-01') TO ('2026-01-01');
        CREATE TABLE public.events_2026 PARTITION OF public.events
            FOR VALUES FROM ('2026-01-01') TO ('2027-01-01')
        """
    )
    gen = CliRunner().invoke(
        main, ["generate", "--database-url", pg_url, "--apply"]
    )
    assert gen.exit_code == 0, gen.output
    # Parent set up; children reported as skipped, pointing at the parent.
    assert "skipped public.events_2025" in gen.output
    assert "partition of public.events" in gen.output

    # Gold-standard guarantee holds for the partitioned shape.
    assert _lint_violations(pg_url) == []

    # No duplicate index: each child carries exactly one tenant_id index
    # (cascaded from the parent's partitioned index), not two.
    with psycopg.connect(pg_url) as conn, conn.cursor() as cur:
        for child in ("events_2025", "events_2026"):
            cur.execute(
                "SELECT count(*) FROM pg_indexes WHERE schemaname = 'public' "
                "AND tablename = %s AND indexdef LIKE '%%tenant_id%%'",
                (child,),
            )
            row = cur.fetchone()
            assert row is not None and row[0] == 1, (
                f"{child} should have exactly one tenant_id index, "
                f"got {row[0] if row else None}"
            )


def test_generate_is_idempotent(
    pg_url: str, apply_sql, ensure_authenticated_role
) -> None:
    apply_sql(
        "CREATE TABLE public.posts ("
        "id uuid PRIMARY KEY DEFAULT gen_random_uuid(), "
        "tenant_id uuid NOT NULL)"
    )
    runner = CliRunner()
    first = runner.invoke(main, ["generate", "--database-url", pg_url, "--apply"])
    assert first.exit_code == 0, first.output
    # Second run: the table now has policies → nothing to generate.
    second = runner.invoke(main, ["generate", "--database-url", pg_url, "--apply"])
    assert second.exit_code == 0, second.output
    assert "nothing to generate" in second.output


def test_generate_skips_already_policied_table(
    pg_url: str, apply_sql, ensure_authenticated_role
) -> None:
    apply_sql(
        """
        CREATE TABLE public.posts (
            id uuid PRIMARY KEY,
            tenant_id uuid NOT NULL
        );
        ALTER TABLE public.posts ENABLE ROW LEVEL SECURITY;
        CREATE POLICY existing ON public.posts FOR SELECT TO authenticated
            USING (tenant_id = current_setting('app.tenant_id', true)::uuid)
        """
    )
    result = CliRunner().invoke(
        main, ["generate", "--database-url", pg_url]
    )
    assert result.exit_code == 0, result.output
    assert "skipped public.posts" in result.output
    assert "already has policies" in result.output


def test_generate_no_restrictive_lints_clean_except_sec007_advisory(
    pg_url: str, apply_sql, ensure_authenticated_role
) -> None:
    # With --no-restrictive the only remaining finding is SEC007 (info,
    # "all policies permissive") — exactly the floor it opted out of.
    apply_sql(
        "CREATE TABLE public.posts ("
        "id uuid PRIMARY KEY DEFAULT gen_random_uuid(), "
        "tenant_id uuid NOT NULL)"
    )
    gen = CliRunner().invoke(
        main,
        ["generate", "--database-url", pg_url, "--apply", "--no-restrictive"],
    )
    assert gen.exit_code == 0, gen.output
    rule_ids = {v["rule_id"] for v in _lint_violations(pg_url)}
    assert rule_ids <= {"SEC007"}, rule_ids
