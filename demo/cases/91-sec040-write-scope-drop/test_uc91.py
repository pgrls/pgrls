"""Use case 91: write-side scope drop — SEC040."""
from __future__ import annotations


def test_uc91_scope_dropping_policy_fires_sec040(lint_output: str) -> None:
    # USING scopes by tenant_id but the explicit WITH CHECK validates only
    # status, so a caller can UPDATE a row to change tenant_id and migrate
    # it cross-tenant. SEC040 (warning) fires on the live introspected
    # policy.
    assert (
        "SEC040  app.uc91_documents.uc91_documents_rw\n"
        in lint_output
    )


def test_uc91_scope_reasserting_policy_does_not_fire_sec040(
    lint_output: str,
) -> None:
    # SEC040's defining boundary: when WITH CHECK re-asserts the same tenant
    # scope USING enforces, the write side is closed and SEC040 stays SILENT.
    # Pins the exemption through the production introspection path (the unit
    # tests pin it on hand-built ASTs).
    assert (
        "SEC040  app.uc91_documents_fixed.uc91_documents_fixed_rw\n"
        not in lint_output
    )
