"""The thin FastMCP layer for `pgrls mcp` — isolate ALL FastMCP API here.

This is the only pgrls module that imports `fastmcp`; everything substantive
lives in `pgrls.schema_sources` (schema resolution / DDL parsing) and the
existing pgrls internals (`rules`, `verify`, `formatters`). Importing this
module pulls in the optional `fastmcp` extra, so `pgrls.cli` imports it lazily,
inside `pgrls mcp` — a plain `pip install pgrls` never touches FastMCP.

SAFETY POSTURE — NEVER MUTATES A DATABASE (hard constraint):

* The server NEVER executes a statement that changes database state. It exposes
  `lint`, `verify`, `explain_rule`, `list_rules` (analysis), plus `fix` and
  `generate`, which are **emit-only**: they RETURN remediation / scaffold SQL as
  text for the agent to review and run itself — they never apply it. The actual
  mutation paths (`fix --apply`, `generate --apply`, `diff --apply`,
  `verify --probe`) remain deliberately unexposed; an agent that wants to apply
  the returned SQL does so through its own reviewed channel.
* `database_url` is treated as a credential: it is never logged, never echoed
  back, and database errors are sanitized (see `schema_sources`). The
  introspection it triggers — on every tool, including `fix` / `generate` —
  issues only SELECTs against the catalogs over a short-lived connection.
* Every tool wraps its body so any failure returns a STRUCTURED error object
  (`{"error": {"kind": ..., "message": ...}}`) rather than raising — a raised
  exception would otherwise break the stdio JSON-RPC loop.
"""
from __future__ import annotations

import functools
from collections.abc import Callable
from typing import Any

from fastmcp import FastMCP

from pgrls.config import Config
from pgrls.schema_sources import (
    SchemaSourceError,
    resolve_schema,
    schema_source_warnings,
)

mcp: FastMCP = FastMCP("pgrls")

# Structured-error kinds the tools may return. Mirrors the spec's contract; the
# value is echoed in `{"error": {"kind": ...}}` so an agent can branch on it.
_ERROR_KINDS = frozenset(
    {
        "bad_sql",
        "db_unreachable",
        "unknown_rule",
        "no_schema_source",
        "multiple_schema_sources",
        "z3_unavailable",
    }
)


def _error(kind: str, message: str) -> dict[str, Any]:
    """Build the structured error payload returned (never raised) by a tool."""
    assert kind in _ERROR_KINDS, f"unknown error kind {kind!r}"
    return {"error": {"kind": kind, "message": message}}


def _safe_tool(fn: Callable[..., dict[str, Any]]) -> Callable[..., dict[str, Any]]:
    """Wrap a tool body so it returns a structured error instead of raising.

    A raised exception inside a tool would propagate into the FastMCP stdio
    loop; the contract is that a diagnostic tool always returns a value. Known
    failure shapes map to their structured `kind`; any unexpected exception is
    surfaced as `bad_sql` with the exception text (the most likely cause for the
    SQL-analysis tools is malformed input) so the agent still gets a value, not
    a crash.
    """

    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> dict[str, Any]:
        try:
            return fn(*args, **kwargs)
        except SchemaSourceError as exc:
            return _error(exc.kind, exc.message)
        except Exception as exc:  # noqa: BLE001 — never let the stdio loop die
            return _error("bad_sql", f"{type(exc).__name__}: {exc}")

    return wrapper


# ---------------------------------------------------------------------------
# Catalog tools (no schema needed)
# ---------------------------------------------------------------------------


@_safe_tool
def list_rules(config_path: str | None = None) -> dict[str, Any]:
    """List the pgrls rule catalog (id, severity, title, fixable flag).

    Returns ``{pgrls_version, count, rules: [...]}`` — the same payload
    ``pgrls explain --format json`` prints. Pass ``config_path`` to also load
    project-specific ``[lint].extra_rules`` from a ``pgrls.toml``; omit it for
    the built-in catalog (no database, no config needed).
    """
    # Imported here (not at module top) to keep this module's import light and
    # to reuse the CLI's catalog-rendering helpers verbatim — single source of
    # truth for the catalog shape.
    from pgrls import cli

    rules = _rules_for(config_path)
    payload = cli._render_catalog_json(rules, fixable_ids=cli._fixable_rule_ids())
    # `_render_catalog_json` returns a JSON string (the CLI contract); parse it
    # back to a dict so FastMCP serializes a structured object, not a string.
    import json

    return dict(json.loads(payload))


@_safe_tool
def explain_rule(rule_id: str) -> dict[str, Any]:
    """Explain a single pgrls rule: id, severity, title, fixable, and reference.

    ``reference`` is the rule's full documentation body (what it flags, why,
    how detection works, scope, how to allowlist). An unknown ``rule_id``
    returns a structured ``unknown_rule`` error.
    """
    from pgrls import cli
    from pgrls.rules import all_rules

    normalized = rule_id.strip().upper()
    rule = next((r for r in all_rules() if r.id == normalized), None)
    if rule is None:
        known = ", ".join(r.id for r in all_rules())
        return _error(
            "unknown_rule",
            f"unknown rule {rule_id!r}. Known rules: {known}.",
        )
    import json

    payload = cli._render_rule_json(rule, fixable_ids=cli._fixable_rule_ids())
    return dict(json.loads(payload))


# ---------------------------------------------------------------------------
# Analysis tools (resolve a schema from sql / database_url / snapshot)
# ---------------------------------------------------------------------------


@_safe_tool
def lint(
    sql: str | None = None,
    database_url: str | None = None,
    snapshot: str | None = None,
    schemas: list[str] | None = None,
    rules: list[str] | None = None,
    exclude_rules: list[str] | None = None,
    min_severity: str | None = None,
) -> dict[str, Any]:
    """Lint Postgres RLS policies for security / hygiene issues.

    Provide EXACTLY ONE schema source:

    * ``sql`` — raw DDL (``CREATE TABLE`` / ``ALTER TABLE … ENABLE ROW LEVEL
      SECURITY`` / ``CREATE POLICY`` / ``GRANT``) analyzed OFFLINE, no database.
      The headline use: lint the DDL you just wrote.
    * ``database_url`` — a live Postgres connection (read-only introspection).
    * ``snapshot`` — a path to a ``pgrls snapshot`` JSON.

    ``schemas`` selects which schemas to scan (default ``["public"]``).
    ``rules`` / ``exclude_rules`` restrict the rule set (rule ids, e.g.
    ``["SEC004"]``). ``min_severity`` (``error`` / ``warning`` / ``info``)
    filters the returned findings.

    Returns ``{schema_source, summary, violations: [...], warnings: [...]}``.
    IMPORTANT: on the ``sql`` path, ``warnings`` notes that catalog-only rules
    cannot fire — so an empty ``violations`` list is NOT a proof of safety.
    """
    import json

    from pgrls.formatters.json import format_json
    from pgrls.violations import coerce_severity, is_at_or_above

    schema, source, snapshot_version = resolve_schema(
        sql=sql,
        database_url=database_url,
        snapshot=snapshot,
        schemas=tuple(schemas) if schemas else None,
    )

    rule_filter, exclude_filter, err = _resolve_rule_filters(rules, exclude_rules)
    if err is not None:
        return err

    violations = _run_lint(
        schema, rule_filter=rule_filter, exclude_filter=exclude_filter
    )

    if min_severity is not None:
        try:
            floor = coerce_severity(min_severity)
        except ValueError as exc:
            return _error("bad_sql", str(exc))
        violations = [v for v in violations if is_at_or_above(v.severity, floor)]

    # Reuse lint's JSON violation shape verbatim (the public CI contract), then
    # layer the MCP-only `schema_source` + `warnings` keys on top.
    base = json.loads(format_json(violations))
    return {
        "schema_source": source,
        "summary": base["summary"],
        "violations": base["violations"],
        "warnings": schema_source_warnings(source, snapshot_version=snapshot_version),
    }


@_safe_tool
def verify(
    sql: str | None = None,
    database_url: str | None = None,
    snapshot: str | None = None,
    schemas: list[str] | None = None,
    mode: str = "anon",
    auth_functions: list[str] | None = None,
    anon_roles: list[str] | None = None,
    strict: bool = False,
) -> dict[str, Any]:
    """Prove RLS tenant isolation with Z3 — and show a leaking row when it fails.

    For every RLS-enabled table, returns one of three honest verdicts per
    policy: ``isolated`` (PROVEN), ``leak`` (with a concrete counterexample
    witness), or ``unverified`` (Z3 can't decide, or there's no single scoping
    equality). Four threat models via ``mode``:

    * ``anon`` (default) — can an anonymous session (JWT-less, or the Supabase
      anon-key caller whose ``auth.role()`` is 'anon') read any row?
    * ``cross-tenant`` — can a session authenticated as one tenant read a
      different tenant's row?
    * ``write`` — can such a session WRITE a row stamped for another tenant?
    * ``escalation`` — proves the static SEC048 reachability finding: can a
      low-trust role that is a member of a table's owner bypass RLS on the
      owner's not-``FORCE``'d tables (and the SEC042 anon-callable SECDEF case)?
      Needs a ``database_url`` or a snapshot ≥ v21 (the role/owner graph is
      introspected); an ``sql`` source has no role graph, so it finds nothing.

    Provide EXACTLY ONE schema source (``sql`` / ``database_url`` / ``snapshot``
    — same semantics as ``lint``). ``auth_functions`` extends the default auth
    helper set (``auth.uid``/``role``/``jwt``, ``current_setting``).
    ``anon_roles`` names the roles an ``anon`` proof treats as anonymous —
    default ``["anon", "PUBLIC"]``; set it (e.g. ``["web_anon"]``) for a project
    whose unauthenticated role has a different name, or a ``TO <that role>``
    leak will be mis-proven ``isolated`` against a live DB.
    ``strict`` is advisory metadata here (the server reports verdicts; it does
    not set a process exit code).

    Returns ``{schema_source, mode, strict, summary, tables: [...],
    warnings: [...]}``.
    """
    import json

    from pgrls.verify import DEFAULT_AUTH_FUNCTIONS, build_verification
    from pgrls.verify import render_json as verify_render_json

    if mode not in ("anon", "cross-tenant", "write", "escalation"):
        return _error(
            "bad_sql",
            f"unknown verify mode {mode!r}. Use 'anon', 'cross-tenant', "
            "'write', or 'escalation'.",
        )

    schema, source, snapshot_version = resolve_schema(
        sql=sql,
        database_url=database_url,
        snapshot=snapshot,
        schemas=tuple(schemas) if schemas else None,
    )

    auth = (
        set(DEFAULT_AUTH_FUNCTIONS) | {a.strip() for a in auth_functions if a.strip()}
        if auth_functions
        else None
    )
    # `anon` / `escalation` role-gate the prover to the anon-reachable role set;
    # honor a project whose anonymous role isn't named `anon` (e.g. PostgREST's
    # `web_anon`) — parity with the CLI's `[lint.rules.SEC004].anon_roles`. `None`
    # keeps the default `{anon, PUBLIC}`. Normalized so `public` matches `PUBLIC`.
    resolved_anon: set[str] | None = None
    if anon_roles is not None:
        from pgrls.rules.sec004 import _parse_anon_roles

        try:
            resolved_anon = _parse_anon_roles({"anon_roles": anon_roles})
        except TypeError as exc:
            return _error("bad_sql", str(exc))

    try:
        verification = build_verification(schema, auth_functions=auth, mode=mode, anon_roles=resolved_anon)  # type: ignore[arg-type]
    except Exception as exc:  # noqa: BLE001
        # The Z3 path is a core dependency, so this is unlikely; still, surface
        # a clean structured error rather than crashing the stdio loop.
        return _error("z3_unavailable", f"could not run the verifier: {exc}")

    # Reuse verify's JSON payload shape verbatim (parity with `pgrls verify
    # --format json`), then add the MCP-only `schema_source` / `strict` /
    # `warnings` keys.
    base = json.loads(verify_render_json(verification))
    return {
        "schema_source": source,
        "mode": base["mode"],
        "strict": strict,
        "summary": base["summary"],
        "tables": base["tables"],
        "warnings": schema_source_warnings(source, snapshot_version=snapshot_version),
    }


# ---------------------------------------------------------------------------
# Remediation tools — EMIT-ONLY (return SQL text, never execute it)
# ---------------------------------------------------------------------------


@_safe_tool
def fix(
    sql: str | None = None,
    database_url: str | None = None,
    snapshot: str | None = None,
    schemas: list[str] | None = None,
    rules: list[str] | None = None,
    exclude_rules: list[str] | None = None,
) -> dict[str, Any]:
    """Emit auto-fix SQL for the mechanically-fixable RLS findings.

    The remediation counterpart of ``lint``: for every finding pgrls can fix
    mechanically (20 of the rules — SEC001/SEC002/SEC004/SEC006/SEC010/SEC011/
    SEC015/SEC017/SEC019/SEC020/SEC030/SEC031/SEC032/SEC044/PERF001/PERF003/
    PERF004/HYG003/VIEW001/VIEW002), returns the exact SQL that closes it.

    EMIT-ONLY: this returns SQL text for you to review and apply yourself — it
    never touches the database (the live path issues read-only introspection
    SELECTs only, same as ``lint``). Each fix is strictly remediating: pgrls's
    fixers only ever narrow access (close a leak / drop an inert policy / revoke
    an over-broad grant), never broaden it.

    Provide EXACTLY ONE schema source (``sql`` / ``database_url`` / ``snapshot``
    — same semantics as ``lint``). ``rules`` / ``exclude_rules`` restrict which
    rules' fixes are emitted (rule ids; non-fixable ids simply produce nothing).

    Returns ``{schema_source, count, fixes: [{rule_id, location, sql,
    description}], migration, warnings}``. ``migration`` is the same statements
    rendered as one copy-pasteable ``.sql`` file (header + body); it is ``""``
    when there is nothing to fix. As with ``lint``, on the ``sql`` path
    ``warnings`` notes that catalog-only rules cannot fire, so an empty
    ``fixes`` list is NOT a proof that the schema is clean.
    """
    from pgrls import __version__
    from pgrls.fixers import generate_fixes, render_migration

    schema, source, snapshot_version = resolve_schema(
        sql=sql,
        database_url=database_url,
        snapshot=snapshot,
        schemas=tuple(schemas) if schemas else None,
    )

    rule_filter, exclude_filter, err = _resolve_rule_filters(rules, exclude_rules)
    if err is not None:
        return err

    # `generate_fixes` validates each fixer's allowlist option with the rule's
    # strict parser; pass empty rule options (the server has no config-file
    # concept on this path) so every fixer runs with its defaults.
    fixes = generate_fixes(schema, {}, rule_filter=rule_filter)
    if exclude_filter:
        fixes = [f for f in fixes if f.rule_id not in exclude_filter]

    return {
        "schema_source": source,
        "count": len(fixes),
        "fixes": [
            {
                "rule_id": f.rule_id,
                "location": f.location,
                "sql": f.sql,
                "description": f.description,
            }
            for f in fixes
        ],
        "migration": (
            render_migration(fixes, tool_version=__version__) if fixes else ""
        ),
        "warnings": schema_source_warnings(source, snapshot_version=snapshot_version),
    }


@_safe_tool
def generate(
    sql: str | None = None,
    database_url: str | None = None,
    snapshot: str | None = None,
    schemas: list[str] | None = None,
    tenant_column: str | None = None,
    model: str = "tenant",
    convention: str = "app-guc",
    setting_name: str | None = None,
    auth_function: str = "auth.uid",
    role: str = "authenticated",
    restrictive: bool = True,
    tables: list[str] | None = None,
) -> dict[str, Any]:
    """Scaffold gold-standard RLS for unprotected multi-tenant / row-owner tables.

    For every table that has the discriminator column but no row security yet,
    emits ``ENABLE`` + ``FORCE ROW LEVEL SECURITY``, a permissive tenant- (or
    owner-) isolation policy, a restrictive floor, and a supporting index — SQL
    that lints clean by construction. The headline use for an agent: stop
    hand-writing RLS, generate the correct shape and lint it.

    EMIT-ONLY: returns SQL text for you to review and apply yourself; it never
    touches the database (the live path is read-only introspection, same as
    ``lint``). A table that already has ANY policy is skipped (never clobbered)
    and reported in ``skipped``.

    Provide EXACTLY ONE schema source (``sql`` / ``database_url`` / ``snapshot``).
    Knobs (all optional): ``tenant_column`` (the discriminator column; defaults
    to ``user_id`` for ``model='owner'`` else ``tenant_id``); ``model``
    (``tenant`` | ``owner``); ``convention`` (``app-guc`` | ``postgrest`` |
    ``supabase``) selecting the session-value source — ``supabase`` is for the
    ``owner`` model only (it emits ``(SELECT auth.uid())``); ``setting_name`` to
    override the derived GUC/claim; ``auth_function`` (owner/supabase model;
    default ``auth.uid``); ``role`` (default ``authenticated`` — never
    ``PUBLIC``); ``restrictive`` (emit the restrictive floor, default true);
    ``tables`` for per-table column overrides, each ``"schema.table:column"``.

    Returns ``{schema_source, count, statements: [{rule_id, location, sql,
    description}], migration, skipped: [{table, reason}], notes, warnings}``.
    ``migration`` is the statements as one copy-pasteable ``.sql`` file (``""``
    when nothing matched).
    """
    from pgrls import __version__
    from pgrls.fixers import render_migration
    from pgrls.generate import GenerateOptions, plan_generation

    if model not in ("tenant", "owner"):
        return _error(
            "bad_sql", f"unknown model {model!r}. Use 'tenant' or 'owner'."
        )
    if convention not in ("app-guc", "postgrest", "supabase"):
        return _error(
            "bad_sql",
            f"unknown convention {convention!r}. Use 'app-guc', 'postgrest', "
            "or 'supabase'.",
        )
    # Parity with the CLI: `supabase` is the owner-model convention (it emits
    # `(SELECT auth.uid())`); pairing it with the tenant model would scaffold a
    # policy comparing a tenant key to a user id — silently-wrong RLS.
    if convention == "supabase" and model != "owner":
        return _error(
            "bad_sql",
            "convention 'supabase' is for model 'owner' (it emits "
            "(SELECT auth.uid())). For tenant scoping use 'app-guc' or "
            "'postgrest'.",
        )
    # The discriminator column default depends on the model (matches the CLI):
    # `user_id` for the owner model, `tenant_id` otherwise.
    resolved_column = tenant_column or (
        "user_id" if model == "owner" else "tenant_id"
    )

    schema, source, snapshot_version = resolve_schema(
        sql=sql,
        database_url=database_url,
        snapshot=snapshot,
        schemas=tuple(schemas) if schemas else None,
    )

    from pgrls import cli

    options = GenerateOptions(
        tenant_column=resolved_column,
        model="owner" if model == "owner" else "tenant",
        convention=convention,  # type: ignore[arg-type]
        setting_name=setting_name,
        auth_function=auth_function,
        role=role,
        restrictive=restrictive,
        tables=cli._parse_generate_tables(tuple(tables) if tables else ()),
    )

    try:
        result = plan_generation(schema, options)
    except ValueError as exc:
        # session_predicate rejects an unsafe / unknown column type before it
        # reaches a `::<type>` cast — surface it as a clean structured error.
        return _error("bad_sql", str(exc))

    statements = list(result.statements)
    return {
        "schema_source": source,
        "count": len(statements),
        "statements": [
            {
                "rule_id": f.rule_id,
                "location": f.location,
                "sql": f.sql,
                "description": f.description,
            }
            for f in statements
        ],
        "migration": (
            render_migration(statements, tool_version=__version__)
            if statements
            else ""
        ),
        "skipped": [
            {"table": qname, "reason": reason}
            for qname, reason in result.skipped
        ],
        "notes": list(result.notes),
        "warnings": schema_source_warnings(source, snapshot_version=snapshot_version),
    }


# ---------------------------------------------------------------------------
# Shared helpers (kept module-private; the tools above are the public surface)
# ---------------------------------------------------------------------------


def _rules_for(config_path: str | None) -> list[Any]:
    """Resolve the catalog rule list — built-ins, plus extras if a config path."""
    from pgrls.rules import all_rules

    if config_path is None:
        return list(all_rules())
    from pgrls import cli
    from pgrls.config import ConfigError, load_config

    try:
        config = load_config(config_path)
    except ConfigError as exc:
        raise SchemaSourceError("bad_sql", str(exc)) from exc
    return cli._runtime_rules(config)


def _resolve_rule_filters(
    rules: list[str] | None, exclude_rules: list[str] | None
) -> tuple[set[str] | None, set[str] | None, dict[str, Any] | None]:
    """Validate `rules` / `exclude_rules` against the known built-in catalog.

    Returns ``(rule_filter, exclude_filter, error)``. On an unknown id the
    error dict is set (structured ``unknown_rule``) and the caller returns it.
    """
    from pgrls.rules import all_rules

    known = {r.id for r in all_rules()}
    rule_filter: set[str] | None = None
    exclude_filter: set[str] | None = None

    if rules:
        rule_filter = {r.strip().upper() for r in rules if r.strip()}
        unknown = sorted(rule_filter - known)
        if unknown:
            return None, None, _error(
                "unknown_rule",
                f"unknown rule(s) in `rules`: {', '.join(unknown)}.",
            )
    if exclude_rules:
        exclude_filter = {r.strip().upper() for r in exclude_rules if r.strip()}
        unknown = sorted(exclude_filter - known)
        if unknown:
            return None, None, _error(
                "unknown_rule",
                f"unknown rule(s) in `exclude_rules`: {', '.join(unknown)}.",
            )
    return rule_filter, exclude_filter, None


def _run_lint(
    schema: Any,
    *,
    rule_filter: set[str] | None,
    exclude_filter: set[str] | None,
) -> list[Any]:
    """Run the rule registry over `schema` — reuses `cli._run_rules`.

    Uses a default `Config()` (the server has no config-file concept on the
    analysis path); `_run_rules` then runs the built-in registry with the given
    include / exclude filters.
    """
    from pgrls import cli

    return cli._run_rules(
        schema,
        config=Config(),
        rule_filter=rule_filter,
        exclude_filter=exclude_filter or None,
    )


# Register the tools. `mcp.tool(fn)` returns `fn` unchanged in FastMCP, so the
# module-level functions stay directly callable (the test suite calls them
# without a live MCP client).
mcp.tool(list_rules)
mcp.tool(explain_rule)
mcp.tool(lint)
mcp.tool(verify)
mcp.tool(fix)
mcp.tool(generate)


def run_stdio() -> None:
    """Run the pgrls MCP server over stdio (the transport AI agents use).

    Blocks until the client disconnects. `show_banner=False` keeps stdout clean
    for the JSON-RPC stream (FastMCP's banner is cosmetic and would otherwise
    risk corrupting the protocol on stdout).
    """
    mcp.run(transport="stdio", show_banner=False)
