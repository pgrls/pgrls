"""SEC040 — Write-side policy WITH CHECK drops USING's row scope.

A row-scoping policy keys visibility off a tenant/owner discriminator
compared to a per-request auth value:

```sql
CREATE POLICY tenant_rw ON documents
    FOR ALL TO authenticated
    USING      (tenant_id = current_setting('app.tenant_id', true)::int)
    WITH CHECK (status IN ('draft', 'published'));   -- tenant_id NOT re-asserted!
```

`USING` restricts which existing rows a caller may *read* and update
(`tenant_id` must be theirs). `WITH CHECK` validates the *new* row image
on INSERT/UPDATE. Postgres treats the two clauses independently: an
explicit `WITH CHECK` **replaces** the implicit reuse of `USING` that an
omitted clause would get. So when the explicit `WITH CHECK` binds **no**
tenant/owner column at all — it validates only non-identity columns like
`status` — an authenticated caller can `UPDATE documents SET tenant_id =
<some other tenant>` and the write passes: the row **migrates out of the
caller's tenant**, a cross-tenant (or cross-owner) write/escape. The same
gap lets a `FOR ALL` policy INSERT a row stamped with another tenant's id.

An *asymmetric* policy that binds a **different** identity column on the
write side — the common "read your team (`USING team_id = …`), write rows
you own (`WITH CHECK user_id = …`)" shape — is a deliberate ownership
model and is **not** flagged: the write side still carries a tenant/owner
binding. SEC040 fires only when the write side carries no identity binding
whatsoever.

This is the asymmetry the existing write-side rules miss:

* **SEC006** fires when `WITH CHECK` is *absent*. There it is present —
  and an explicit clause turns OFF the USING-reuse that SEC006 relies on
  to call the omitted shape "closed", so the scope is genuinely dropped.
* **SEC028** fires when `WITH CHECK` is constant `true` (open write, no
  restrictive USING). **SEC020** fires on the constant-`true` WITH CHECK
  *with* a restrictive USING. SEC040 cedes both constant-`true` cases to
  them; it covers the subtler shape where `WITH CHECK` is a *real*
  predicate that simply forgot the tenant key.

SEC040 fires when a **permissive** `UPDATE`/`ALL` policy has a `USING`
that scopes by a discriminator equality `col = <auth value>` and an
**explicit, non-constant** `WITH CHECK` that binds **no** identity/
discriminator column to an auth value. Detection reuses SEC030's
`_scoping_columns` (the same direct-operand, own-column, fromless-sub-
select-aware scoping-equality extraction), run over `USING` and over
`WITH CHECK` separately: it fires when `USING` yields a scope and
`WITH CHECK` yields none.

Scope (intentional, kept tight to stay low-noise):

* **Permissive UPDATE/ALL only.** `INSERT` carries no `USING`, so there
  is no read-scope to drop (an open INSERT WITH CHECK is SEC028's). A
  `SELECT`/`DELETE` policy has no `WITH CHECK`. Restrictive policies
  AND-combine and are SEC006/SEC028's restrictive framing, not an escape
  on their own — out of scope, as in those rules.
* **Explicit, non-constant WITH CHECK.** An *omitted* WITH CHECK reuses
  `USING` (scope preserved — SEC006's domain for the genuinely-open
  shapes). A constant-`true` WITH CHECK is SEC028/SEC020; a constant-
  `false` one blocks every write (no migration is possible), so both
  literal-boolean shapes are skipped.
* **Discriminator equality, identity column names only.** Reusing
  SEC030's extraction (with `null_safe=True`), a scalar `col = <auth
  value>` or the NULL-safe `col IS NOT DISTINCT FROM <auth value>` on an
  identity/discriminator-named own column (`tenant_id`, `user_id`, … —
  the SEC021 default set, overridable via `identity_columns`) is treated
  as a scope/binding. A non-identity column or a non-equality comparison
  is not a row scope, so it never trips the rule. Recognizing the NULL-
  safe form on the write side matters specifically here: it is a
  *stronger* re-assertion than `=`, so a hardened `WITH CHECK (tenant_id
  IS NOT DISTINCT FROM …)` must clear the finding, not trip it.
* **Any write-side identity binding clears it.** If `WITH CHECK` binds
  *any* identity column to an auth value — including one `USING` does not
  use — the asymmetry is treated as an intentional ownership model (the
  "read your team, write your own" shape) and the policy is not flagged.
  SEC040 fires only when the write side carries no identity binding at
  all. This deliberately under-reports the rarer "write side binds a
  *different* tenant level than the read side" case in exchange for not
  flagging the common, legitimate asymmetric pattern.

Known limitation: SEC040 reasons about a single policy. If a sibling
**restrictive** policy on the same table re-imposes the tenant predicate
in its own `WITH CHECK`, the migration is in practice blocked even though
the permissive policy dropped the scope; SEC040 still flags the permissive
policy (re-asserting the scope on the policy that owns the read-side is
the clearer fix). Allowlist by qualified policy id when the column is
genuinely immutable (enforced by a `BEFORE UPDATE` trigger or a generated
column) or a restrictive floor covers it:

```toml
[lint.rules.SEC040]
allowlist = ["public.documents.tenant_rw"]
```

Configure the auth-context function set and the identity-column set the
same way SEC030 does (both replace the default):

```toml
[lint.rules.SEC040]
auth_functions = ["auth.uid", "current_setting", "request.jwt.claim"]
identity_columns = ["tenant_id", "workspace", "region"]
```

Severity: warning. No auto-fix — the correct re-assertion is the
application's own tenant/ownership equality (the one `USING` already
carries), but transplanting a `USING` sub-expression into `WITH CHECK`
across casts and boolean structure is exactly the kind of rewrite that
needs a human eye, so SEC040 reports rather than edits.
"""
from __future__ import annotations

from typing import Any

from pgrls.ast_utils import is_literal_false, is_literal_true
from pgrls.model import Policy, Schema, policy_id
from pgrls.rules._allowlist import parse_policy_id_allowlist
# Reuse SEC021's identity/discriminator column-name set and SEC030's
# scoping-equality extraction + auth-function default, so SEC040's notion
# of "a tenant/owner scope" cannot drift from the rule (SEC030) and fixer
# that already share them. Same private-import pattern fixers/sec030.py
# uses to reuse `_scoping_columns`.
from pgrls.rules.sec021 import _DEFAULT_IDENTITY_COLUMNS
from pgrls.rules.sec030 import _DEFAULT_AUTH_FUNCTIONS, _scoping_columns
from pgrls.violations import Severity, Violation

# UPDATE and ALL are the only commands with BOTH a USING (read scope) and
# a WITH CHECK (write image) — the precondition for a drop to matter.
# INSERT has no USING; SELECT/DELETE have no WITH CHECK.
_SCOPED_WRITE_COMMANDS: frozenset[str] = frozenset({"UPDATE", "ALL"})


def _parse_auth_functions(options: dict[str, Any]) -> set[str]:
    raw = options.get("auth_functions")
    if raw is None:
        return set(_DEFAULT_AUTH_FUNCTIONS)
    if not isinstance(raw, list) or not all(isinstance(s, str) for s in raw):
        raise TypeError(
            "[lint.rules.SEC040].auth_functions must be a list of "
            'strings (e.g. ["auth.uid", "current_setting"]).'
        )
    return set(raw)


def _parse_identity_columns(options: dict[str, Any]) -> set[str]:
    raw = options.get("identity_columns")
    if raw is None:
        return set(_DEFAULT_IDENTITY_COLUMNS)
    if not isinstance(raw, list) or not all(isinstance(s, str) for s in raw):
        raise TypeError(
            "[lint.rules.SEC040].identity_columns must be a list of "
            'column names, e.g. ["tenant_id", "org_id"].'
        )
    # Case-fold: Postgres lowercases unquoted identifiers, and the
    # column-name comparison inside _scoping_columns lowercases too.
    return {s.lower() for s in raw}


class SEC040:
    id: str = "SEC040"
    severity: Severity = "warning"
    title: str = "Write-side policy WITH CHECK drops USING's row scope"

    def check(
        self, schema: Schema, options: dict[str, Any]
    ) -> list[Violation]:
        auth_functions = _parse_auth_functions(options)
        identity_columns = _parse_identity_columns(options)
        allowlist = parse_policy_id_allowlist("SEC040", options)
        out: list[Violation] = []
        for table in schema.tables:
            for policy in table.policies:
                if not policy.permissive:
                    continue
                if policy.command not in _SCOPED_WRITE_COMMANDS:
                    continue
                # An explicit WITH CHECK is required. When omitted on
                # UPDATE/ALL, Postgres reuses USING as the implicit WITH
                # CHECK — the scope is preserved (SEC006 owns the
                # genuinely-open shapes). An explicit clause replaces that
                # reuse, so it must carry the scope itself.
                if policy.with_check_ast is None:
                    continue
                # Constant-true WITH CHECK is the open-write footgun SEC028
                # (no restrictive USING) / SEC020 (restrictive USING)
                # already own; constant-false blocks every write, so no
                # migration is possible. Cede both literal-boolean shapes.
                if is_literal_true(policy.with_check_ast) or is_literal_false(
                    policy.with_check_ast
                ):
                    continue
                if policy.using_ast is None:
                    continue
                using_scope = _scoping_columns(
                    policy.using_ast,
                    table,
                    auth_functions,
                    identity_columns,
                    null_safe=True,
                )
                if not using_scope:
                    continue
                # Fire only when the WITH CHECK binds NO tenant/owner column at
                # all. If it binds ANY identity column to an auth value — even a
                # *different* one than USING scopes by — treat the asymmetry as
                # an intentional read-scope / write-own pattern (the common
                # "read your team (USING team_id = …), write rows you own (WITH
                # CHECK user_id = …)" shape) and stay silent. The genuine hole
                # is a write side with no ownership binding whatsoever, where a
                # row can be written or migrated with any tenant AND any owner.
                check_scope = _scoping_columns(
                    policy.with_check_ast,
                    table,
                    auth_functions,
                    identity_columns,
                    null_safe=True,
                )
                if check_scope:
                    continue
                dropped = sorted(using_scope)
                pid = policy_id(table, policy)
                if pid in allowlist:
                    continue
                out.append(
                    Violation(
                        rule_id="SEC040",
                        severity=self.severity,
                        title=self.title,
                        message=self._message(table.qualified_name, policy, dropped),
                        location=pid,
                    )
                )
        return out

    @staticmethod
    def _message(qualified_name: str, policy: Policy, dropped: list[str]) -> str:
        cols = ", ".join(repr(c) for c in dropped)
        plural = "s" if len(dropped) > 1 else ""
        return (
            f"Permissive {policy.command} policy {policy.name!r} on "
            f"{qualified_name} scopes row access by the discriminator "
            f"column{plural} {cols} in USING, but its WITH CHECK pins no "
            f"tenant/owner column to the caller. A write is therefore not "
            f"constrained to the caller's {cols}, so a row can be created or "
            "moved outside their tenant/owner scope (cross-scope row "
            f"migration). Add the same `{dropped[0]} = <session value>` "
            "equality USING uses to WITH CHECK, or allowlist this policy in "
            "[lint.rules.SEC040] if the column is immutable (enforced by a "
            "trigger or generated column) or a restrictive floor covers the "
            "write side."
        )
