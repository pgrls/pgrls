# Writing a new pgrls rule

A worked tutorial for contributors. By the end you'll have a complete
rule (module + tests + fixture + docs) of the same shape as every
SEC/PERF/HYG/VIEW rule already in the catalogue.

For the user-facing rule reference, see [`AGENTS.md`](../AGENTS.md).
For the project-wide checklist of contribution conventions, see
[`CONTRIBUTING.md`](../CONTRIBUTING.md).

## The shape of a rule

Every rule is a Python class that conforms to a `Protocol` declared
in [`src/pgrls/rules/__init__.py`](../src/pgrls/rules/__init__.py):

```python
class Rule(Protocol):
    id: str            # e.g. "SEC024"
    severity: Severity # "error" | "warning" | "info"
    title: str         # one-line human-facing title

    def check(
        self,
        schema: Schema,
        options: dict[str, Any],
    ) -> list[Violation]: ...
```

The runtime contract:

- `schema` is the live-database snapshot — `Schema(tables=...)` with
  every table, policy, role, view, trigger, index, and column the
  introspector found.
- `options` is the rule's own `[lint.rules.<ID>]` table from
  `pgrls.toml`, parsed into a plain `dict`.
- The method returns a list of `Violation` records. An empty list
  means the rule fired clean.

Rules never connect to a database themselves — introspection is the
CLI's job (`pgrls.introspect`), and rules consume the resulting
`Schema` model. This keeps unit tests fast (no DB needed) and makes
every rule deterministic.

## Anatomy of a real rule: SEC024

[`src/pgrls/rules/sec024.py`](../src/pgrls/rules/sec024.py) is a
small, complete rule worth reading end-to-end. Its job: flag a
policy whose `current_setting()` call names an *unqualified*
parameter (`tenant_id` instead of `app.tenant_id`).

```python
"""SEC024 — policy calls current_setting() with an unqualified parameter name.

<the docstring is the rule's CONTRACT: what it catches, what it
doesn't, when to allowlist, how it relates to neighbour rules>
"""
from __future__ import annotations

from typing import Any

from pglast.ast import A_Const, String, TypeCast

from pgrls.ast_utils import find_func_calls
from pgrls.model import Policy, Schema, Table
from pgrls.rules._allowlist import parse_policy_id_allowlist
from pgrls.violations import Severity, Violation


class SEC024:
    id: str = "SEC024"
    severity: Severity = "info"
    title: str = (
        "Policy calls current_setting() with an unqualified parameter name"
    )

    def check(
        self,
        schema: Schema,
        options: dict[str, Any],
    ) -> list[Violation]:
        allowlist = parse_policy_id_allowlist("SEC024", options)
        out: list[Violation] = []
        for table in schema.tables:
            for policy in table.policies:
                # ... walk policy.using_ast / policy.with_check_ast,
                #     emit Violations for unqualified names
                pass
        return out
```

Three things to internalise from SEC024:

1. **The docstring is load-bearing.** `pgrls explain SEC024` prints
   the module docstring to the user; this is the rule's user-facing
   documentation. Cover what fires, what doesn't, severity rationale,
   relationship to neighbour rules, and when to allowlist.
2. **All AST work goes through `pgrls.ast_utils` helpers.** Don't
   walk `pglast` nodes yourself — `find_func_calls`,
   `extract_column_refs`, `extract_range_vars`, `is_literal_true`
   etc. handle the gotchas (sub-link sublinks, `TypeCast` wrappers,
   `BoolExpr.args` lists, qualified function names like
   `pg_catalog.current_setting`).
3. **Allowlists go through `pgrls.rules._allowlist`.** Two
   canonical shapes: `parse_policy_id_allowlist` for "`schema.table.policy_name`"
   and `parse_table_ref_allowlist` for "`schema.table`". Don't roll
   your own parser.

## Step-by-step: ship a brand-new rule

Walk through what changes for a hypothetical new SEC033.

### 1. Pick the ID

Rule numbers are append-only. Find the next free number in the
right family by looking at [`src/pgrls/rules/`](../src/pgrls/rules/):

| Family   | Concern                                | Range used |
| -------- | -------------------------------------- | ---------- |
| `SEC`    | Security / correctness                 | 001–032    |
| `PERF`   | Performance / index health             | 001–004    |
| `HYG`    | Hygiene / naming                       | 001–003    |
| `VIEW`   | View-mediated RLS bypasses             | 001–004    |

Pick the next free integer in your family. Never reuse a deprecated
rule's number — keep history clean.

### 2. Write the rule module

Create `src/pgrls/rules/sec033.py`:

```python
"""SEC033 — <one-line statement of what fires>.

<2-3 paragraphs: the bug, why it's invisible to eyeball review, what
the detection actually looks at, what's intentionally out of scope.>

Severity: <info | warning | error>. <Why this severity.>

Allowlist by qualified policy ID (`schema.table.policy_name`) when
<...legitimate case...>.

Relationship to <neighbour-rule>: <how they differ>.
"""
from __future__ import annotations

from typing import Any

from pgrls.model import Schema
from pgrls.rules._allowlist import parse_policy_id_allowlist
from pgrls.violations import Severity, Violation


class SEC033:
    id: str = "SEC033"
    severity: Severity = "info"      # pick deliberately
    title: str = "<one-line title — appears in `lint` text output>"

    def check(
        self,
        schema: Schema,
        options: dict[str, Any],
    ) -> list[Violation]:
        allowlist = parse_policy_id_allowlist("SEC033", options)
        out: list[Violation] = []
        for table in schema.tables:
            for policy in table.policies:
                policy_id = (
                    f"{table.schema}.{table.name}.{policy.name}"
                )
                if policy_id in allowlist:
                    continue
                # YOUR DETECTION LOGIC HERE — read policy.using_ast,
                # policy.with_check_ast, table.columns,
                # table.column_details, table.indexes, etc.
                if self._policy_fires(policy, table):
                    out.append(self._violation(table, policy, policy_id))
        return out

    def _policy_fires(self, policy: Any, table: Any) -> bool:
        ...   # AST walk, schema lookup, …

    def _violation(
        self, table: Any, policy: Any, policy_id: str
    ) -> Violation:
        return Violation(
            rule_id=self.id,
            severity=self.severity,
            title=self.title,
            message=(
                f"Policy {policy.name!r} on {table.qualified_name} "
                "<concrete description of the specific instance> — "
                "<the remedy in one or two sentences, or an "
                "allowlist instruction if the case is legitimate>."
            ),
            location=policy_id,
        )
```

Severity guidance:

- **`error`** — almost always a bug; default `--fail-on=warning`
  makes it a CI-blocker.
- **`warning`** — likely a bug or a real performance problem; same
  CI-blocking treatment by default.
- **`info`** — a nudge; the rule's catch is correct but might be
  intentional (the user has the context). `--fail-on=warning`
  shows it but doesn't fail CI.

### 3. Register the rule

[`src/pgrls/rules/__init__.py`](../src/pgrls/rules/__init__.py) has a
private `_build_default_registry()` function that imports and
registers every rule lazily on the first call to `default_registry()`
/ `all_rules()`. Add yours:

```python
from pgrls.rules.sec033 import SEC033
# ...
def _build_default_registry() -> RuleRegistry:
    registry = RuleRegistry()
    # ...
    registry.register(SEC033())
    return registry
```

Keep the imports + registrations sorted by family then number — the
file's existing pattern.

### 4. Write the tests

Create `tests/rules/test_sec033.py`. Aim for **10–20 cases**: 5–8
fires-when shapes, 5–8 silent-when shapes, plus configuration / edge
cases.

```python
"""Unit tests for SEC033."""
from __future__ import annotations

import pglast

from pgrls.model import Policy, Schema, Table
from pgrls.rules.sec033 import SEC033


def _wrap(policy: Policy) -> Schema:
    return Schema(tables=(
        Table(
            schema="public",
            name="t",
            rls_enabled=True,
            force_rls=False,
            policies=(policy,),
        ),
    ))


def _policy(using: str, *, name: str = "p") -> Policy:
    using_ast = pglast.parse_sql(f"SELECT {using}")[0].stmt.targetList[0].val
    return Policy(
        name=name,
        command="SELECT",
        permissive=True,
        roles=("public",),
        using_sql=using,
        using_ast=using_ast,
        with_check_sql=None,
        with_check_ast=None,
    )


def test_sec033_fires_on_canonical_shape() -> None:
    schema = _wrap(_policy("<your canonical bad shape>"))
    [v] = SEC033().check(schema, options={})
    assert v.rule_id == "SEC033"


def test_sec033_silent_on_close_but_not_the_shape() -> None:
    schema = _wrap(_policy("<a shape that LOOKS similar but isn't>"))
    assert SEC033().check(schema, options={}) == []
```

Patterns to cover (mine the existing `tests/rules/test_sec*.py` for
templates):

- Fires on the canonical shape.
- Silent on close-but-different shapes.
- Silent when the policy is allowlisted by qualified ID.
- Silent / behaves correctly when `policy.using_ast is None` (no
  USING clause) or `policy.with_check_ast is None`.
- Silent when the table has no policies, or RLS is off — whichever
  predicate your rule wants.
- Fires once per offending policy (not per offending column, or
  whatever your aggregation is).
- Handles cross-schema / qualified / unqualified / 4-part column
  references (use `_own_table_column`-style resolution if relevant).

### 5. Wire into the combined fixture

[`tests/fixtures/all_bad.sql`](../tests/fixtures/all_bad.sql) is the
"this file deliberately trips every rule once" smoke fixture.
[`tests/test_cli.py`](../tests/test_cli.py)'s
`test_lint_fires_every_registered_rule_in_combined_fixture` asserts
that every registered rule fires at least once when pgrls lints the
file.

Add a SQL block to `all_bad.sql`:

```sql
-- SEC033 — <one-line description>.
CREATE TABLE allbad_sec033 (id INT, tenant_id INT);
ALTER TABLE allbad_sec033 ENABLE ROW LEVEL SECURITY;
CREATE POLICY allbad_sec033_pol ON allbad_sec033
    USING (<your canonical bad shape>);
```

Run `pytest tests/test_cli.py::test_lint_fires_every_registered_rule_in_combined_fixture`
to confirm.

### 6. Update the docs

Six files to touch (the last one is informational — no edit usually
needed, but worth knowing the tests exist):

| File                                  | Update                                                                 |
| ------------------------------------- | ---------------------------------------------------------------------- |
| [`AGENTS.md`](../AGENTS.md)           | Add a per-rule section under the right family with the docstring text. |
| [`README.md`](../README.md)           | Bump the rule count (`43 lint rules` → `44`) in the badges/intro/feature line. |
| [`pyproject.toml`](../pyproject.toml) | Same: the `description` field cites the rule count.                    |
| [`CHANGELOG.md`](../CHANGELOG.md)     | An `### Added` bullet under `[Unreleased]` with the rule + severity + one-line summary. |
| [`pgrls.schema.json`](../pgrls.schema.json) | If your rule has its own option name (`auth_functions`, `placeholder_words`, etc.) and you want it to surface in the JSON-schema example, the example in `pgrls.schema.json` may also need a touch. |
| [`tests/test_cli.py`](../tests/test_cli.py) | The `test_lint_fires_every_registered_rule_in_combined_fixture` test runs against `all_bad.sql`; with your new rule it'll auto-include yours. The `test_explain_covers_every_registered_rule` test counts the catalog — passes automatically as rules are added. No rule-count constant to bump. |

**Grep before you commit.** Repo-wide search for the previous rule
count (`43 lint rules`, `42 of 43`, etc.) is a cheap insurance
against missing a doc spot.

### 7. (Optional) Write a fixer

If your rule has a mechanical remediation, see
[`src/pgrls/fixers/`](../src/pgrls/fixers/) for the protocol and
existing examples (`sec031.py` is a short worked example, ~100 lines).
The fixer emits `DROP POLICY` / `CREATE POLICY` / `CREATE INDEX` SQL
ready for the next migration; register it in
[`src/pgrls/fixers/__init__.py`](../src/pgrls/fixers/__init__.py)'s
`default_fixers()` list.

Bump the auto-fixable count (`12 mechanically auto-fixable`) in the
same docs that cite the rule count.

### 8. Verify

```bash
.venv/bin/ruff check .
.venv/bin/mypy src/pgrls
.venv/bin/python -m pytest tests/ -q
.venv/bin/python -m pytest demo/ -q
```

All four green.

### 9. Submit

Branch as `feat/sec033`, commit with `feat(rules): SEC033 — <title>`,
open a PR. Per the project's release procedure, the PR goes through
a 3-clean review loop before merging.

## Common patterns

- **Walk both `using_ast` and `with_check_ast`** unless your rule
  is specifically about one or the other. WITH CHECK is a real
  enforcement surface for INSERT/UPDATE; many rules need to flag
  the same condition there.
- **Resolve own-table columns with care.** The canonical resolution
  pattern is: bare (`col`), table-qualified (`t.col`), schema-qualified
  (`s.t.col`); a 4-part `db.schema.table.col` reference is left
  unresolved (rules treat it as not-own-table).
  `pgrls.rules.perf003._own_table_column` is one such resolver
  (re-imported by PERF004); SEC005 / SEC018 / SEC030 carry their own
  `_own_column_names`-style helpers (each rule's bug class needs
  slightly different resolution semantics).
- **Sub-link handling.** A column reference inside a `SubLink` body
  belongs to a different table; pass `exclude_sublinks=True` to
  `extract_column_refs` when you want only own-table refs. A
  fromless scalar sub-select (`(SELECT current_setting(...))`) is
  the PERF001-recommended wrap, so don't blindly skip sublinks
  when looking for auth-function calls.
- **Configuration options.** Keep options simple. `auth_functions`
  (a list of strings), `allowlist` (a list of strings), `min_X` (an
  integer) — accept either the canonical shape or `None` (use a
  default). Validate types and raise `TypeError` with a clear
  message on misuse.
- **Always set `location`** on the Violation to the most precise
  thing the user can grep / allowlist. For per-policy rules, that's
  the qualified policy ID. For per-table rules, it's the qualified
  table name.

## What to ask for in PR review

Beyond the standard ruff/mypy/tests:

- Read the docstring as if you've never seen the rule. Is the
  bug class clear? Are the OUT-OF-SCOPE cases listed?
- Are there 10–20 test cases including silent-when shapes?
- Does the rule's behavior match its docstring's claim, especially
  the "relationship to neighbour rules" paragraph?
- Is the `location` field actionable (something the user can put
  in an `allowlist`)?
- Does the message tell the user *what to do*, not just *what's
  wrong*?

## Where to ask for help

Open a draft PR early — pgrls maintainers will read the docstring
and the canonical test case and tell you if there's already a
neighbouring rule that covers the bug, or a shape gotcha worth
knowing about.
