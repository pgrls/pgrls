# Project-specific rules — `[lint].extra_rules`

`pgrls` ships 67 built-in rules. You can add more — private to your
project, experimental, or domain-specific — without forking.

This guide is for **consumers** writing rules used only by their own
project. Contributors writing rules for the upstream catalog should
follow [`docs/RULE_AUTHORING.md`](RULE_AUTHORING.md); both audiences
share the same `Rule` Protocol shape.

## Quick start

1. **Make a Python package** containing your rules:

   ```
   mycompany_pgrls_rules/
   ├── __init__.py        # exposes RULES
   └── mycompany_001.py   # one file per rule, matches built-in convention
   ```

2. **Write the rule.** It must implement the `Rule` Protocol from
   `pgrls.rules`:

   ```python
   # mycompany_pgrls_rules/mycompany_001.py
   from pgrls.model import Schema
   from pgrls.violations import Severity, Violation


   class MyCompany001:
       id: str = "MYCO001"
       severity: Severity = "warning"
       title: str = "Tables in tenant.* must have tenant_id column"

       def check(
           self, schema: Schema, options: dict
       ) -> list[Violation]:
           out: list[Violation] = []
           for table in schema.tables:
               if table.schema != "tenant":
                   continue
               if "tenant_id" not in {c for c in table.columns}:
                   out.append(
                       Violation(
                           rule_id=self.id,
                           severity=self.severity,
                           title=self.title,
                           message=(
                               f"{table.qualified_name} is in the "
                               "tenant schema but has no tenant_id "
                               "column."
                           ),
                           location=table.qualified_name,
                       )
                   )
           return out
   ```

3. **Expose `RULES`** in the package's `__init__.py`:

   ```python
   # mycompany_pgrls_rules/__init__.py
   from .mycompany_001 import MyCompany001

   RULES = [MyCompany001()]
   ```

4. **Install the package** in the same environment as `pgrls`:

   ```
   pip install -e ./path/to/mycompany_pgrls_rules
   ```

5. **Reference it from `pgrls.toml`:**

   ```toml
   [lint]
   extra_rules = ["mycompany_pgrls_rules"]
   ```

That's it. `pgrls lint` now runs your rule alongside the built-ins.
`pgrls explain` lists it in the catalog. `pgrls.toml`'s
`[lint.rules.MYCO001]` table can carry per-rule options the same way
built-ins do.

## Rule ID conventions

- **Don't collide with built-ins.** pgrls rejects duplicate IDs at
  registration time with a clear error. Built-in IDs use the
  patterns `SEC###`, `PERF###`, `HYG###`, `VIEW###`.
- **Use a prefix unique to your project.** `MYCO###`, `ACME_###`,
  or any 3-6 letter prefix that's unlikely to collide with future
  built-ins.
- **IDs are case-sensitive at registration time** but case-insensitive
  in `[lint.rules.<ID>]` config lookup, `--rule`, `--exclude-rule`,
  and `[lint].disable`. Use uppercase as the canonical form.

## Rule shape requirements

The `Rule` Protocol requires four attributes:

| Attribute | Type | Notes |
| --- | --- | --- |
| `id` | `str` | Non-empty. Conventionally uppercase. |
| `severity` | `Severity` | One of `"error"`, `"warning"`, `"info"`. |
| `title` | `str` | One-line headline shown in `pgrls explain` + finding output. |
| `check` | `Callable[[Schema, dict[str, Any]], list[Violation]]` | The rule's logic. |

`load_extra_rules` validates each field at load time. A malformed
rule fails fast with a message naming the offending module + index,
not a mysterious `AttributeError` from inside the rule walk.

## Configuration for your rule

If your rule needs operator-tunable options (allowlists,
thresholds, custom function names), accept them via the
`options: dict[str, Any]` argument to `check()`. The
`[lint.rules.MYCO001]` table in the user's `pgrls.toml` flows
through to that dict:

```toml
[lint.rules.MYCO001]
allowlist = ["tenant.archive_log"]
required_column = "tenant_id"  # let users override the column name
```

```python
def check(self, schema, options):
    required = options.get("required_column", "tenant_id")
    allowlist = set(options.get("allowlist", []))
    ...
```

`[lint.rules.MYCO001].severity` works too — operators can promote
a warning to error or demote without disabling.

## Sharing rules between projects

A monorepo can keep its rules in one shared package and reference
it from every service's `pgrls.toml`:

```toml
# services/billing/pgrls.toml
extends = "../../shared/pgrls.base.toml"
```

```toml
# shared/pgrls.base.toml
[lint]
extra_rules = ["mycompany_pgrls_rules"]
```

`extends` resolves the chain at config-load; `extra_rules` from the
base merges into the child unless the child sets its own
`extra_rules` (which fully replaces — list-replace semantics).

## Distribution

For a few projects sharing rules, an editable install
(`pip install -e ./rules-pkg`) is the simplest. For wider sharing,
publish the package privately (PyPI, a private index, or a Git URL
in `requirements.txt`) — `pgrls` treats it like any other Python
dependency.

## Anti-patterns

- **Don't reach into `pgrls.rules._build_default_registry()`** or
  any private function. The public surface is `Rule`, `RuleRegistry`,
  `Violation`, `Schema`, `Severity`, `load_extra_rules`, and the
  `pgrls.ast_utils` helpers. Anything else is subject to change.
- **Don't ship rules whose `check` makes a database connection** —
  rules consume the already-introspected `Schema` argument. If you
  need DB state the schema doesn't carry, file an issue rather than
  introducing a second connection from inside a rule.
- **Don't ship rules with side effects.** Rules emit `Violation`
  objects, full stop. No prints, no logs, no writes.

## Where the loader lives

If you're curious about the implementation: the loader is
`pgrls.rules.load_extra_rules`, called from `pgrls.cli._run_rules`
once per lint. The loaded rules go into a fresh `RuleRegistry`
alongside the built-ins; the registry's `register()` raises on ID
collisions. See [`src/pgrls/rules/__init__.py`](../src/pgrls/rules/__init__.py)
for the full Protocol + registry source.
