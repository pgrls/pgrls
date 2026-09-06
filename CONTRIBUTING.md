# Contributing to pgrls

Issues and pull requests are welcome. The fastest path:

1. **For a bug or a missed lint shape:** open an
   [issue](https://github.com/pgrls/pgrls/issues) with a minimal SQL
   fixture, the exact `pgrls` invocation, and the output you got vs.
   the output you expected.
2. **For a code change:** fork, branch (`feat/rule-sec0NN`,
   `fix/perf003-edge-case`, etc.), open a PR against `main`.
   Every PR gets a code-review pass before merge; the bar is the same
   as the one the existing rules clear.

## Local development

```bash
git clone https://github.com/pgrls/pgrls.git
cd pgrls
python -m venv .venv
.venv/bin/python -m pip install -e .[dev]
.venv/bin/python -m pytest tests/       # ~3,900 tests, several minutes (needs Docker)
.venv/bin/python -m pytest demo/        # end-to-end use cases
.venv/bin/python -m pytest corpus/      # the precision gate — CI runs it as its own job
.venv/bin/ruff check src tests
.venv/bin/mypy src
```

The `demo/` and `corpus/` suites need Docker (they build a real database);
a live Postgres is **not** required for the unit tests — the rule
suite runs against in-memory `Schema` fixtures. The integration tests
under `tests/` and the demo cases under `demo/` use
[testcontainers](https://testcontainers-python.readthedocs.io/) to
spin up an ephemeral PG container per session.

## Conventions

- **Rule numbers are append-only.** A new security rule gets the next
  free `SEC0NN`; performance rules get `PERF00N`; hygiene `HYG00N`;
  view-related `VIEW00N`. Never reuse a deprecated rule's number.
- **Every rule needs:** a module under `src/pgrls/rules/`, a unit-test
  module under `tests/rules/`, an entry in
  `tests/fixtures/all_bad.sql` (so the combined-fixture test trips
  it), a `## <RULE> — …` section (with its `rule-<id>` anchor) in
  `docs/RULES.md` documenting the detection shape and any allowlist /
  config knobs, and the one-line catalog entry in `AGENTS.md`.
- **Auto-fixable rules:** add a fixer module under
  `src/pgrls/fixers/`, register it in `default_fixers()`, and update
  the `## Auto-fix: pgrls fix` section of `AGENTS.md`.
- **CHANGELOG entries** go under `[Unreleased]` until the maintainer
  cuts a release.
- **No Claude / AI-generated attribution** in commit messages or PR
  bodies. Authorship sits with the human who reviewed the diff.

## What gets reviewed for

- **Correctness of the AST traversal.** The rule must fire on every
  shape it claims to catch and stay silent on the documented
  "out of scope" shapes.
- **Round-trip stability through `pg_get_expr`.** pgrls introspects
  policies via `pg_get_expr`, which deparses to a normalized form
  (e.g. `LIKE` → `~~`). Detection should match the deparsed form, not
  just the literal source.
- **Test coverage.** Each rule module has its own
  `tests/rules/test_<rule>.py` file; expect ~10–20 cases covering
  fires, silent-paths, allowlist semantics, and any config options.

For larger architectural changes (new commands, new output formats,
new dependencies), open an issue first to align on the shape before
writing the patch.
