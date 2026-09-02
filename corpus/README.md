# Precision corpus

An **adjudicated** set of small, self-contained schemas used to measure
pgrls's per-rule precision and — the point — its **false-positive**
behavior, over the real introspection + lint path. The published run is
[`docs/PRECISION.md`](../docs/PRECISION.md).

Two corpora live here, asking different questions of the same kind of
fixture:

- the **lint** corpus (`cases.py`) — *which rules fire?*
- the **verdict** corpus (`verdicts.py`) — *what does `pgrls verify`
  conclude?*

They are separate because a verdict regression is invisible to the lint
corpus. Two exploitable false clears reached 0.52.0 with every lint case
green: `--mode write` proved isolation on a schema one tenant could wipe,
and `--mode anon` reported a LEAK on the canonical tenant policy. Both were
caught by hand. The verdict corpus exists so the next one is caught here.

## Layout

| file | role |
|------|------|
| `cases.py` | the labeled cases — each `Case` is a self-contained schema plus the COMPLETE set of rule IDs that should fire (`expect`) |
| `harness.py` | applies each case to a fresh `public` schema on a throwaway Postgres, introspects, runs the full built-in rule set at **default options**, tabulates TP/FP/FN |
| `measure.py` | `python -m corpus.measure` → regenerates `docs/PRECISION.md` + `results.json` |
| `test_corpus.py` | the CI gate — fails on any *undocumented* false positive or false negative |
| `verdicts.py` | the labeled **verdict** cases — each `VerdictCase` is a schema, a `--mode`, and the COMPLETE set of per-table verdicts expected |
| `test_verdicts.py` | the verdict CI gate — fails on any verdict that no longer matches its adjudication |

## Run it

```bash
python -m corpus.measure          # spin a throwaway PG, write the report
python -m corpus.measure --print  # console only, don't write files
python -m corpus.verdicts         # verdict corpus, pass/fail per case
pytest corpus/                    # both regression gates
```

Needs Docker (testcontainers) unless `PGRLS_TEST_DATABASE_URL` /
`DATABASE_URL` points at a throwaway database the harness may DROP schemas
on.

## Adding a case

1. Start from a clean gold-standard base (`_clean_tenant` / `_clean_owner`):
   RLS enabled **and** forced, the predicate wrapped in `(SELECT …)`, the
   filter column `NOT NULL` and indexed, a restrictive floor, granted to a
   concrete role (never `PUBLIC`).
2. Perturb **one** thing:
   - **Positive** — introduce one violation; set `expect` to every rule
     that legitimately fires.
   - **Negative** — introduce an adversarial near-miss that must stay
     silent; leave `expect` empty.
3. `python -m corpus.measure --print` and reconcile until the case matches
   its label. If a near-miss surfaces a *real* false positive, fix the rule
   — or record it in `known_fp` with a note. Don't paper over it by adding
   the wrongly-fired rule to `expect`.

## Adding a verdict case

1. Write the smallest schema that isolates the behaviour, and pick the
   `--mode` whose claim you are pinning.
2. **Establish the truth on a real database first.** Apply the schema, then
   `SET ROLE` to the threat actor and run the query — count the rows it
   actually returns. That measurement is the adjudication.
3. Set `expect` to the COMPLETE set of `(qualified_name, verdict)` pairs,
   so an extra finding fails as loudly as a missing one. Use `expect_paths`
   where *which* view or owner the finding came through is the point.
4. Put the measurement in `note`. A case whose note does not say why the
   verdict is correct cannot be re-checked by the next reader, and
   `test_verdicts.py` requires one.

The bar: the expected verdict must be checkable against what Postgres
does, **not** against what the prover currently prints. Pinning today's
output is how a wrong verdict becomes a permanent fixture.

Roles are cluster-wide, so anything a case creates it must also remove —
`verdicts.py` tears its roles down in a `finally`. Leaving a `BYPASSRLS`
role behind makes SEC016 fire on every case of the *lint* corpus that runs
afterwards in the same database.

## What the numbers mean

Construct validity, **not** a population estimate. The corpus is
hand-labeled and adversarial by design; 100% precision here means "no false
positive on the shapes we've thought to test," not "no false positive
ever." See the scope caveat in `docs/PRECISION.md`. The two
artifact-dependent rules (HYG004, PERF005) need runtime data a static
schema can't provide and are out of scope.
