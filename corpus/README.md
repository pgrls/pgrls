# Precision corpus

An **adjudicated** set of small, self-contained schemas used to measure
pgrls's per-rule precision and — the point — its **false-positive**
behavior, over the real introspection + lint path. The published run is
[`docs/PRECISION.md`](../docs/PRECISION.md).

## Layout

| file | role |
|------|------|
| `cases.py` | the labeled cases — each `Case` is a self-contained schema plus the COMPLETE set of rule IDs that should fire (`expect`) |
| `harness.py` | applies each case to a fresh `public` schema on a throwaway Postgres, introspects, runs the full built-in rule set at **default options**, tabulates TP/FP/FN |
| `measure.py` | `python -m corpus.measure` → regenerates `docs/PRECISION.md` + `results.json` |
| `test_corpus.py` | the CI gate — fails on any *undocumented* false positive or false negative |

## Run it

```bash
python -m corpus.measure          # spin a throwaway PG, write the report
python -m corpus.measure --print  # console only, don't write files
pytest corpus/                    # the regression gate
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

## What the numbers mean

Construct validity, **not** a population estimate. The corpus is
hand-labeled and adversarial by design; 100% precision here means "no false
positive on the shapes we've thought to test," not "no false positive
ever." See the scope caveat in `docs/PRECISION.md`. The two
artifact-dependent rules (HYG004, PERF005) need runtime data a static
schema can't provide and are out of scope.
