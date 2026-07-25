# RAG retrieval-path audit — the RLS bypass a linter can't see

Your Supabase RAG assistant has Row-Level Security on the embeddings table. A
direct `SELECT` as another tenant returns **zero rows**. Every table-level check
passes. And it can still hand one tenant another tenant's private chunks —
through the retrieval function.

This example reproduces the leak on a throwaway database and catches it with
[`pgrls vector`](../../README.md#rag-retrieval-path--pgrls-vector).

## Run it

```bash
pip install "pgrls[all]"      # needs Docker for the throwaway pgvector db
./run.sh
```

`run.sh` starts a disposable `pgvector` container, loads [`schema.sql`](schema.sql),
and prints the two steps below. It cleans the container up on exit.

## The shape (Supabase's own "RAG with Permissions" pattern)

- `document_sections` holds chunk embeddings; its RLS restricts a row to the
  owner of the parent document. This is **correct** and `FORCE`'d.
- Retrieval goes through a `SECURITY DEFINER` similarity-search function — which
  the same ecosystem recommends for RLS *performance*.

Two functions are defined over the same table:

| function | body | verdict |
|---|---|---|
| `match_document_sections` | reads the table, **no re-filter** | **LEAK** |
| `match_document_sections_safe` | re-applies the ownership filter | NO LEAK |

They have the same signature and both are `SECURITY DEFINER`, so a static rule
([`SEC014`](../../docs/RULES.md#rule-sec014)) flags them **identically** — it can
only say a SECDEF function *could* bypass RLS.

## Step 1 — RLS looks correct

As Bob, a direct read returns only Bob's row. Alice's private chunk is denied:

```
 id |      content
----+--------------------
  2 | Bob's public notes
```

## Step 2 — the retrieval path tells a different story

`pgrls vector` calls each function as Bob and compares what it returns against
what the direct read allows:

```
LEAK     match_document_sections -> document_sections as app_user
           leaked row: (id=1, content='ALICE PRIVATE: Q3 revenue was $4.2M')
NO LEAK  match_document_sections_safe -> document_sections as app_user
```

`match_document_sections` ran its body as the **owner**, so the table's RLS was
never re-checked — Bob gets Alice's chunk. The probe surfaces the primary key
Bob is denied and re-verifies it is a real row of the table, so the evidence is
a genuine bypass, not a coincidence.

## Why a probe and not a rule

The bypass lives in the *composition* — a correct table, a correct policy, and a
`SECURITY DEFINER` function that each look fine on their own. A rule reading the
table sees nothing wrong. Executing the path is what separates the leaking
function from the safe one. `pgrls vector` is a leak **detector**: a `LEAK` is a
proven bypass with evidence; `NO LEAK` is a clean spot-check, not a proof of
isolation for every argument.

## The fix

Re-apply the tenant predicate inside the function body (as
`match_document_sections_safe` does), or make the function `SECURITY INVOKER` so
the caller's own RLS applies to the read.

> Run `pgrls vector` as a superuser / `BYPASSRLS` role: it needs an unfiltered
> baseline to compare against, and abstains rather than guess if the connection
> role is itself subject to RLS.
