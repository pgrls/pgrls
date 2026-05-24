"""Property-based tests for the canonical own-column resolver.

`_own_table_column` is defined in `pgrls.rules.perf003` and shared
with `pgrls.rules.perf004` (which imports it directly); both PERF
rules treat its return value as the source of truth for "does this
ref belong to the policy's own table?". The SEC rules (SEC005 /
SEC018 / SEC030) have their own equivalent helpers
(`_own_column_names` and similar) — those are separate fuzz targets
a future PR may add.

Example-based tests (`tests/rules/test_perf003.py`) cover the
specific *shapes* we've thought to enumerate. Hypothesis covers the
combinatorial space — random tuples of random strings against tables
with random schema/name — and asserts the contract docstrings claim:

  - 1-tuple `(col,)` → always returns `col` (treated as own-table).
  - 2-tuple `(qual, col)` → returns `col` iff `qual == table.name`.
  - 3-tuple `(schema, table, col)` → returns `col` iff both schema
    and table match.
  - Any other shape (empty, ≥4-part) → returns `None`.
  - Never raises on any combination of input strings.

Catches edge cases (empty strings, very long strings, unicode
identifiers, schema collisions) the example fixtures don't enumerate.
"""
from __future__ import annotations

from hypothesis import given, strategies as st

from pgrls.model import Table
from pgrls.rules.perf003 import _own_table_column


def _table(schema: str = "public", name: str = "t") -> Table:
    """Minimal Table instance — only the fields the resolver inspects."""
    return Table(
        schema=schema,
        name=name,
        rls_enabled=False,
        force_rls=False,
        policies=(),
    )


# Strategy for SQL identifier-shaped strings. Identifiers in
# Postgres can be almost anything when quoted, but the resolver
# compares them as Python strings, so we generate the full text
# range including empty strings, unicode, and very long identifiers
# — the resolver's contract should hold regardless.
ident = st.text(min_size=0, max_size=64)


@given(col=ident)
def test_one_part_always_returns_the_col_regardless_of_table(col: str) -> None:
    # The 1-tuple branch is unconditional: an unqualified ref is
    # treated as own-table no matter what the table's schema/name are.
    assert _own_table_column((col,), _table(schema="any_s", name="any_t")) == col
    assert _own_table_column((col,), _table(schema="other", name="other")) == col


@given(qual=ident, col=ident, table_name=ident)
def test_two_part_returns_col_iff_qualifier_matches_table_name(
    qual: str, col: str, table_name: str
) -> None:
    table = _table(schema="public", name=table_name)
    result = _own_table_column((qual, col), table)
    if qual == table_name:
        assert result == col
    else:
        assert result is None


@given(schema=ident, name=ident, col=ident, t_schema=ident, t_name=ident)
def test_three_part_returns_col_iff_schema_and_name_both_match(
    schema: str, name: str, col: str, t_schema: str, t_name: str
) -> None:
    table = _table(schema=t_schema, name=t_name)
    result = _own_table_column((schema, name, col), table)
    if schema == t_schema and name == t_name:
        assert result == col
    else:
        assert result is None


@given(parts=st.lists(ident, min_size=4, max_size=10))
def test_four_or_more_parts_always_returns_none(parts: list[str]) -> None:
    # A 4-part `db.schema.table.col` ref (Postgres accepts the form)
    # is uniformly unresolved by the helper — by design, since the
    # resolver doesn't model cross-database references.
    assert _own_table_column(tuple(parts), _table()) is None


@given(parts=st.lists(ident, max_size=3))
def test_resolver_never_raises_on_any_string_ref(parts: list[str]) -> None:
    # The combinatorial sanity check: for any input that fits the
    # 0/1/2/3-part shape, the resolver returns `str | None` and never
    # raises. This pins the function's total-function contract — a
    # rule iterating over `extract_column_refs(...)` output should
    # never abort because of a weird identifier.
    result = _own_table_column(tuple(parts), _table())
    assert result is None or isinstance(result, str)


def test_empty_tuple_returns_none() -> None:
    # An empty ref — `extract_column_refs` shouldn't produce one,
    # but the resolver tolerates it (falls through to the final
    # `return None`). Plain pytest test — no Hypothesis needed for
    # a single-input case.
    assert _own_table_column((), _table()) is None
