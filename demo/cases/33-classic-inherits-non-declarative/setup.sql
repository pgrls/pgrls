-- ============================================================
-- Use case 33: Classic INHERITS (non-declarative) — partition_of
-- stays None
-- Pre-declarative table inheritance still uses pg_inherits,
-- but `cc.relispartition` is false on the child. The
-- `_PARTITION_PARENTS_SQL` filter in introspect.py keys on
-- `relispartition = true`, so this child does NOT get a
-- `partition_of`, and SEC001 fires on both parent and child
-- with the standalone classic message.
-- ============================================================

CREATE TABLE app.legacy_parent (
    id BIGSERIAL PRIMARY KEY,
    payload TEXT
);
CREATE TABLE app.legacy_child (
    extra TEXT
) INHERITS (app.legacy_parent);
