-- ============================================================
-- Use case 78: PERF002 — VOLATILE function in policy
-- `random()` is VOLATILE: it returns a different value on every
-- call. As a policy predicate it's a security hazard
-- (`random() < 0.5` admits/denies rows unpredictably) and a
-- performance hazard (cannot be cached, evaluated per row).
-- STABLE alternatives like `now()` are NOT in PERF002's set —
-- those have separate treatment via PERF001's wrap-in-subquery
-- mechanic.
-- ============================================================

CREATE TABLE app.volatile_predicate (
    id BIGSERIAL,
    payload TEXT
);
ALTER TABLE app.volatile_predicate ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.volatile_predicate FORCE ROW LEVEL SECURITY;
CREATE POLICY random_sampling ON app.volatile_predicate
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (random() < 0.5);
