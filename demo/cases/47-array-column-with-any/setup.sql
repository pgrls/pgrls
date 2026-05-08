-- ============================================================
-- Use case 47: ARRAY column with ANY() — CLEAN
-- `<scalar> = ANY(array_col)` is a common pattern for tag-
-- based access ("rows whose visible_to array contains the
-- caller"). The column ref `tags` is on the RHS of `= ANY`.
-- Pin that extract_column_refs walks ArrayExpr / ANY
-- correctly so SEC005 stays silent.
-- ============================================================

CREATE TABLE app.array_tags (
    id BIGSERIAL PRIMARY KEY,
    tags TEXT[]
);
ALTER TABLE app.array_tags ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.array_tags FORCE ROW LEVEL SECURITY;
-- PERMISSIVE policy mirroring the array-membership predicate.
-- `tags` (the array column) is referenced inside ANY(); the
-- case pins that extract_column_refs walks through that.
CREATE POLICY array_tags_authenticated_access ON app.array_tags
    FOR ALL TO app_authenticated
    USING (
        (SELECT current_setting('app.user', true)) = ANY(tags)
    )
    WITH CHECK (
        (SELECT current_setting('app.user', true)) = ANY(tags)
    );
CREATE POLICY in_tags ON app.array_tags
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (
        (SELECT current_setting('app.user', true)) = ANY(tags)
    );
