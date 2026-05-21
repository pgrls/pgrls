-- ============================================================
-- Use case 54: SEC005 with TypeCast wrapping a column ref —
-- CLEAN
-- `email::text = ...` parses as a TypeCast over a ColumnRef.
-- extract_column_refs needs to walk through TypeCast.arg to
-- still see `email`. Pin that the cast doesn't hide the col.
-- ============================================================

CREATE TABLE app.typecast_email (
    id BIGSERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL
);
ALTER TABLE app.typecast_email ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.typecast_email FORCE ROW LEVEL SECURITY;
-- PERMISSIVE policy mirroring the typecast-over-column shape.
-- Pins the same AST path (TypeCast around `email`) so
-- extract_column_refs still sees the own-column ref → SEC005
-- silent on both policies.
CREATE POLICY typecast_email_authenticated_access ON app.typecast_email
    FOR ALL TO app_authenticated
    USING (email::text = (SELECT current_setting('app.user', true)))
    WITH CHECK (email::text = (SELECT current_setting('app.user', true)));
CREATE POLICY by_email_text ON app.typecast_email
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (email::text = (SELECT current_setting('app.user', true)));
