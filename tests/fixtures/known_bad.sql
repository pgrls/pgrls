-- Two tables; only `users` lacks RLS, `orders` has it enabled.
-- SEC001 should fire on `public.users` and not on `public.orders`.

CREATE TABLE public.users (
    id BIGSERIAL PRIMARY KEY,
    email TEXT NOT NULL
);

CREATE TABLE public.orders (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL,
    total NUMERIC NOT NULL
);

ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.orders FORCE ROW LEVEL SECURITY;

CREATE POLICY orders_owner ON public.orders
    FOR SELECT
    TO PUBLIC
    USING (user_id = current_setting('app.user_id', true)::BIGINT);
