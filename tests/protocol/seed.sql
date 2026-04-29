-- Seeded as the connecting (admin) role before any actor switches.
INSERT INTO protocol_invoices (tenant_id, amount) VALUES
    ('tenant-a', 100),
    ('tenant-a', 200),
    ('tenant-b', 300),
    ('tenant-b', 400),
    ('tenant-b', 500);
