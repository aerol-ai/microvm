-- Minimal RLS seed for postgres-supabase sim (stub fixture).
-- Full your-own-supabase bundle may be vendored from aerolvm-examples.
CREATE TABLE IF NOT EXISTS bench_rows (id serial primary key, secret text);
ALTER TABLE bench_rows ENABLE ROW LEVEL SECURITY;
