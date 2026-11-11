-- Readiness probe (coordination#29 U1 stats round 2): the least-privilege
-- runtime login reports the applied migration in /health, so it needs
-- SELECT on the migrations table. Writes stay revoked (see 001_core.sql).
SET search_path = control, pg_catalog, pg_temp;
GRANT SELECT ON schema_migrations TO cp_runtime;
