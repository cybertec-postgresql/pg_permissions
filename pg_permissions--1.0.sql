-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION pg_permissions" to load this file. \quit

CREATE VIEW table_permissions AS
SELECT TEXT 'table' AS object_type,
       r.rolname AS role_name,
       t.relnamespace::regnamespace::name AS schema_name,
       t.relname::text AS object_name,
       NULL::name AS subobject_name,
       p.perm AS permission,
       has_table_privilege(r.oid, t.oid, p.perm) AS granted
FROM pg_catalog.pg_class AS t
   CROSS JOIN pg_catalog.pg_roles AS r
   CROSS JOIN (VALUES (TEXT 'INSERT'), ('UPDATE'), ('DELETE'), ('TRUNCATE'), ('REFERENCES'), ('TRIGGER')) AS p(perm)
WHERE t.relnamespace::regnamespace::name <> 'information_schema'
  AND t.relnamespace::regnamespace::name NOT LIKE 'pg_%'
  AND t.relkind = 'r';

CREATE VIEW view_permissions AS
WITH list AS (SELECT unnest AS perm 
        FROM unnest ('{"INSERT", "UPDATE", "DELETE", "TRIGGER"}'::text[]))
SELECT TEXT 'view' AS object_type,
       r.rolname AS role_name,
       t.relnamespace::regnamespace::name AS schema_name,
       t.relname::text AS object_name,
       NULL::name AS subobject_name,
       p.perm AS permission,
       has_table_privilege(r.oid, t.oid, p.perm) AS granted
FROM pg_catalog.pg_class AS t
   CROSS JOIN pg_catalog.pg_roles AS r
   CROSS JOIN (VALUES ('INSERT'), ('UPDATE'), ('DELETE'), ('TRIGGER')) AS p(perm)
WHERE t.relnamespace::regnamespace::name <> 'information_schema'
  AND t.relnamespace::regnamespace::name NOT LIKE 'pg_%'
  AND t.relkind = 'v';

CREATE VIEW column_permissions AS
SELECT TEXT 'column' AS object_type,
       r.rolname AS role_name,
       t.relnamespace::regnamespace::name AS schema_name,
       t.relname::text AS object_name,
       c.attname AS subobject_name,
       p.perm AS permission,
       has_column_privilege(r.oid, t.oid, c.attnum, p.perm) AS granted
FROM pg_catalog.pg_class AS t
   JOIN pg_catalog.pg_attribute AS c ON t.oid = c.attrelid
   CROSS JOIN pg_catalog.pg_roles AS r
   CROSS JOIN (VALUES ('INSERT'), ('UPDATE'), ('SELECT'), ('REFERENCES')) AS p(perm)
WHERE t.relnamespace::regnamespace::name <> 'information_schema'
  AND t.relnamespace::regnamespace::name NOT LIKE 'pg_%'
  AND c.attnum > 0 AND NOT c.attisdropped
  AND t.relkind IN ('r', 'v');

CREATE VIEW function_permissions AS
SELECT TEXT 'function' AS object_type,
       r.rolname AS role_name,
       f.pronamespace::regnamespace::name AS schema_name,
       f.oid::regprocedure::text AS object_name,
       NULL::name AS subobject_name,
       TEXT 'EXECUTE' AS permission,
       has_function_privilege(r.oid, f.oid, 'EXECUTE') AS granted
FROM pg_catalog.pg_proc f
   CROSS JOIN pg_catalog.pg_roles AS r
WHERE f.pronamespace::regnamespace::name <> 'information_schema'
  AND f.pronamespace::regnamespace::name NOT LIKE 'pg_%';

CREATE VIEW schema_permissions AS
SELECT TEXT 'schema' AS object_type,
       r.rolname AS role_name,
       n.nspname AS schema_name,
       NULL::text AS object_name,
       NULL::name AS subobject_name,
       p.perm AS permissions,
       has_schema_privilege(r.oid, n.oid, p.perm) AS granted
FROM pg_catalog.pg_namespace AS n
   CROSS JOIN pg_catalog.pg_roles AS r
   CROSS JOIN (VALUES ('USAGE'), ('CREATE')) AS p(perm)
WHERE n.nspname <> 'information_schema'
  AND n.nspname NOT LIKE 'pg_%';

CREATE VIEW database_permissions AS
    WITH list AS (SELECT unnest AS perm 
            FROM unnest ('{"CREATE", "CONNECT", "TEMPORARY"}'::text[]))
SELECT TEXT 'database' AS object_type,
    r.rolname AS role_name,
    NULL::name AS schema_name,
    NULL::text AS object_name,
    NULL::name AS subobject_name,
    p.perm AS permissions,
    has_database_privilege(r.oid, d.oid, p.perm) AS granted
FROM pg_catalog.pg_database AS d
   CROSS JOIN pg_catalog.pg_roles AS r
   CROSS JOIN (VALUES ('CREATE'), ('CONNECT'), ('TEMPORARY')) AS p(perm)
WHERE d.datname = current_database();

CREATE VIEW all_permissions AS
SELECT * FROM table_permissions
UNION ALL
SELECT * FROM view_permissions
UNION ALL
SELECT * FROM column_permissions
UNION ALL
SELECT * FROM function_permissions
UNION ALL
SELECT * FROM schema_permissions
UNION ALL
SELECT * FROM database_permissions;
