-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "ALTER EXTENSION pg_permissions UPDATE" to load this file. \quit

CREATE OR REPLACE VIEW table_permissions AS
SELECT obj_type 'TABLE' AS object_type,
       r.rolname AS role_name,
       t.relnamespace::regnamespace::name AS schema_name,
       t.relname::text AS object_name,
       NULL::name AS column_name,
       p.perm::perm_type AS permission,
       has_table_privilege(r.oid, t.oid, p.perm) AS granted
FROM pg_catalog.pg_class AS t
   CROSS JOIN pg_catalog.pg_roles AS r
   CROSS JOIN unnest(
                 CASE WHEN current_setting('server_version_num')::integer < 170000
                      THEN ARRAY['SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER']
                      ELSE ARRAY['SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER','MAINTAIN']
                 END
              ) AS p(perm)
WHERE t.relnamespace::regnamespace::name <> 'information_schema'
  AND t.relnamespace::regnamespace::name NOT LIKE 'pg\_%'
  AND t.relkind = 'r'
  AND NOT r.rolsuper;


CREATE OR REPLACE VIEW view_permissions AS
SELECT obj_type 'VIEW' AS object_type,
       r.rolname AS role_name,
       t.relnamespace::regnamespace::name AS schema_name,
       t.relname::text AS object_name,
       NULL::name AS column_name,
       p.perm::perm_type AS permission,
       has_table_privilege(r.oid, t.oid, p.perm) AS granted
FROM pg_catalog.pg_class AS t
   CROSS JOIN pg_catalog.pg_roles AS r
   CROSS JOIN unnest(
                 CASE WHEN current_setting('server_version_num')::integer < 170000
                      THEN ARRAY['SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER']
                      ELSE ARRAY['SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER','MAINTAIN']
                 END
              ) AS p(perm)
WHERE t.relnamespace::regnamespace::name <> 'information_schema'
  AND t.relnamespace::regnamespace::name NOT LIKE 'pg\_%'
  AND t.relkind = 'v'
  AND NOT r.rolsuper;


CREATE OR REPLACE VIEW column_permissions AS
SELECT obj_type 'COLUMN' AS object_type,
       r.rolname AS role_name,
       t.relnamespace::regnamespace::name AS schema_name,
       t.relname::text AS object_name,
       c.attname AS column_name,
       p.perm::perm_type AS permission,
       has_column_privilege(r.oid, t.oid, c.attnum, p.perm)
       AND NOT has_table_privilege(r.oid, t.oid, p.perm) AS granted
FROM pg_catalog.pg_class AS t
   JOIN pg_catalog.pg_attribute AS c ON t.oid = c.attrelid
   CROSS JOIN pg_catalog.pg_roles AS r
   CROSS JOIN (VALUES ('SELECT'), ('INSERT'), ('UPDATE'), ('REFERENCES')) AS p(perm)
WHERE t.relnamespace::regnamespace::name <> 'information_schema'
  AND t.relnamespace::regnamespace::name NOT LIKE 'pg\_%'
  AND c.attnum > 0 AND NOT c.attisdropped
  AND t.relkind IN ('r', 'v')
  AND NOT r.rolsuper;


CREATE OR REPLACE VIEW sequence_permissions AS
SELECT obj_type 'SEQUENCE' AS object_type,
       r.rolname AS role_name,
       t.relnamespace::regnamespace::name AS schema_name,
       t.relname::text AS object_name,
       NULL::name AS column_name,
       p.perm::perm_type AS permission,
       has_sequence_privilege(r.oid, t.oid, p.perm) AS granted
FROM pg_catalog.pg_class AS t
   CROSS JOIN pg_catalog.pg_roles AS r
   CROSS JOIN (VALUES ('SELECT'), ('USAGE'), ('UPDATE')) AS p(perm)
WHERE t.relnamespace::regnamespace::name <> 'information_schema'
  AND t.relnamespace::regnamespace::name NOT LIKE 'pg\_%'
  AND t.relkind = 'S'
  AND NOT r.rolsuper;


CREATE OR REPLACE VIEW function_permissions AS
SELECT obj_type 'FUNCTION' AS object_type,
       r.rolname AS role_name,
       f.pronamespace::regnamespace::name AS schema_name,
       regexp_replace(f.oid::regprocedure::text, '^((("[^"]*")|([^"][^.]*))\.)?', '') AS object_name,
       NULL::name AS column_name,
       perm_type 'EXECUTE' AS permission,
       has_function_privilege(r.oid, f.oid, 'EXECUTE') AS granted
FROM pg_catalog.pg_proc f
   CROSS JOIN pg_catalog.pg_roles AS r
WHERE f.pronamespace::regnamespace::name <> 'information_schema'
  AND f.pronamespace::regnamespace::name NOT LIKE 'pg\_%'
  AND NOT r.rolsuper;


CREATE OR REPLACE VIEW schema_permissions AS
SELECT obj_type 'SCHEMA' AS object_type,
       r.rolname AS role_name,
       n.nspname AS schema_name,
       NULL::text AS object_name,
       NULL::name AS column_name,
       p.perm::perm_type AS permission,
       has_schema_privilege(r.oid, n.oid, p.perm) AS granted
FROM pg_catalog.pg_namespace AS n
   CROSS JOIN pg_catalog.pg_roles AS r
   CROSS JOIN (VALUES ('USAGE'), ('CREATE')) AS p(perm)
WHERE n.nspname <> 'information_schema'
  AND n.nspname NOT LIKE 'pg\_%'
  AND NOT r.rolsuper;
