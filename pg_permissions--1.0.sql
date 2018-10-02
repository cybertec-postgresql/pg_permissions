-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION pg_permissions" to load this file. \quit

/* types */

CREATE TYPE perm_type AS ENUM (
   'SELECT',
   'INSERT',
   'UPDATE',
   'DELETE',
   'TRUNCATE',
   'REFERENCES',
   'TRIGGER',
   'USAGE',
   'CREATE',
   'EXECUTE',
   'CONNECT',
   'TEMPORARY'
);

CREATE TYPE obj_type AS ENUM (
   'TABLE',
   'VIEW',
   'COLUMN',
   'SEQUENCE',
   'FUNCTION',
   'SCHEMA',
   'DATABASE'
);

/* views for the actual permissions */

CREATE VIEW table_permissions AS
SELECT obj_type 'TABLE' AS object_type,
       r.rolname AS role_name,
       t.relnamespace::regnamespace::name AS schema_name,
       t.relname::text AS object_name,
       NULL::name AS column_name,
       p.perm::perm_type AS permission,
       has_table_privilege(r.oid, t.oid, p.perm) AS granted
FROM pg_catalog.pg_class AS t
   CROSS JOIN pg_catalog.pg_roles AS r
   CROSS JOIN (VALUES (TEXT 'SELECT'), ('INSERT'), ('UPDATE'), ('DELETE'), ('TRUNCATE'), ('REFERENCES'), ('TRIGGER')) AS p(perm)
WHERE t.relnamespace::regnamespace::name <> 'information_schema'
  AND t.relnamespace::regnamespace::name NOT LIKE 'pg_%'
  AND t.relkind = 'r'
  AND NOT r.rolsuper;

GRANT SELECT ON table_permissions TO PUBLIC;

CREATE VIEW view_permissions AS
SELECT obj_type 'VIEW' AS object_type,
       r.rolname AS role_name,
       t.relnamespace::regnamespace::name AS schema_name,
       t.relname::text AS object_name,
       NULL::name AS column_name,
       p.perm::perm_type AS permission,
       has_table_privilege(r.oid, t.oid, p.perm) AS granted
FROM pg_catalog.pg_class AS t
   CROSS JOIN pg_catalog.pg_roles AS r
   CROSS JOIN (VALUES (TEXT 'SELECT'), ('INSERT'), ('UPDATE'), ('DELETE'), ('TRUNCATE'), ('REFERENCES'), ('TRIGGER')) AS p(perm)
WHERE t.relnamespace::regnamespace::name <> 'information_schema'
  AND t.relnamespace::regnamespace::name NOT LIKE 'pg_%'
  AND t.relkind = 'v'
  AND NOT r.rolsuper;

GRANT SELECT ON view_permissions TO PUBLIC;

CREATE VIEW column_permissions AS
SELECT obj_type 'COLUMN' AS object_type,
       r.rolname AS role_name,
       t.relnamespace::regnamespace::name AS schema_name,
       t.relname::text AS object_name,
       c.attname AS column_name,
       p.perm::perm_type AS permission,
       has_column_privilege(r.oid, t.oid, c.attnum, p.perm) AS granted
FROM pg_catalog.pg_class AS t
   JOIN pg_catalog.pg_attribute AS c ON t.oid = c.attrelid
   CROSS JOIN pg_catalog.pg_roles AS r
   CROSS JOIN (VALUES ('SELECT'), ('INSERT'), ('UPDATE'), ('REFERENCES')) AS p(perm)
WHERE t.relnamespace::regnamespace::name <> 'information_schema'
  AND t.relnamespace::regnamespace::name NOT LIKE 'pg_%'
  AND c.attnum > 0 AND NOT c.attisdropped
  AND t.relkind IN ('r', 'v')
  AND NOT r.rolsuper;

GRANT SELECT ON column_permissions TO PUBLIC;

CREATE VIEW sequence_permissions AS
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
  AND t.relnamespace::regnamespace::name NOT LIKE 'pg_%'
  AND t.relkind = 'S'
  AND NOT r.rolsuper;

GRANT SELECT ON sequence_permissions TO PUBLIC;

CREATE VIEW function_permissions AS
SELECT obj_type 'FUNCTION' AS object_type,
       r.rolname AS role_name,
       f.pronamespace::regnamespace::name AS schema_name,
       f.oid::regprocedure::text AS object_name,
       NULL::name AS column_name,
       perm_type 'EXECUTE' AS permission,
       has_function_privilege(r.oid, f.oid, 'EXECUTE') AS granted
FROM pg_catalog.pg_proc f
   CROSS JOIN pg_catalog.pg_roles AS r
WHERE f.pronamespace::regnamespace::name <> 'information_schema'
  AND f.pronamespace::regnamespace::name NOT LIKE 'pg_%'
  AND NOT r.rolsuper;

GRANT SELECT ON function_permissions TO PUBLIC;

CREATE VIEW schema_permissions AS
SELECT obj_type 'SCHEMA' AS object_type,
       r.rolname AS role_name,
       n.nspname AS schema_name,
       NULL::text AS object_name,
       NULL::name AS column_name,
       p.perm::perm_type AS permissions,
       has_schema_privilege(r.oid, n.oid, p.perm) AS granted
FROM pg_catalog.pg_namespace AS n
   CROSS JOIN pg_catalog.pg_roles AS r
   CROSS JOIN (VALUES ('USAGE'), ('CREATE')) AS p(perm)
WHERE n.nspname <> 'information_schema'
  AND n.nspname NOT LIKE 'pg_%'
  AND NOT r.rolsuper;

GRANT SELECT ON schema_permissions TO PUBLIC;

CREATE VIEW database_permissions AS
    WITH list AS (SELECT unnest AS perm
            FROM unnest ('{"CREATE", "CONNECT", "TEMPORARY"}'::text[]))
SELECT obj_type 'DATABASE' AS object_type,
    r.rolname AS role_name,
    NULL::name AS schema_name,
    NULL::text AS object_name,
    NULL::name AS column_name,
    p.perm::perm_type AS permissions,
    has_database_privilege(r.oid, d.oid, p.perm) AS granted
FROM pg_catalog.pg_database AS d
   CROSS JOIN pg_catalog.pg_roles AS r
   CROSS JOIN (VALUES ('CREATE'), ('CONNECT'), ('TEMPORARY')) AS p(perm)
WHERE d.datname = current_database()
  AND NOT r.rolsuper;

GRANT SELECT ON database_permissions TO PUBLIC;

CREATE VIEW all_permissions AS
SELECT * FROM table_permissions
UNION ALL
SELECT * FROM view_permissions
UNION ALL
SELECT * FROM column_permissions
UNION ALL
SELECT * FROM sequence_permissions
UNION ALL
SELECT * FROM function_permissions
UNION ALL
SELECT * FROM schema_permissions
UNION ALL
SELECT * FROM database_permissions;

GRANT SELECT ON all_permissions TO PUBLIC;

/* table for the targeted permissions */

CREATE TABLE permission_target (
   id             int4        PRIMARY KEY,
   role_name      name        NOT NULL,
   permissions    perm_type[] NOT NULL,
   object_type    obj_type    NOT NULL,
   schema_name    name,
   object_name    text,
   column_name name,
   CONSTRAINT permission_target_valid
   CHECK (CASE WHEN object_type = 'DATABASE'
               THEN schema_name IS NULL AND object_name IS NULL AND column_name IS NULL
                  AND ARRAY['CONNECT','CREATE','TEMPORARY']::perm_type[] @> permissions
               WHEN object_type = 'SCHEMA'
               THEN object_name IS NULL AND column_name IS NULL
                  AND ARRAY['CREATE','USAGE']::perm_type[] @> permissions
               WHEN object_type IN ('TABLE', 'VIEW')
               THEN column_name IS NULL
                  AND ARRAY['SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER']::perm_type[] @> permissions
               WHEN object_type = 'SEQUENCE'
               THEN column_name IS NULL
                  AND ARRAY['SELECT','USAGE','UPDATE']::perm_type[] @> permissions
               WHEN object_type = 'FUNCTION'
               THEN column_name IS NULL
                  AND ARRAY['EXECUTE']::perm_type[] @> permissions
               WHEN object_type = 'COLUMN'
               THEN ARRAY['SELECT','INSERT','UPDATE','REFERENCES']::perm_type[] @> permissions
          END)
);

GRANT SELECT, INSERT, UPDATE, DELETE ON permission_target TO PUBLIC;

SELECT pg_catalog.pg_extension_config_dump('permission_target', '');

CREATE FUNCTION permission_diffs()
   RETURNS TABLE (
      missing boolean,
      role_name name,
      object_type obj_type,
      schema_name name,
      object_name text,
      column_name name,
      permission perm_type
   )
   LANGUAGE plpgsql SET search_path FROM CURRENT STABLE AS
$$DECLARE
   typ obj_type;
   r name;
   ar name;
   s name;
   a_s name;
   o text;
   ao text;
   so name;
   aso name;
   p perm_type;
   g boolean;
   ag boolean;
BEGIN
   FOR r, p, typ, s, o, so IN
      SELECT pt.role_name, p.permission, pt.object_type, pt.schema_name, pt.object_name, pt.column_name
      FROM permission_target AS pt
         CROSS JOIN LATERAL unnest(pt.permissions) AS p(permission)
   LOOP
      FOR ar, a_s, ao, aso, ag IN
         SELECT ap.role_name, ap.schema_name, ap.object_name, ap.column_name, ap.granted
         FROM all_permissions AS ap
         WHERE ap.object_type = typ
           AND ap.permission = p
           AND (ap.schema_name = s OR s IS NULL)
           AND (ap.object_name = o OR o IS NULL)
           AND (ap.column_name = so OR so IS NULL)
      LOOP
         IF ar = r AND NOT ag THEN
            /* permission not granted that should be */
            permission_diffs.missing := TRUE;
            permission_diffs.role_name := r;
            permission_diffs.object_type := typ;
            permission_diffs.schema_name := a_s;
            permission_diffs.object_name := ao;
            permission_diffs.column_name := aso;
            permission_diffs.permission := p;
            RETURN NEXT;
         END IF;
         IF ar <> r AND ag THEN
            /* permission granted to a different role, check if there is a rule */
            IF NOT EXISTS (
                      SELECT 1
                      FROM permission_target AS pt
                      WHERE pt.role_name = ar
                        AND (pt.schema_name IS NULL OR pt.schema_name = a_s)
                        AND (pt.object_name IS NULL OR pt.object_name = ao)
                        AND (pt.column_name IS NULL OR pt.column_name = aso)
                   )
            THEN
               /* extra permission found, report */
               permission_diffs.missing := FALSE;
               permission_diffs.role_name := ar;
               permission_diffs.object_type := typ;
               permission_diffs.schema_name := a_s;
               permission_diffs.object_name := ao;
               permission_diffs.column_name := aso;
               permission_diffs.permission := p;
               RETURN NEXT;
            END IF;
         END IF;
      END LOOP;
   END LOOP;
END;$$;
