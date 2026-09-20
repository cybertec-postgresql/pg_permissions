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
   'TEMPORARY',
   'MAINTAIN'
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
   CROSS JOIN unnest(
                 CASE WHEN current_setting('server_version_num')::integer < 170000
                      THEN ARRAY['SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER']
                      ELSE ARRAY['SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER','MAINTAIN']
                 END
              ) AS p(perm)
WHERE t.relnamespace::regnamespace::name <> 'information_schema'
  AND t.relnamespace::regnamespace::name NOT LIKE 'pg\_%'
  AND t.relkind IN ('r', 'p', 'f')
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
   CROSS JOIN unnest(
                 CASE WHEN current_setting('server_version_num')::integer < 170000
                      THEN ARRAY['SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER']
                      ELSE ARRAY['SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER','MAINTAIN']
                 END
              ) AS p(perm)
WHERE t.relnamespace::regnamespace::name <> 'information_schema'
  AND t.relnamespace::regnamespace::name NOT LIKE 'pg\_%'
  AND t.relkind IN ('v', 'm')
  AND NOT r.rolsuper;

GRANT SELECT ON view_permissions TO PUBLIC;

CREATE VIEW column_permissions AS
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
  AND t.relkind IN ('r', 'v', 'm', 'p', 'f')
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
  AND t.relnamespace::regnamespace::name NOT LIKE 'pg\_%'
  AND t.relkind = 'S'
  AND NOT r.rolsuper;

GRANT SELECT ON sequence_permissions TO PUBLIC;

CREATE VIEW function_permissions AS
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

GRANT SELECT ON function_permissions TO PUBLIC;

CREATE VIEW schema_permissions AS
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

GRANT SELECT ON schema_permissions TO PUBLIC;

CREATE VIEW database_permissions AS
SELECT obj_type 'DATABASE' AS object_type,
    r.rolname AS role_name,
    NULL::name AS schema_name,
    NULL::text AS object_name,
    NULL::name AS column_name,
    p.perm::perm_type AS permission,
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

/* update trigers for the views */

CREATE FUNCTION permissions_trigger_func()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
   db_name text;
   cmd     text;
   func    pg_catalog.regprocedure;
BEGIN
   -- "IS DISTINCT FROM" so that keys that are NULL (e.g. "object_name"
   -- for schemas and databases) are compared correctly
   IF NEW.object_type IS DISTINCT FROM OLD.object_type OR
      NEW.role_name IS DISTINCT FROM OLD.role_name OR
      NEW.schema_name IS DISTINCT FROM OLD.schema_name OR
      NEW.object_name IS DISTINCT FROM OLD.object_name OR
      NEW.column_name IS DISTINCT FROM OLD.column_name OR
      NEW.permission IS DISTINCT FROM OLD.permission
   THEN
      RAISE 'Only the "granted" column may be updated';
   END IF;

   -- Is there anything to do at all?
   IF NEW.granted = OLD.granted
   THEN
      RETURN NEW;
   END IF;

   -- all identifiers are quoted with %I to make the statement safe
   -- for names that need quoting
   IF OLD.object_type IN ('TABLE', 'VIEW')
   THEN
      IF NOT OLD.granted
      THEN
         cmd := pg_catalog.format('GRANT %s ON %I.%I TO %I',
            OLD.permission, OLD.schema_name,
            OLD.object_name, OLD.role_name);
      ELSE
         cmd := pg_catalog.format('REVOKE %s ON %I.%I FROM %I',
            OLD.permission, OLD.schema_name,
            OLD.object_name, OLD.role_name);
      END IF;
   ELSIF OLD.object_type = 'COLUMN'
   THEN
      IF NOT OLD.granted
      THEN
         cmd := pg_catalog.format('GRANT %s(%I) ON %I.%I TO %I',
            OLD.permission, OLD.column_name,
            OLD.schema_name, OLD.object_name,
            OLD.role_name);
      ELSE
         cmd := pg_catalog.format('REVOKE %s(%I) ON %I.%I FROM %I',
            OLD.permission, OLD.column_name,
            OLD.schema_name, OLD.object_name,
            OLD.role_name);
      END IF;
   ELSIF OLD.object_type = 'SEQUENCE'
   THEN
      IF NOT OLD.granted
      THEN
         cmd := pg_catalog.format('GRANT %s ON SEQUENCE %I.%I TO %I',
            OLD.permission, OLD.schema_name,
            OLD.object_name, OLD.role_name);
      ELSE
         cmd := pg_catalog.format('REVOKE %s ON SEQUENCE %I.%I FROM %I',
            OLD.permission, OLD.schema_name,
            OLD.object_name, OLD.role_name);
      END IF;
   ELSIF OLD.object_type = 'FUNCTION'
   THEN
      /*
       * "object_name" contains the argument list; resolve the whole thing
       * to regprocedure so that all identifiers are quoted correctly.
       * "ROUTINE" is used instead of "FUNCTION" because the views also
       * contain procedures, for which "FUNCTION" does not work.
       */
      func := pg_catalog.format('%I.%s', OLD.schema_name,
                                OLD.object_name)::pg_catalog.regprocedure;

      IF NOT OLD.granted
      THEN
         cmd := pg_catalog.format('GRANT %s ON ROUTINE %s TO %I',
            OLD.permission, func, OLD.role_name);
      ELSE
         cmd := pg_catalog.format('REVOKE %s ON ROUTINE %s FROM %I',
            OLD.permission, func, OLD.role_name);
      END IF;
   ELSIF OLD.object_type = 'SCHEMA'
   THEN
      IF NOT OLD.granted
      THEN
         cmd := pg_catalog.format('GRANT %s ON SCHEMA %I TO %I',
            OLD.permission, OLD.schema_name,
            OLD.role_name);
      ELSE
         cmd := pg_catalog.format('REVOKE %s ON SCHEMA %I FROM %I',
            OLD.permission, OLD.schema_name,
            OLD.role_name);
      END IF;
   ELSIF OLD.object_type = 'DATABASE'
   THEN
      db_name := pg_catalog.current_database();

      IF NOT OLD.granted
      THEN
         cmd := pg_catalog.format('GRANT %s ON DATABASE %I TO %I',
            OLD.permission, db_name, OLD.role_name);
      ELSE
         cmd := pg_catalog.format('REVOKE %s ON DATABASE %I FROM %I',
            OLD.permission, db_name, OLD.role_name);
      END IF;
   ELSE
      RAISE 'Unrecognized object type: %',
         OLD.object_type;
   END IF;

   EXECUTE cmd;
   RETURN NEW;
END;
$$;

CREATE TRIGGER permissions_trigger
   INSTEAD OF UPDATE ON table_permissions
   FOR EACH ROW EXECUTE PROCEDURE permissions_trigger_func();

CREATE TRIGGER permissions_trigger
   INSTEAD OF UPDATE ON column_permissions
   FOR EACH ROW EXECUTE PROCEDURE permissions_trigger_func();

CREATE TRIGGER permissions_trigger
   INSTEAD OF UPDATE ON view_permissions
   FOR EACH ROW EXECUTE PROCEDURE permissions_trigger_func();

CREATE TRIGGER permissions_trigger
   INSTEAD OF UPDATE ON sequence_permissions
   FOR EACH ROW EXECUTE PROCEDURE permissions_trigger_func();

CREATE TRIGGER permissions_trigger
   INSTEAD OF UPDATE ON function_permissions
   FOR EACH ROW EXECUTE PROCEDURE permissions_trigger_func();

CREATE TRIGGER permissions_trigger
   INSTEAD OF UPDATE ON schema_permissions
   FOR EACH ROW EXECUTE PROCEDURE permissions_trigger_func();

CREATE TRIGGER permissions_trigger
   INSTEAD OF UPDATE ON database_permissions
   FOR EACH ROW EXECUTE PROCEDURE permissions_trigger_func();

CREATE TRIGGER permissions_trigger
   INSTEAD OF UPDATE ON all_permissions
   FOR EACH ROW EXECUTE PROCEDURE permissions_trigger_func();

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
                  AND ARRAY['SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER','MAINTAIN']::perm_type[] @> permissions
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

CREATE SEQUENCE permission_target_id_seq OWNED BY permission_target.id;
ALTER TABLE permission_target ALTER id
   SET DEFAULT nextval('permission_target_id_seq'::regclass);

GRANT SELECT, INSERT, UPDATE, DELETE ON permission_target TO PUBLIC;
GRANT USAGE ON SEQUENCE permission_target_id_seq TO PUBLIC;

SELECT pg_catalog.pg_extension_config_dump('permission_target', '');
SELECT pg_catalog.pg_extension_config_dump('permission_target_id_seq', '');

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
   LANGUAGE sql SET search_path FROM CURRENT AS
$$
/* permissions that should be granted but are not */
SELECT DISTINCT TRUE AS missing,
       pt.role_name,
       pt.object_type,
       apm.schema_name,
       apm.object_name,
       apm.column_name,
       p.permission
   FROM permission_target AS pt
      CROSS JOIN LATERAL unnest(pt.permissions) AS p(permission)
      JOIN all_permissions AS apm
         ON apm.object_type = pt.object_type
        AND (apm.schema_name = pt.schema_name OR pt.schema_name IS NULL)
        AND (apm.object_name = pt.object_name OR pt.object_name IS NULL)
        AND (apm.column_name = pt.column_name OR pt.column_name IS NULL)
   WHERE apm.role_name = pt.role_name
     AND apm.permission = p.permission
     AND NOT apm.granted
     /*
      * "column_permissions.granted" is false for a privilege that is held
      * at the table level; such a privilege is not missing.
      */
     AND NOT (apm.object_type = 'COLUMN'
              AND pg_catalog.has_table_privilege(
                     pg_catalog.quote_ident(apm.role_name::text)::pg_catalog.regrole,
                     pg_catalog.to_regclass(
                        pg_catalog.format('%I.%I', apm.schema_name,
                                          apm.object_name)),
                     apm.permission::text))
UNION
/* permissions that are granted but should not be */
SELECT DISTINCT FALSE AS missing,
       apm.role_name,
       apm.object_type,
       apm.schema_name,
       apm.object_name,
       apm.column_name,
       apm.permission
   FROM permission_target AS pt
      JOIN all_permissions AS apm
         ON apm.object_type = pt.object_type
        AND (apm.schema_name = pt.schema_name OR pt.schema_name IS NULL)
        AND (apm.object_name = pt.object_name OR pt.object_name IS NULL)
        AND (apm.column_name = pt.column_name OR pt.column_name IS NULL)
   WHERE apm.granted
     AND NOT (apm.role_name = pt.role_name
              AND apm.permission = ANY (pt.permissions))
     AND NOT EXISTS (
              SELECT 1
              FROM permission_target AS pt2
              WHERE pt2.role_name = apm.role_name
                AND pt2.permissions @> ARRAY[apm.permission]::perm_type[]
                AND (   pt2.object_type = apm.object_type
                     OR (apm.object_type = 'COLUMN'
                         AND pt2.object_type IN ('TABLE', 'VIEW')))
                AND (pt2.schema_name IS NULL OR pt2.schema_name = apm.schema_name)
                AND (pt2.object_name IS NULL OR pt2.object_name = apm.object_name)
                AND (pt2.column_name IS NULL OR pt2.column_name = apm.column_name)
           );
$$;
