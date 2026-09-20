-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "ALTER EXTENSION pg_permissions UPDATE" to load this file. \quit

/*
 * "table_permissions" also contains partitioned tables and foreign tables,
 * "view_permissions" also contains materialized views, and
 * "column_permissions" covers all of these object types.
 */

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
  AND t.relkind IN ('r', 'p', 'f')
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
  AND t.relkind IN ('v', 'm')
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
  AND t.relkind IN ('r', 'v', 'm', 'p', 'f')
  AND NOT r.rolsuper;


/* the unused "list" CTE is gone */

CREATE OR REPLACE VIEW database_permissions AS
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


/*
 * The trigger function
 * - compares keys with "IS DISTINCT FROM" so that NULL keys cannot be
 *   changed unnoticed,
 * - quotes all identifiers, and
 * - uses "ROUTINE" for functions and procedures.
 */

CREATE OR REPLACE FUNCTION permissions_trigger_func()
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


/*
 * "permission_diffs()" is a plain SQL function now; it no longer uses a
 * temporary table, so it can be called more than once per transaction.
 * Column privileges that are held at the table level are no longer
 * reported as missing, and table level targets cover column targets.
 */

CREATE OR REPLACE FUNCTION permission_diffs()
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
