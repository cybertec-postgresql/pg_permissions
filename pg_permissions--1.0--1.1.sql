-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "ALTER EXTENSION pg_permissions UPDATE" to load this file. \quit

/* rename some view columns to match the other views */

DROP VIEW all_permissions;
DROP VIEW schema_permissions;
DROP VIEW database_permissions;

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
BEGIN
   IF NEW.object_type <> OLD.object_type OR
      NEW.role_name <> OLD.role_name OR
      NEW.schema_name <> OLD.schema_name OR
      NEW.object_name <> OLD.object_name OR
      NEW.column_name <> OLD.column_name OR
      NEW.permission <> OLD.permission
   THEN
      RAISE 'Only the "granted" column may be updated';
   END IF;

   -- Is there anything to do at all?
   IF NEW.granted = OLD.granted
   THEN
      RETURN NEW;
   END IF;

   IF OLD.object_type IN ('TABLE', 'VIEW')
   THEN
      IF NOT OLD.granted
      THEN
         cmd := format('GRANT %s ON %s.%s TO %s',
            OLD.permission, OLD.schema_name,
            OLD.object_name, OLD.role_name);
      ELSE
         cmd := format('REVOKE %s ON %s.%s FROM %s',
            OLD.permission, OLD.schema_name,
            OLD.object_name, OLD.role_name);
      END IF;
   ELSIF OLD.object_type = 'COLUMN'
   THEN
      IF NOT OLD.granted
      THEN
         cmd := format('GRANT %s(%s) ON %s.%s TO %s',
            OLD.permission, OLD.column_name,
            OLD.schema_name, OLD.object_name,
            OLD.role_name);
      ELSE
         cmd := format('REVOKE %s(%s) ON %s.%s FROM %s',
            OLD.permission, OLD.column_name,
            OLD.schema_name, OLD.object_name,
            OLD.role_name);
      END IF;
   ELSIF OLD.object_type = 'SEQUENCE'
   THEN
      IF NOT OLD.granted
      THEN
         cmd := format('GRANT %s ON SEQUENCE %s.%s TO %s',
            OLD.permission, OLD.schema_name,
            OLD.object_name, OLD.role_name);
      ELSE
         cmd := format('REVOKE %s ON SEQUENCE %s.%s FROM %s',
            OLD.permission, OLD.schema_name,
            OLD.object_name, OLD.role_name);
      END IF;
   ELSIF OLD.object_type = 'FUNCTION'
   THEN
      IF NOT OLD.granted
      THEN
         cmd := format('GRANT %s ON FUNCTION %s.%s TO %s',
            OLD.permission, OLD.schema_name,
            OLD.object_name, OLD.role_name);
      ELSE
         cmd := format('REVOKE %s ON FUNCTION %s.%s FROM %s',
            OLD.permission, OLD.schema_name,
            OLD.object_name, OLD.role_name);
      END IF;
   ELSIF OLD.object_type = 'SCHEMA'
   THEN
      IF NOT OLD.granted
      THEN
         cmd := format('GRANT %s ON SCHEMA %s TO %s',
            OLD.permission, OLD.schema_name,
            OLD.role_name);
      ELSE
         cmd := format('REVOKE %s ON SCHEMA %s FROM %s',
            OLD.permission, OLD.schema_name,
            OLD.role_name);
      END IF;
   ELSIF OLD.object_type = 'DATABASE'
   THEN
      db_name := pg_catalog.current_database();

      IF NOT OLD.granted
      THEN
         cmd := format('GRANT %s ON DATABASE %s TO %s',
            OLD.permission, db_name, OLD.role_name);
      ELSE
         cmd := format('REVOKE %s ON DATABASE %s FROM %s',
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
