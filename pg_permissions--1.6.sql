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

/* helpers */

/*
 * Is "permission" held by "role_oid" on the object?  A "role_oid" of 0 means
 * PUBLIC, which the has_*_privilege functions understand.
 *
 * The function is deliberately not marked with SET search_path so that the
 * planner can inline it; every name is schema-qualified instead.
 */
CREATE FUNCTION permission_granted(
   role_oid oid, object_type obj_type, obj_oid oid, attnum int2, permission perm_type)
RETURNS boolean
LANGUAGE sql STABLE
AS $$
   SELECT CASE object_type
      WHEN 'TABLE'    THEN pg_catalog.has_table_privilege(role_oid, obj_oid, permission::text)
      WHEN 'VIEW'     THEN pg_catalog.has_table_privilege(role_oid, obj_oid, permission::text)
      WHEN 'COLUMN'   THEN pg_catalog.has_column_privilege(role_oid, obj_oid, attnum, permission::text)
      WHEN 'SEQUENCE' THEN pg_catalog.has_sequence_privilege(role_oid, obj_oid, permission::text)
      WHEN 'FUNCTION' THEN pg_catalog.has_function_privilege(role_oid, obj_oid, permission::text)
      WHEN 'SCHEMA'   THEN pg_catalog.has_schema_privilege(role_oid, obj_oid, permission::text)
      WHEN 'DATABASE' THEN pg_catalog.has_database_privilege(role_oid, obj_oid, permission::text)
   END
$$;

/*
 * Like permission_granted(), but a column privilege that is already held at
 * the table level is not reported.  This is what the views display.
 */
CREATE FUNCTION permission_visible(
   role_oid oid, object_type obj_type, obj_oid oid, attnum int2, permission perm_type)
RETURNS boolean
LANGUAGE sql STABLE
AS $$
   SELECT permission_granted(role_oid, object_type, obj_oid, attnum, permission)
      AND NOT (object_type = 'COLUMN'
               AND permission_granted(role_oid, 'TABLE', obj_oid, NULL, permission))
$$;

/*
 * The owner and the effective ACL of an object.  For a column the column ACL
 * is combined with the table ACL, because a column privilege can be held at
 * either level.
 */
CREATE FUNCTION permission_acl(object_type obj_type, obj_oid oid, col_attnum int2)
RETURNS TABLE (owner oid, acl aclitem[])
LANGUAGE sql STABLE
AS $$
   SELECT c.relowner,
          CASE object_type
             WHEN 'COLUMN' THEN COALESCE(a.attacl, '{}'::aclitem[])
                                || COALESCE(c.relacl, acldefault('r', c.relowner))
             WHEN 'SEQUENCE' THEN COALESCE(c.relacl, acldefault('S', c.relowner))
             ELSE COALESCE(c.relacl, acldefault('r', c.relowner))
          END
   FROM pg_catalog.pg_class AS c
      LEFT JOIN pg_catalog.pg_attribute AS a
         ON a.attrelid = c.oid AND a.attnum = col_attnum
   WHERE object_type IN ('TABLE', 'VIEW', 'COLUMN', 'SEQUENCE')
     AND c.oid = obj_oid
   UNION ALL
   SELECT p.proowner, COALESCE(p.proacl, acldefault('f', p.proowner))
   FROM pg_catalog.pg_proc AS p
   WHERE object_type = 'FUNCTION' AND p.oid = obj_oid
   UNION ALL
   SELECT n.nspowner, COALESCE(n.nspacl, acldefault('n', n.nspowner))
   FROM pg_catalog.pg_namespace AS n
   WHERE object_type = 'SCHEMA' AND n.oid = obj_oid
   UNION ALL
   SELECT d.datdba, COALESCE(d.datacl, acldefault('d', d.datdba))
   FROM pg_catalog.pg_database AS d
   WHERE object_type = 'DATABASE' AND d.oid = obj_oid
$$;

/*
 * Why does a role hold a privilege?  Returns 'owner', 'direct', 'PUBLIC',
 * 'role:<name>' for a privilege inherited through role membership, or NULL
 * when the privilege is not held at all.
 */
CREATE FUNCTION permission_source(
   role_oid oid, object_type obj_type, obj_oid oid, col_attnum int2, permission perm_type)
RETURNS text
LANGUAGE sql STABLE
AS $$
   WITH obj AS (
      SELECT a.owner, a.acl
      FROM permission_acl(object_type, obj_oid, col_attnum) AS a
   ),
   grants AS (
      SELECT x.grantee
      FROM obj, LATERAL pg_catalog.aclexplode(obj.acl) AS x
      WHERE x.privilege_type = permission::text
   )
   SELECT CASE
      WHEN NOT permission_granted(role_oid, object_type, obj_oid, col_attnum, permission)
         THEN NULL
      WHEN role_oid = (SELECT owner FROM obj) THEN 'owner'
      WHEN EXISTS (SELECT 1 FROM grants WHERE grantee = role_oid) THEN 'direct'
      WHEN EXISTS (SELECT 1 FROM grants WHERE grantee = 0) THEN 'PUBLIC'
      ELSE (SELECT 'role:' || r.rolname
            FROM grants AS g
               JOIN pg_catalog.pg_roles AS r ON r.oid = g.grantee
            WHERE pg_catalog.pg_has_role(role_oid, g.grantee, 'MEMBER')
            ORDER BY r.rolname
            LIMIT 1)
   END
$$;

/*
 * Is the object part of this extension?  Used by permission_target_snapshot()
 * so that the extension does not baseline its own tables and views.
 */
CREATE FUNCTION permission_is_extension_object(object_type obj_type, obj_oid oid)
RETURNS boolean
LANGUAGE sql STABLE
AS $$
   SELECT EXISTS (
      SELECT 1
      FROM pg_catalog.pg_depend AS d
      WHERE d.objid = obj_oid
        AND d.classid = CASE object_type
                           WHEN 'SCHEMA'   THEN 'pg_catalog.pg_namespace'::regclass
                           WHEN 'FUNCTION' THEN 'pg_catalog.pg_proc'::regclass
                           ELSE                 'pg_catalog.pg_class'::regclass
                        END
        AND d.refclassid = 'pg_catalog.pg_extension'::regclass
        AND d.refobjid = (SELECT oid FROM pg_catalog.pg_extension
                          WHERE extname = 'pg_permissions')
   )
$$;

/*
 * The roles the views report on: every non-superuser role plus PUBLIC.
 * PUBLIC is not a row in pg_roles, but the has_*_privilege functions accept
 * the oid 0 for it, so it can be modelled as a pseudo-role.
 */
CREATE FUNCTION permission_roles()
RETURNS TABLE (oid oid, rolname name)
LANGUAGE sql STABLE
AS $$
   SELECT r.oid, r.rolname
   FROM pg_catalog.pg_roles AS r
   WHERE NOT r.rolsuper
   UNION ALL
   SELECT 0::oid, 'PUBLIC'::name
$$;

/*
 * The universe of (object, privilege) pairs, independent of roles.  Keeping
 * this in one place means the views and permission_diffs() cannot drift
 * apart, and lets the planner prune the UNION branches that a caller does
 * not need.
 */
CREATE FUNCTION permission_objects()
RETURNS TABLE (object_type obj_type, schema_name name, object_name text,
               column_name name, permission perm_type, obj_oid oid, attnum int2)
LANGUAGE sql STABLE
AS $$
   SELECT obj_type 'TABLE', t.relnamespace::regnamespace::name, t.relname::text,
          NULL::name, p.perm::perm_type, t.oid, NULL::int2
   FROM pg_catalog.pg_class AS t
      CROSS JOIN unnest(
         CASE WHEN current_setting('server_version_num')::integer < 170000
              THEN ARRAY['SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER']
              ELSE ARRAY['SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER','MAINTAIN']
         END) AS p(perm)
   WHERE t.relnamespace::regnamespace::name <> 'information_schema'
     AND t.relnamespace::regnamespace::name NOT LIKE 'pg\_%'
     AND t.relkind IN ('r', 'p', 'f')
   UNION ALL
   SELECT obj_type 'VIEW', t.relnamespace::regnamespace::name, t.relname::text,
          NULL::name, p.perm::perm_type, t.oid, NULL::int2
   FROM pg_catalog.pg_class AS t
      CROSS JOIN unnest(
         CASE WHEN current_setting('server_version_num')::integer < 170000
              THEN ARRAY['SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER']
              ELSE ARRAY['SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER','MAINTAIN']
         END) AS p(perm)
   WHERE t.relnamespace::regnamespace::name <> 'information_schema'
     AND t.relnamespace::regnamespace::name NOT LIKE 'pg\_%'
     AND t.relkind IN ('v', 'm')
   UNION ALL
   SELECT obj_type 'COLUMN', t.relnamespace::regnamespace::name, t.relname::text,
          c.attname, p.perm::perm_type, t.oid, c.attnum
   FROM pg_catalog.pg_class AS t
      JOIN pg_catalog.pg_attribute AS c ON t.oid = c.attrelid
      CROSS JOIN (VALUES ('SELECT'), ('INSERT'), ('UPDATE'), ('REFERENCES')) AS p(perm)
   WHERE t.relnamespace::regnamespace::name <> 'information_schema'
     AND t.relnamespace::regnamespace::name NOT LIKE 'pg\_%'
     AND c.attnum > 0 AND NOT c.attisdropped
     AND t.relkind IN ('r', 'v', 'm', 'p', 'f')
   UNION ALL
   SELECT obj_type 'SEQUENCE', t.relnamespace::regnamespace::name, t.relname::text,
          NULL::name, p.perm::perm_type, t.oid, NULL::int2
   FROM pg_catalog.pg_class AS t
      CROSS JOIN (VALUES ('SELECT'), ('USAGE'), ('UPDATE')) AS p(perm)
   WHERE t.relnamespace::regnamespace::name <> 'information_schema'
     AND t.relnamespace::regnamespace::name NOT LIKE 'pg\_%'
     AND t.relkind = 'S'
   UNION ALL
   SELECT obj_type 'FUNCTION', f.pronamespace::regnamespace::name,
          regexp_replace(f.oid::regprocedure::text, '^((("[^"]*")|([^"][^.]*))\.)?', ''),
          NULL::name, perm_type 'EXECUTE', f.oid, NULL::int2
   FROM pg_catalog.pg_proc AS f
   WHERE f.pronamespace::regnamespace::name <> 'information_schema'
     AND f.pronamespace::regnamespace::name NOT LIKE 'pg\_%'
   UNION ALL
   SELECT obj_type 'SCHEMA', n.nspname, NULL::text, NULL::name,
          p.perm::perm_type, n.oid, NULL::int2
   FROM pg_catalog.pg_namespace AS n
      CROSS JOIN (VALUES ('USAGE'), ('CREATE')) AS p(perm)
   WHERE n.nspname <> 'information_schema'
     AND n.nspname NOT LIKE 'pg\_%'
   UNION ALL
   SELECT obj_type 'DATABASE', NULL::name, NULL::text, NULL::name,
          p.perm::perm_type, d.oid, NULL::int2
   FROM pg_catalog.pg_database AS d
      CROSS JOIN (VALUES ('CREATE'), ('CONNECT'), ('TEMPORARY')) AS p(perm)
   WHERE d.datname = current_database()
$$;

/* views for the actual permissions */

CREATE VIEW table_permissions AS
SELECT o.object_type,
       r.rolname AS role_name,
       o.schema_name,
       o.object_name COLLATE "C",
       o.column_name,
       o.permission,
       g.granted,
       s.source
FROM permission_objects() AS o
   CROSS JOIN permission_roles() AS r
   CROSS JOIN LATERAL (
      SELECT permission_visible(r.oid, o.object_type, o.obj_oid, o.attnum, o.permission) AS granted
   ) AS g
   CROSS JOIN LATERAL (
      SELECT CASE WHEN g.granted
                  THEN permission_source(r.oid, o.object_type, o.obj_oid, o.attnum, o.permission)
             END AS source
   ) AS s
WHERE o.object_type = 'TABLE';

GRANT SELECT ON table_permissions TO PUBLIC;

CREATE VIEW view_permissions AS
SELECT o.object_type,
       r.rolname AS role_name,
       o.schema_name,
       o.object_name COLLATE "C",
       o.column_name,
       o.permission,
       g.granted,
       s.source
FROM permission_objects() AS o
   CROSS JOIN permission_roles() AS r
   CROSS JOIN LATERAL (
      SELECT permission_visible(r.oid, o.object_type, o.obj_oid, o.attnum, o.permission) AS granted
   ) AS g
   CROSS JOIN LATERAL (
      SELECT CASE WHEN g.granted
                  THEN permission_source(r.oid, o.object_type, o.obj_oid, o.attnum, o.permission)
             END AS source
   ) AS s
WHERE o.object_type = 'VIEW';

GRANT SELECT ON view_permissions TO PUBLIC;

CREATE VIEW column_permissions AS
SELECT o.object_type,
       r.rolname AS role_name,
       o.schema_name,
       o.object_name COLLATE "C",
       o.column_name,
       o.permission,
       g.granted,
       s.source
FROM permission_objects() AS o
   CROSS JOIN permission_roles() AS r
   CROSS JOIN LATERAL (
      SELECT permission_visible(r.oid, o.object_type, o.obj_oid, o.attnum, o.permission) AS granted
   ) AS g
   CROSS JOIN LATERAL (
      SELECT CASE WHEN g.granted
                  THEN permission_source(r.oid, o.object_type, o.obj_oid, o.attnum, o.permission)
             END AS source
   ) AS s
WHERE o.object_type = 'COLUMN';

GRANT SELECT ON column_permissions TO PUBLIC;

CREATE VIEW sequence_permissions AS
SELECT o.object_type,
       r.rolname AS role_name,
       o.schema_name,
       o.object_name COLLATE "C",
       o.column_name,
       o.permission,
       g.granted,
       s.source
FROM permission_objects() AS o
   CROSS JOIN permission_roles() AS r
   CROSS JOIN LATERAL (
      SELECT permission_visible(r.oid, o.object_type, o.obj_oid, o.attnum, o.permission) AS granted
   ) AS g
   CROSS JOIN LATERAL (
      SELECT CASE WHEN g.granted
                  THEN permission_source(r.oid, o.object_type, o.obj_oid, o.attnum, o.permission)
             END AS source
   ) AS s
WHERE o.object_type = 'SEQUENCE';

GRANT SELECT ON sequence_permissions TO PUBLIC;

CREATE VIEW function_permissions AS
SELECT o.object_type,
       r.rolname AS role_name,
       o.schema_name,
       o.object_name,
       o.column_name,
       o.permission,
       g.granted,
       s.source
FROM permission_objects() AS o
   CROSS JOIN permission_roles() AS r
   CROSS JOIN LATERAL (
      SELECT permission_visible(r.oid, o.object_type, o.obj_oid, o.attnum, o.permission) AS granted
   ) AS g
   CROSS JOIN LATERAL (
      SELECT CASE WHEN g.granted
                  THEN permission_source(r.oid, o.object_type, o.obj_oid, o.attnum, o.permission)
             END AS source
   ) AS s
WHERE o.object_type = 'FUNCTION';

GRANT SELECT ON function_permissions TO PUBLIC;

CREATE VIEW schema_permissions AS
SELECT o.object_type,
       r.rolname AS role_name,
       o.schema_name,
       o.object_name,
       o.column_name,
       o.permission,
       g.granted,
       s.source
FROM permission_objects() AS o
   CROSS JOIN permission_roles() AS r
   CROSS JOIN LATERAL (
      SELECT permission_visible(r.oid, o.object_type, o.obj_oid, o.attnum, o.permission) AS granted
   ) AS g
   CROSS JOIN LATERAL (
      SELECT CASE WHEN g.granted
                  THEN permission_source(r.oid, o.object_type, o.obj_oid, o.attnum, o.permission)
             END AS source
   ) AS s
WHERE o.object_type = 'SCHEMA';

GRANT SELECT ON schema_permissions TO PUBLIC;

CREATE VIEW database_permissions AS
SELECT o.object_type,
       r.rolname AS role_name,
       o.schema_name,
       o.object_name,
       o.column_name,
       o.permission,
       g.granted,
       s.source
FROM permission_objects() AS o
   CROSS JOIN permission_roles() AS r
   CROSS JOIN LATERAL (
      SELECT permission_visible(r.oid, o.object_type, o.obj_oid, o.attnum, o.permission) AS granted
   ) AS g
   CROSS JOIN LATERAL (
      SELECT CASE WHEN g.granted
                  THEN permission_source(r.oid, o.object_type, o.obj_oid, o.attnum, o.permission)
             END AS source
   ) AS s
WHERE o.object_type = 'DATABASE';

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

/*
 * The GRANT or REVOKE statement that would bring one row of
 * permission_diffs() into line.  "missing" is TRUE when the privilege
 * should be granted.
 */
CREATE FUNCTION permission_sql(
   missing boolean, role_name name, object_type obj_type,
   schema_name name, object_name text, column_name name, permission perm_type)
RETURNS text
LANGUAGE plpgsql IMMUTABLE
AS $$
DECLARE
   role_sql text;
   func     pg_catalog.regprocedure;
   db_name  text;
BEGIN
   -- PUBLIC is a keyword, not an identifier, so it must not be quoted
   role_sql := CASE WHEN role_name = 'PUBLIC' THEN 'PUBLIC'
                    ELSE pg_catalog.format('%I', role_name) END;

   -- all identifiers are quoted with %I to make the statement safe
   -- for names that need quoting
   IF object_type IN ('TABLE', 'VIEW')
   THEN
      IF missing
      THEN
         RETURN pg_catalog.format('GRANT %s ON %I.%I TO %s',
            permission, schema_name, object_name, role_sql);
      ELSE
         RETURN pg_catalog.format('REVOKE %s ON %I.%I FROM %s',
            permission, schema_name, object_name, role_sql);
      END IF;
   ELSIF object_type = 'COLUMN'
   THEN
      IF missing
      THEN
         RETURN pg_catalog.format('GRANT %s(%I) ON %I.%I TO %s',
            permission, column_name, schema_name, object_name, role_sql);
      ELSE
         RETURN pg_catalog.format('REVOKE %s(%I) ON %I.%I FROM %s',
            permission, column_name, schema_name, object_name, role_sql);
      END IF;
   ELSIF object_type = 'SEQUENCE'
   THEN
      IF missing
      THEN
         RETURN pg_catalog.format('GRANT %s ON SEQUENCE %I.%I TO %s',
            permission, schema_name, object_name, role_sql);
      ELSE
         RETURN pg_catalog.format('REVOKE %s ON SEQUENCE %I.%I FROM %s',
            permission, schema_name, object_name, role_sql);
      END IF;
   ELSIF object_type = 'FUNCTION'
   THEN
      /*
       * "object_name" contains the argument list; resolve the whole thing
       * to regprocedure so that all identifiers are quoted correctly.
       * "ROUTINE" is used instead of "FUNCTION" because the views also
       * contain procedures, for which "FUNCTION" does not work.
       */
      func := pg_catalog.format('%I.%s', schema_name,
                                object_name)::pg_catalog.regprocedure;

      IF missing
      THEN
         RETURN pg_catalog.format('GRANT %s ON ROUTINE %s TO %s',
            permission, func, role_sql);
      ELSE
         RETURN pg_catalog.format('REVOKE %s ON ROUTINE %s FROM %s',
            permission, func, role_sql);
      END IF;
   ELSIF object_type = 'SCHEMA'
   THEN
      IF missing
      THEN
         RETURN pg_catalog.format('GRANT %s ON SCHEMA %I TO %s',
            permission, schema_name, role_sql);
      ELSE
         RETURN pg_catalog.format('REVOKE %s ON SCHEMA %I FROM %s',
            permission, schema_name, role_sql);
      END IF;
   ELSIF object_type = 'DATABASE'
   THEN
      db_name := pg_catalog.current_database();

      IF missing
      THEN
         RETURN pg_catalog.format('GRANT %s ON DATABASE %I TO %s',
            permission, db_name, role_sql);
      ELSE
         RETURN pg_catalog.format('REVOKE %s ON DATABASE %I FROM %s',
            permission, db_name, role_sql);
      END IF;
   ELSE
      RAISE 'Unrecognized object type: %', object_type;
   END IF;
END;
$$;

CREATE FUNCTION permissions_trigger_func()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
   -- "IS DISTINCT FROM" so that keys that are NULL (e.g. "object_name"
   -- for schemas and databases) are compared correctly
   IF NEW.object_type IS DISTINCT FROM OLD.object_type OR
      NEW.role_name IS DISTINCT FROM OLD.role_name OR
      NEW.schema_name IS DISTINCT FROM OLD.schema_name OR
      NEW.object_name IS DISTINCT FROM OLD.object_name OR
      NEW.column_name IS DISTINCT FROM OLD.column_name OR
      NEW.permission IS DISTINCT FROM OLD.permission OR
      NEW.source IS DISTINCT FROM OLD.source
   THEN
      RAISE 'Only the "granted" column may be updated';
   END IF;

   -- Is there anything to do at all?
   IF NEW.granted = OLD.granted
   THEN
      RETURN NEW;
   END IF;

   EXECUTE permission_sql(NOT OLD.granted, OLD.role_name, OLD.object_type,
                          OLD.schema_name, OLD.object_name, OLD.column_name,
                          OLD.permission);
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
   column_name    name,
   CONSTRAINT permission_target_valid
   CHECK (cardinality(permissions) > 0
          AND CASE WHEN object_type = 'DATABASE'
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
                   THEN column_name IS NOT NULL
                      AND ARRAY['SELECT','INSERT','UPDATE','REFERENCES']::perm_type[] @> permissions
              END),
   -- NULLS NOT DISTINCT so that a target for a database or a whole schema
   -- (where the key columns are NULL) cannot be entered twice
   CONSTRAINT permission_target_unique
   UNIQUE NULLS NOT DISTINCT (role_name, object_type, schema_name, object_name, column_name)
);

CREATE SEQUENCE permission_target_id_seq OWNED BY permission_target.id;
ALTER TABLE permission_target ALTER id
   SET DEFAULT nextval('permission_target_id_seq'::regclass);

/*
 * The CHECK constraint cannot look at server_version_num (it is not
 * immutable), so the version-dependent and catalog-dependent parts of the
 * validation live in a trigger.
 */
CREATE FUNCTION permission_target_check()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
   allowed perm_type[];
BEGIN
   IF cardinality(NEW.permissions) = 0 THEN
      RAISE EXCEPTION 'the permission list must not be empty';
   END IF;

   CASE NEW.object_type
      WHEN 'DATABASE' THEN
         allowed := ARRAY['CONNECT','CREATE','TEMPORARY']::perm_type[];
         IF NEW.schema_name IS NOT NULL OR NEW.object_name IS NOT NULL
            OR NEW.column_name IS NOT NULL
         THEN
            RAISE EXCEPTION 'a DATABASE target must not set schema_name, object_name or column_name';
         END IF;
      WHEN 'SCHEMA' THEN
         allowed := ARRAY['CREATE','USAGE']::perm_type[];
         IF NEW.object_name IS NOT NULL OR NEW.column_name IS NOT NULL THEN
            RAISE EXCEPTION 'a SCHEMA target must not set object_name or column_name';
         END IF;
      WHEN 'TABLE', 'VIEW' THEN
         allowed := ARRAY['SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER','MAINTAIN']::perm_type[];
         IF NEW.column_name IS NOT NULL THEN
            RAISE EXCEPTION 'a % target must not set column_name', NEW.object_type;
         END IF;
      WHEN 'SEQUENCE' THEN
         allowed := ARRAY['SELECT','USAGE','UPDATE']::perm_type[];
         IF NEW.column_name IS NOT NULL THEN
            RAISE EXCEPTION 'a SEQUENCE target must not set column_name';
         END IF;
      WHEN 'FUNCTION' THEN
         allowed := ARRAY['EXECUTE']::perm_type[];
         IF NEW.column_name IS NOT NULL THEN
            RAISE EXCEPTION 'a FUNCTION target must not set column_name';
         END IF;
      WHEN 'COLUMN' THEN
         allowed := ARRAY['SELECT','INSERT','UPDATE','REFERENCES']::perm_type[];
         IF NEW.column_name IS NULL THEN
            RAISE EXCEPTION 'a COLUMN target requires column_name';
         END IF;
   END CASE;

   IF NOT allowed @> NEW.permissions THEN
      RAISE EXCEPTION 'invalid permission for a % target: %',
         NEW.object_type,
         ARRAY(SELECT unnest(NEW.permissions)
               EXCEPT
               SELECT unnest(allowed));
   END IF;

   IF current_setting('server_version_num')::integer < 170000
      AND 'MAINTAIN'::perm_type = ANY (NEW.permissions)
   THEN
      RAISE EXCEPTION 'the MAINTAIN privilege requires PostgreSQL 17 or later';
   END IF;

   IF NEW.role_name <> 'PUBLIC'
      AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = NEW.role_name)
   THEN
      RAISE EXCEPTION 'role "%" does not exist', NEW.role_name;
   END IF;

   RETURN NEW;
END;
$$;

CREATE TRIGGER permission_target_check
   BEFORE INSERT OR UPDATE ON permission_target
   FOR EACH ROW EXECUTE PROCEDURE permission_target_check();

/*
 * The desired state is a compliance baseline, so it must not be writable by
 * every role.  Everybody may read it (permission_diffs() needs that), but
 * only the extension owner and roles that are explicitly granted write
 * access may change it.
 */
REVOKE ALL ON permission_target FROM PUBLIC;
GRANT SELECT ON permission_target TO PUBLIC;
REVOKE ALL ON SEQUENCE permission_target_id_seq FROM PUBLIC;

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
   LANGUAGE sql STABLE SET search_path FROM CURRENT AS
$$
WITH
/*
 * Only roles that appear in permission_target are managed, plus the roles
 * that inherit from them: a member of a managed role is effectively managed
 * too, otherwise a direct grant to the member would go unnoticed.
 * Restricting the scan to them is what keeps the cost proportional to the
 * size of the desired state rather than to objects x roles x privileges.
 */
managed_roles AS (
   SELECT r.oid, r.rolname
   FROM permission_roles() AS r
   WHERE EXISTS (
            SELECT 1
            FROM permission_target AS pt
               JOIN permission_roles() AS pr ON pr.rolname = pt.role_name
            WHERE pt.role_name = r.rolname
               OR pg_catalog.pg_has_role(r.oid, pr.oid, 'MEMBER')
         )
),
objects AS (
   SELECT o.*
   FROM permission_objects() AS o
   WHERE o.object_type IN (SELECT DISTINCT pt.object_type FROM permission_target AS pt)
),
/* permissions that should be granted but are not */
missing AS (
   SELECT DISTINCT TRUE AS missing,
          pt.role_name,
          o.object_type,
          o.schema_name,
          o.object_name COLLATE "C",
          o.column_name,
          o.permission
   FROM permission_target AS pt
      JOIN permission_roles() AS r ON r.rolname = pt.role_name
      CROSS JOIN LATERAL unnest(pt.permissions) AS p(permission)
      JOIN objects AS o
         ON o.object_type = pt.object_type
        AND o.permission = p.permission
        AND (pt.schema_name IS NULL OR o.schema_name = pt.schema_name)
        AND (pt.object_name IS NULL OR o.object_name = pt.object_name)
        AND (pt.column_name IS NULL OR o.column_name = pt.column_name)
   WHERE NOT permission_granted(r.oid, o.object_type, o.obj_oid, o.attnum, o.permission)
),
/* permissions that are granted but should not be */
extra AS (
   SELECT DISTINCT FALSE AS missing,
          mr.rolname AS role_name,
          o.object_type,
          o.schema_name,
          o.object_name COLLATE "C",
          o.column_name,
          o.permission
   FROM objects AS o
      CROSS JOIN managed_roles AS mr
   WHERE permission_visible(mr.oid, o.object_type, o.obj_oid, o.attnum, o.permission)
     /* the object must be in scope: some target must mention it */
     AND EXISTS (
            SELECT 1
            FROM permission_target AS pt
            WHERE (pt.object_type = o.object_type
                   OR (o.object_type = 'COLUMN'
                       AND pt.object_type IN ('TABLE', 'VIEW')))
              AND (pt.schema_name IS NULL OR pt.schema_name = o.schema_name)
              AND (pt.object_name IS NULL OR pt.object_name = o.object_name)
              AND (pt.column_name IS NULL OR pt.column_name = o.column_name)
         )
     /* and no target may grant it, directly or through role membership */
     AND NOT EXISTS (
            SELECT 1
            FROM permission_target AS pt2
               JOIN permission_roles() AS pr2 ON pr2.rolname = pt2.role_name
            WHERE (pt2.role_name = mr.rolname
                   OR pg_catalog.pg_has_role(mr.oid, pr2.oid, 'MEMBER'))
              AND pt2.permissions @> ARRAY[o.permission]::perm_type[]
              AND (pt2.object_type = o.object_type
                   OR (o.object_type = 'COLUMN'
                       AND pt2.object_type IN ('TABLE', 'VIEW')))
              AND (pt2.schema_name IS NULL OR pt2.schema_name = o.schema_name)
              AND (pt2.object_name IS NULL OR pt2.object_name = o.object_name)
              AND (pt2.column_name IS NULL OR pt2.column_name = o.column_name)
         )
)
SELECT * FROM missing
UNION
SELECT * FROM extra;
$$;

/*
 * The GRANT and REVOKE statements that would resolve every row of
 * permission_diffs().  Nothing is executed; review the output first.
 */
CREATE FUNCTION permission_fix_sql()
   RETURNS TABLE (
      missing boolean,
      role_name name,
      object_type obj_type,
      schema_name name,
      object_name text,
      column_name name,
      permission perm_type,
      sql text
   )
   LANGUAGE sql STABLE SET search_path FROM CURRENT AS
$$
   SELECT d.missing, d.role_name, d.object_type, d.schema_name, d.object_name,
          d.column_name, d.permission,
          permission_sql(d.missing, d.role_name, d.object_type, d.schema_name,
                         d.object_name, d.column_name, d.permission)
   FROM permission_diffs() AS d;
$$;

/*
 * Apply the statements from permission_fix_sql().  With the default
 * "dry_run" the statements are only returned; pass FALSE to execute them.
 */
CREATE FUNCTION permission_apply(dry_run boolean DEFAULT true)
RETURNS SETOF text
LANGUAGE plpgsql
AS $$
DECLARE
   r record;
BEGIN
   FOR r IN SELECT * FROM permission_fix_sql() LOOP
      IF NOT dry_run THEN
         EXECUTE r.sql;
      END IF;
      RETURN NEXT r.sql;
   END LOOP;
END;
$$;

/*
 * permission_diffs() returns one row per deviation, which can be thousands
 * of rows for a single target.  This view collapses them per role, object
 * type, schema and privilege.
 */
CREATE VIEW permission_diff_summary AS
SELECT missing,
       role_name,
       object_type,
       schema_name,
       permission,
       count(*) AS objects
FROM permission_diffs()
GROUP BY missing, role_name, object_type, schema_name, permission;

GRANT SELECT ON permission_diff_summary TO PUBLIC;

/*
 * Adopt the current state as the desired state.  Useful to bootstrap a
 * baseline: run it, then delete the rows that should not be there.
 * Returns the number of targets that were inserted.
 */
CREATE FUNCTION permission_target_snapshot(
   role_pattern name DEFAULT NULL, schema_pattern name DEFAULT NULL)
RETURNS integer
LANGUAGE plpgsql
AS $$
DECLARE
   inserted integer;
BEGIN
   INSERT INTO permission_target
      (role_name, permissions, object_type, schema_name, object_name, column_name)
   SELECT r.rolname,
          array_agg(DISTINCT o.permission ORDER BY o.permission),
          o.object_type,
          o.schema_name,
          o.object_name,
          o.column_name
   FROM permission_objects() AS o
      CROSS JOIN permission_roles() AS r
   WHERE permission_visible(r.oid, o.object_type, o.obj_oid, o.attnum, o.permission)
     AND (role_pattern IS NULL OR r.rolname = role_pattern)
     AND (schema_pattern IS NULL OR o.schema_name = schema_pattern)
     AND NOT permission_is_extension_object(o.object_type, o.obj_oid)
   GROUP BY r.rolname, o.object_type, o.schema_name, o.object_name, o.column_name
   ON CONFLICT ON CONSTRAINT permission_target_unique DO NOTHING;

   GET DIAGNOSTICS inserted = ROW_COUNT;
   RETURN inserted;
END;
$$;

/* role removal */

/*
 * What still depends on a role?  "database" is NULL for shared objects, and
 * "object" is NULL when the object lives in another database, whose catalog
 * cannot be read from here.
 */
CREATE FUNCTION role_dependencies(role_name name)
RETURNS TABLE (database name, kind text, object text)
LANGUAGE sql STABLE
AS $$
   SELECT CASE WHEN d.dbid = 0 THEN NULL
               ELSE (SELECT datname FROM pg_catalog.pg_database WHERE oid = d.dbid)
          END,
          CASE d.classid
             WHEN 'pg_catalog.pg_class'::regclass THEN 'relation'
             WHEN 'pg_catalog.pg_proc'::regclass THEN 'function'
             WHEN 'pg_catalog.pg_namespace'::regclass THEN 'schema'
             WHEN 'pg_catalog.pg_database'::regclass THEN 'database'
             WHEN 'pg_catalog.pg_default_acl'::regclass THEN 'default acl'
             WHEN 'pg_catalog.pg_type'::regclass THEN 'type'
             ELSE d.classid::regclass::text
          END,
          CASE WHEN d.dbid = 0
                    OR d.dbid = (SELECT oid FROM pg_catalog.pg_database
                                 WHERE datname = current_database())
               THEN CASE d.classid
                       WHEN 'pg_catalog.pg_class'::regclass
                          THEN (SELECT c.oid::regclass::text
                                FROM pg_catalog.pg_class AS c WHERE c.oid = d.objid)
                       WHEN 'pg_catalog.pg_proc'::regclass
                          THEN (SELECT p.oid::regprocedure::text
                                FROM pg_catalog.pg_proc AS p WHERE p.oid = d.objid)
                       WHEN 'pg_catalog.pg_namespace'::regclass
                          THEN (SELECT n.nspname
                                FROM pg_catalog.pg_namespace AS n WHERE n.oid = d.objid)
                       WHEN 'pg_catalog.pg_database'::regclass
                          THEN (SELECT datname
                                FROM pg_catalog.pg_database WHERE oid = d.objid)
                       WHEN 'pg_catalog.pg_default_acl'::regclass
                          THEN (SELECT CASE d2.defaclobjtype
                                          WHEN 'r' THEN 'TABLE'
                                          WHEN 'S' THEN 'SEQUENCE'
                                          WHEN 'f' THEN 'FUNCTION'
                                          WHEN 'T' THEN 'TYPE'
                                          WHEN 'n' THEN 'SCHEMA'
                                       END
                                       || CASE WHEN d2.defaclnamespace = 0
                                               THEN ' (all schemas)'
                                               ELSE ' in ' || d2.defaclnamespace::regnamespace::name
                                          END
                                FROM pg_catalog.pg_default_acl AS d2
                                WHERE d2.oid = d.objid)
                       ELSE d.objid::text
                    END
               ELSE NULL
          END
   FROM pg_catalog.pg_shdepend AS d
   WHERE d.refobjid = (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = role_name)
     AND d.deptype IN ('o', 'a')
$$;

/*
 * Remove a role from the current database.
 *
 * With "new_owner" the objects the role owns are reassigned to that role;
 * without it they are dropped.  In both cases every privilege granted to the
 * role is revoked.  "drop_role" then removes the role itself.
 *
 * REASSIGN OWNED and DROP OWNED only cover the current database (plus shared
 * objects such as databases and tablespaces), so run this in every database
 * that contains objects owned by the role.  Use drop_role = false for all but
 * the last database, then drop the role once nothing depends on it.
 */
CREATE FUNCTION role_drop(
   role_name name,
   new_owner name DEFAULT NULL,
   drop_role boolean DEFAULT true)
RETURNS TABLE (step text, statement text)
LANGUAGE plpgsql
AS $$
DECLARE
   stmt text;
BEGIN
   IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = role_name) THEN
      RAISE EXCEPTION 'role "%" does not exist', role_name;
   END IF;

   IF new_owner IS NOT NULL THEN
      IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = new_owner) THEN
         RAISE EXCEPTION 'role "%" does not exist', new_owner;
      END IF;
      IF new_owner = role_name THEN
         RAISE EXCEPTION 'the new owner must be a different role';
      END IF;

      stmt := pg_catalog.format('REASSIGN OWNED BY %I TO %I', role_name, new_owner);
      EXECUTE stmt;
      RETURN QUERY SELECT 'reassign owned'::text, stmt;
   END IF;

   stmt := pg_catalog.format('DROP OWNED BY %I', role_name);
   EXECUTE stmt;
   RETURN QUERY SELECT 'drop owned'::text, stmt;

   IF drop_role THEN
      stmt := pg_catalog.format('DROP ROLE %I', role_name);
      EXECUTE stmt;
      RETURN QUERY SELECT 'drop role'::text, stmt;
   END IF;
END;
$$;

/* default privileges (ALTER DEFAULT PRIVILEGES) */

/*
 * pg_default_acl.defaclobjtype uses a single character; map it to obj_type.
 */
CREATE FUNCTION default_acl_objtype(object_type obj_type)
RETURNS "char"
LANGUAGE sql IMMUTABLE
AS $$
   SELECT CASE object_type
      WHEN 'TABLE'    THEN 'r'
      WHEN 'SEQUENCE' THEN 'S'
      WHEN 'FUNCTION' THEN 'f'
   END::"char"
$$;

/*
 * The default ACL that applies to objects of "objtype" created by
 * "for_role" in the schema "schema_oid": the per-schema entry if there is
 * one, otherwise the global entry, otherwise the built-in default.
 */
CREATE FUNCTION default_acl_effective(for_role oid, schema_oid oid, objtype "char")
RETURNS aclitem[]
LANGUAGE sql STABLE
AS $$
   SELECT COALESCE(
      (SELECT d.defaclacl
       FROM pg_catalog.pg_default_acl AS d
       WHERE d.defaclrole = for_role
         AND d.defaclobjtype = objtype
         AND d.defaclnamespace = schema_oid),
      (SELECT d.defaclacl
       FROM pg_catalog.pg_default_acl AS d
       WHERE d.defaclrole = for_role
         AND d.defaclobjtype = objtype
         AND d.defaclnamespace = 0),
      pg_catalog.acldefault(objtype, for_role))
$$;

CREATE TABLE default_acl_target (
   id             int4        PRIMARY KEY,
   for_role_name  name        NOT NULL,
   schema_name    name,
   object_type    obj_type    NOT NULL,
   role_name      name        NOT NULL,
   permissions    perm_type[] NOT NULL,
   CONSTRAINT default_acl_target_valid
   CHECK (cardinality(permissions) > 0
          AND CASE object_type
                 WHEN 'TABLE'
                 THEN ARRAY['SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER','MAINTAIN']::perm_type[] @> permissions
                 WHEN 'SEQUENCE'
                 THEN ARRAY['SELECT','USAGE','UPDATE']::perm_type[] @> permissions
                 WHEN 'FUNCTION'
                 THEN ARRAY['EXECUTE']::perm_type[] @> permissions
              END),
   CONSTRAINT default_acl_target_unique
   UNIQUE NULLS NOT DISTINCT (for_role_name, schema_name, object_type, role_name)
);

CREATE SEQUENCE default_acl_target_id_seq OWNED BY default_acl_target.id;
ALTER TABLE default_acl_target ALTER id
   SET DEFAULT nextval('default_acl_target_id_seq'::regclass);

CREATE FUNCTION default_acl_target_check()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
   allowed perm_type[];
BEGIN
   IF cardinality(NEW.permissions) = 0 THEN
      RAISE EXCEPTION 'the permission list must not be empty';
   END IF;

   CASE NEW.object_type
      WHEN 'TABLE' THEN
         allowed := ARRAY['SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER','MAINTAIN']::perm_type[];
      WHEN 'SEQUENCE' THEN
         allowed := ARRAY['SELECT','USAGE','UPDATE']::perm_type[];
      WHEN 'FUNCTION' THEN
         allowed := ARRAY['EXECUTE']::perm_type[];
      ELSE
         RAISE EXCEPTION 'a default ACL target must be TABLE, SEQUENCE or FUNCTION, not %',
            NEW.object_type;
   END CASE;

   IF NOT allowed @> NEW.permissions THEN
      RAISE EXCEPTION 'invalid permission for a % default ACL target: %',
         NEW.object_type,
         ARRAY(SELECT unnest(NEW.permissions)
               EXCEPT
               SELECT unnest(allowed));
   END IF;

   IF current_setting('server_version_num')::integer < 170000
      AND 'MAINTAIN'::perm_type = ANY (NEW.permissions)
   THEN
      RAISE EXCEPTION 'the MAINTAIN privilege requires PostgreSQL 17 or later';
   END IF;

   IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = NEW.for_role_name)
   THEN
      RAISE EXCEPTION 'role "%" does not exist', NEW.for_role_name;
   END IF;

   IF NEW.role_name <> 'PUBLIC'
      AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = NEW.role_name)
   THEN
      RAISE EXCEPTION 'role "%" does not exist', NEW.role_name;
   END IF;

   RETURN NEW;
END;
$$;

CREATE TRIGGER default_acl_target_check
   BEFORE INSERT OR UPDATE ON default_acl_target
   FOR EACH ROW EXECUTE PROCEDURE default_acl_target_check();

REVOKE ALL ON default_acl_target FROM PUBLIC;
GRANT SELECT ON default_acl_target TO PUBLIC;
REVOKE ALL ON SEQUENCE default_acl_target_id_seq FROM PUBLIC;

SELECT pg_catalog.pg_extension_config_dump('default_acl_target', '');
SELECT pg_catalog.pg_extension_config_dump('default_acl_target_id_seq', '');

/*
 * The default privileges that are actually in effect.  Unlike the object
 * permission views this one is read-only: it reports what pg_default_acl
 * contains, and default_acl_diffs() compares that with default_acl_target.
 */
CREATE VIEW default_acl_permissions AS
SELECT CASE d.defaclobjtype
          WHEN 'r' THEN 'TABLE'
          WHEN 'S' THEN 'SEQUENCE'
          WHEN 'f' THEN 'FUNCTION'
       END::obj_type AS object_type,
       fr.rolname AS for_role_name,
       CASE WHEN d.defaclnamespace = 0
            THEN NULL
            ELSE d.defaclnamespace::regnamespace::name
       END AS schema_name,
       COALESCE(g.rolname, 'PUBLIC'::name) AS role_name,
       a.privilege_type::perm_type AS permission,
       TRUE AS granted
FROM pg_catalog.pg_default_acl AS d
   CROSS JOIN LATERAL pg_catalog.aclexplode(d.defaclacl) AS a
   JOIN pg_catalog.pg_roles AS fr ON fr.oid = d.defaclrole
   LEFT JOIN pg_catalog.pg_roles AS g ON g.oid = a.grantee
WHERE d.defaclobjtype IN ('r', 'S', 'f');

GRANT SELECT ON default_acl_permissions TO PUBLIC;

CREATE FUNCTION default_acl_diffs()
   RETURNS TABLE (
      missing boolean,
      for_role_name name,
      schema_name name,
      object_type obj_type,
      role_name name,
      permission perm_type
   )
   LANGUAGE sql STABLE SET search_path FROM CURRENT AS
$$
WITH
target AS (
   SELECT t.for_role_name, t.schema_name, t.object_type, t.role_name,
          p.permission
   FROM default_acl_target AS t
      CROSS JOIN LATERAL unnest(t.permissions) AS p(permission)
),
missing AS (
   SELECT DISTINCT TRUE AS missing,
          t.for_role_name, t.schema_name, t.object_type, t.role_name, t.permission
   FROM target AS t
      JOIN pg_catalog.pg_roles AS fr ON fr.rolname = t.for_role_name
      JOIN (SELECT oid, rolname FROM pg_catalog.pg_roles
            UNION ALL SELECT 0::oid, 'PUBLIC'::name) AS gr
        ON gr.rolname = t.role_name
      LEFT JOIN pg_catalog.pg_namespace AS s ON s.nspname = t.schema_name
   WHERE NOT EXISTS (
            SELECT 1
            FROM pg_catalog.aclexplode(
                    default_acl_effective(fr.oid, COALESCE(s.oid, 0),
                                          default_acl_objtype(t.object_type))) AS a
            WHERE a.grantee = gr.oid
              AND a.privilege_type = t.permission::text
         )
),
extra AS (
   SELECT DISTINCT FALSE AS missing,
          d.for_role_name, d.schema_name, d.object_type, d.role_name, d.permission
   FROM default_acl_permissions AS d
   /* the owner always holds every privilege implicitly; never report it */
   WHERE d.role_name <> d.for_role_name
     AND NOT EXISTS (
            SELECT 1
            FROM target AS t
            WHERE t.for_role_name = d.for_role_name
              AND t.object_type = d.object_type
              AND t.role_name = d.role_name
              AND t.permission = d.permission
              AND (t.schema_name IS NULL OR t.schema_name = d.schema_name)
         )
)
SELECT * FROM missing
UNION
SELECT * FROM extra;
$$;
