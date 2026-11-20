-- ALTER DEFAULT PRIVILEGES is part of the desired state in most production
-- setups, so it is modelled separately from the object permissions.
\set VERBOSITY terse

DROP EXTENSION pg_permissions CASCADE;
CREATE EXTENSION pg_permissions;

CREATE ROLE dacl_owner;
CREATE ROLE dacl_user;

INSERT INTO default_acl_target
   (for_role_name, schema_name, object_type, role_name, permissions)
VALUES ('dacl_owner', NULL, 'TABLE', 'dacl_user', ARRAY['SELECT']::perm_type[]);

-- nothing has been granted yet
SELECT * FROM default_acl_diffs();

-- the target is satisfied
ALTER DEFAULT PRIVILEGES FOR ROLE dacl_owner GRANT SELECT ON TABLES TO dacl_user;
SELECT * FROM default_acl_diffs();

-- a surplus default privilege is reported
ALTER DEFAULT PRIVILEGES FOR ROLE dacl_owner GRANT INSERT ON TABLES TO dacl_user;
SELECT * FROM default_acl_diffs();

-- the owner's implicit privileges are never reported
SELECT count(*) AS owner_rows FROM default_acl_diffs()
WHERE role_name = for_role_name;

-- a per-schema target is satisfied by the global entry, which is what
-- PostgreSQL falls back to when no per-schema entry exists
CREATE SCHEMA dacl_schema;
INSERT INTO default_acl_target
   (for_role_name, schema_name, object_type, role_name, permissions)
VALUES ('dacl_owner', 'dacl_schema', 'TABLE', 'dacl_user', ARRAY['SELECT']::perm_type[]);
SELECT * FROM default_acl_diffs() WHERE schema_name = 'dacl_schema';

-- without the global entry the per-schema target is missing
ALTER DEFAULT PRIVILEGES FOR ROLE dacl_owner REVOKE ALL ON TABLES FROM dacl_user;
SELECT * FROM default_acl_diffs() WHERE schema_name = 'dacl_schema';

-- and a per-schema entry satisfies it
ALTER DEFAULT PRIVILEGES FOR ROLE dacl_owner IN SCHEMA dacl_schema
   GRANT SELECT ON TABLES TO dacl_user;
SELECT * FROM default_acl_diffs() WHERE schema_name = 'dacl_schema';

-- the actual default privileges are visible
SELECT object_type, for_role_name, schema_name, role_name, permission
FROM default_acl_permissions
WHERE role_name = 'dacl_user'
ORDER BY object_type, schema_name, permission;

ALTER DEFAULT PRIVILEGES FOR ROLE dacl_owner IN SCHEMA dacl_schema
   REVOKE ALL ON TABLES FROM dacl_user;
DROP SCHEMA dacl_schema;
DROP ROLE dacl_user;
DROP ROLE dacl_owner;
