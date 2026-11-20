-- PUBLIC is not a row in pg_roles, but it is a grantee like any other and
-- must be visible and targetable.
\set VERBOSITY terse

DROP EXTENSION pg_permissions CASCADE;
CREATE EXTENSION pg_permissions;

CREATE ROLE public_user;
CREATE TABLE public_t(a int);
GRANT SELECT ON public_t TO PUBLIC;

-- PUBLIC appears in the views
SELECT role_name, permission, granted
FROM table_permissions
WHERE schema_name = 'public' AND object_name = 'public_t'
  AND role_name = 'PUBLIC' AND permission = 'SELECT';

-- a PUBLIC target is honoured
INSERT INTO permission_target
   (role_name, permissions, object_type, schema_name, object_name, column_name)
VALUES ('PUBLIC', ARRAY['SELECT']::perm_type[], 'TABLE', 'public', 'public_t', NULL);
SELECT count(*) AS diffs FROM permission_diffs();

-- revoking the privilege is detected
REVOKE SELECT ON public_t FROM PUBLIC;
SELECT * FROM permission_diffs();

-- the updatable view can grant to PUBLIC
UPDATE table_permissions SET granted = TRUE
WHERE role_name = 'PUBLIC' AND schema_name = 'public'
  AND object_name = 'public_t' AND permission = 'SELECT';
SELECT has_table_privilege(0::oid, 'public.public_t', 'SELECT') AS grant_works;

-- and revoke from PUBLIC
UPDATE table_permissions SET granted = FALSE
WHERE role_name = 'PUBLIC' AND schema_name = 'public'
  AND object_name = 'public_t' AND permission = 'SELECT';
SELECT has_table_privilege(0::oid, 'public.public_t', 'SELECT') AS grant_works;

DROP TABLE public_t;
DROP ROLE public_user;
