-- The desired state is a compliance baseline: it must reject nonsense and
-- must not be writable by every role.
\set VERBOSITY terse

DROP EXTENSION pg_permissions CASCADE;
CREATE EXTENSION pg_permissions;

CREATE ROLE con_user;
CREATE TABLE con_t(a int);

-- an empty permission list is a no-op, not a target
INSERT INTO permission_target
   (role_name, permissions, object_type, schema_name, object_name, column_name)
VALUES ('con_user', '{}'::perm_type[], 'TABLE', 'public', 'con_t', NULL);

-- a COLUMN target needs a column name
INSERT INTO permission_target
   (role_name, permissions, object_type, schema_name, object_name, column_name)
VALUES ('con_user', ARRAY['SELECT']::perm_type[], 'COLUMN', 'public', 'con_t', NULL);

-- a privilege that does not apply to the object type is rejected
INSERT INTO permission_target
   (role_name, permissions, object_type, schema_name, object_name, column_name)
VALUES ('con_user', ARRAY['DELETE']::perm_type[], 'COLUMN', 'public', 'con_t', 'a');

-- the same target cannot be entered twice
INSERT INTO permission_target
   (role_name, permissions, object_type, schema_name, object_name, column_name)
VALUES ('con_user', ARRAY['SELECT']::perm_type[], 'TABLE', 'public', 'con_t', NULL);
INSERT INTO permission_target
   (role_name, permissions, object_type, schema_name, object_name, column_name)
VALUES ('con_user', ARRAY['INSERT']::perm_type[], 'TABLE', 'public', 'con_t', NULL);

-- the role must exist
INSERT INTO permission_target
   (role_name, permissions, object_type, schema_name, object_name, column_name)
VALUES ('con_nosuchrole', ARRAY['SELECT']::perm_type[], 'TABLE', 'public', 'con_t', NULL);

-- MAINTAIN is accepted exactly when the server supports it
CREATE TABLE con_t2(a int);
DO $$
DECLARE
   accepted boolean;
BEGIN
   BEGIN
      INSERT INTO permission_target
         (role_name, permissions, object_type, schema_name, object_name, column_name)
      VALUES ('con_user', ARRAY['MAINTAIN']::perm_type[], 'TABLE', 'public', 'con_t2', NULL);
      accepted := TRUE;
   EXCEPTION WHEN others THEN
      accepted := FALSE;
   END;

   IF accepted <> (current_setting('server_version_num')::integer >= 170000) THEN
      RAISE EXCEPTION 'MAINTAIN gating does not match the server version';
   END IF;

   DELETE FROM permission_target
   WHERE permissions = ARRAY['MAINTAIN']::perm_type[];

   RAISE NOTICE 'MAINTAIN gating matches the server version';
END;
$$;

-- and the views expose MAINTAIN exactly when the server supports it
SELECT (count(*) > 0) = (current_setting('server_version_num')::integer >= 170000)
   AS maintain_visibility_ok
FROM table_permissions
WHERE permission = 'MAINTAIN'
  AND schema_name = 'public' AND object_name = 'con_t2';
DROP TABLE con_t2;

-- an unprivileged role cannot change the baseline ...
CREATE ROLE con_low LOGIN;
GRANT USAGE ON SCHEMA public TO con_low;
SET ROLE con_low;
INSERT INTO permission_target
   (role_name, permissions, object_type, schema_name, object_name, column_name)
VALUES ('con_low', ARRAY['SELECT']::perm_type[], 'TABLE', 'public', 'con_t', NULL);
RESET ROLE;

-- ... but can read it and run the check
SET ROLE con_low;
SELECT count(*) AS readable FROM permission_target;
SELECT count(*) AS diffs FROM permission_diffs();
RESET ROLE;

DROP TABLE con_t;
REVOKE USAGE ON SCHEMA public FROM con_low;
DROP ROLE con_low;
DROP ROLE con_user;
