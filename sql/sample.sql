CREATE EXTENSION pg_permissions;

/* test roles (will be removed afterwards) */

CREATE ROLE users;
CREATE ROLE user1 LOGIN IN ROLE users;
CREATE ROLE user2 LOGIN IN ROLE users;

/* database */

-- desired permissions
INSERT INTO permission_target
   (role_name, permissions, object_type, schema_name, object_name, column_name)
VALUES ('users', ARRAY['CONNECT','TEMPORARY']::perm_type[], 'DATABASE', NULL, NULL, NULL),
       ('user1', ARRAY['CONNECT','TEMPORARY']::perm_type[], 'DATABASE', NULL, NULL, NULL),
       ('user2', ARRAY['CONNECT','TEMPORARY']::perm_type[], 'DATABASE', NULL, NULL, NULL);
-- this should fail
INSERT INTO permission_target
   (role_name, permissions, object_type, schema_name, object_name, column_name)
VALUES ('user2', ARRAY['CREATE']::perm_type[], 'DATABASE', 'public', NULL, NULL);

-- actual permissions
REVOKE ALL ON DATABASE contrib_regression FROM PUBLIC;
GRANT CONNECT, TEMPORARY ON DATABASE contrib_regression TO users;
GRANT CREATE ON DATABASE contrib_regression TO user2; -- too much

/* schema */

-- desired permissions
INSERT INTO permission_target
   (role_name, permissions, object_type, schema_name, object_name, column_name)
VALUES ('users', ARRAY['USAGE']::perm_type[], 'SCHEMA', 'appschema', NULL, NULL),
       ('user1', ARRAY['USAGE','CREATE']::perm_type[], 'SCHEMA', 'appschema', NULL, NULL),
       ('user2', ARRAY['USAGE']::perm_type[], 'SCHEMA', 'appschema', NULL, NULL);
-- this should fail
INSERT INTO permission_target
   (role_name, permissions, object_type, schema_name, object_name, column_name)
VALUES ('user2', ARRAY['CREATE']::perm_type[], 'SCHEMA', 'appschema', 'sometable', NULL);
-- actual permissions
CREATE SCHEMA appschema;
GRANT USAGE ON SCHEMA appschema TO PUBLIC; -- missing CREATE for user1
GRANT CREATE ON SCHEMA appschema TO user2; -- too much
CREATE SCHEMA pgabc123;
GRANT USAGE ON SCHEMA pgabc123 TO user1;

/* table */

-- desired permissions
INSERT INTO permission_target
   (role_name, permissions, object_type, schema_name, object_name, column_name)
VALUES ('user1', ARRAY['SELECT','INSERT','UPDATE','DELETE']::perm_type[], 'TABLE', 'appschema', NULL, NULL),
       ('user2', ARRAY['SELECT']::perm_type[], 'TABLE', 'appschema', NULL, NULL),
       ('user1', ARRAY['SELECT']::perm_type[], 'TABLE', 'pgabc213', 'sometable', NULL);
-- this should fail
INSERT INTO permission_target
   (role_name, permissions, object_type, schema_name, object_name, column_name)
VALUES ('user2', ARRAY['INSERT']::perm_type[], 'TABLE', 'appschema', 'apptable', 'acolumn');
-- actual permissions
CREATE TABLE appschema.apptable (
   id integer PRIMARY KEY,
   val text NOT NULL,
   created timestamp with time zone NOT NULL DEFAULT current_timestamp
);
CREATE TABLE appschema.apptable2 (
   id integer PRIMARY KEY,
   val text NOT NULL,
   created timestamp with time zone NOT NULL DEFAULT current_timestamp
); -- missing all permissions on this one
CREATE TABLE pgabc123.sometable (
   id integer PRIMARY KEY,
   val text NOT NULL,
   created timestamp with time zone NOT NULL DEFAULT current_timestamp
);
GRANT SELECT, INSERT, UPDATE ON appschema.apptable TO user1; -- missing DELETE
GRANT SELECT, INSERT ON appschema.apptable TO user2; -- extra privilege INSERT
GRANT SELECT ON pgabc123.sometable TO user1;

/* column */

-- desired permissions
INSERT INTO permission_target
   (role_name, permissions, object_type, schema_name, object_name, column_name)
VALUES ('user1', ARRAY['SELECT','INSERT','UPDATE','REFERENCES']::perm_type[], 'COLUMN', 'appschema', 'apptable2', 'val');
-- this should fail
INSERT INTO permission_target
   (role_name, permissions, object_type, schema_name, object_name, column_name)
VALUES ('user2', ARRAY['DELETE']::perm_type[], 'COLUMN', 'appschema', 'apptable2', 'val');
-- actual permissions
-- missing REFERENCES for user1 on apptable2.val
GRANT UPDATE (val) ON appschema.apptable2 TO user2; -- extra privilege UPDATE

/* view */

-- desired permissions
INSERT INTO permission_target
   (role_name, permissions, object_type, schema_name, object_name, column_name)
VALUES ('user1', ARRAY['SELECT','INSERT','UPDATE','DELETE']::perm_type[], 'VIEW', 'appschema', 'appview', NULL),
       ('user2', ARRAY['SELECT']::perm_type[], 'VIEW', 'appschema', 'appview', NULL);
-- actual permissions
CREATE VIEW appschema.appview AS
SELECT id, val FROM appschema.apptable;
GRANT SELECT ON appschema.appview TO users; -- extra permission to "users"
GRANT INSERT, DELETE ON appschema.appview TO user1; -- missing UPDATE

/* sequence */

-- desired permissions
INSERT INTO permission_target
   (role_name, permissions, object_type, schema_name, object_name, column_name)
VALUES ('users', ARRAY['USAGE']::perm_type[], 'SEQUENCE', 'appschema', 'appseq', NULL),
       ('user1', ARRAY['USAGE','SELECT']::perm_type[], 'SEQUENCE', 'appschema', 'appseq', NULL),
       ('user2', ARRAY['USAGE']::perm_type[], 'SEQUENCE', 'appschema', 'appseq', NULL);
-- actual permissions
CREATE SEQUENCE appschema.appseq;
GRANT USAGE ON SEQUENCE appschema.appseq TO users; -- missing SELECT for user1
GRANT UPDATE ON SEQUENCE appschema.appseq TO user2; -- extra permission UPDATE

/* function */

-- desired permissions
INSERT INTO permission_target
   (role_name, permissions, object_type, schema_name, object_name, column_name)
VALUES ('user1', ARRAY['EXECUTE']::perm_type[], 'FUNCTION', 'appschema', 'appfun(integer)', NULL),
       ('user2', ARRAY['EXECUTE']::perm_type[], 'FUNCTION', 'appschema', 'appfun(integer)', NULL);
-- this should fail
INSERT INTO permission_target
   (role_name, permissions, object_type, schema_name, object_name, column_name)
VALUES ('users', ARRAY['UPDATE']::perm_type[], 'FUNCTION', 'appschema', 'appfun(integer)', NULL);
-- actual permissions
CREATE FUNCTION appschema.appfun(i integer) RETURNS integer
   LANGUAGE sql IMMUTABLE AS
   'SELECT i + 2'; -- extra permission for "users"

/* report all permissions */

SELECT object_type, role_name, schema_name, object_name, column_name, permission
FROM all_permissions
WHERE granted
  AND role_name IN ('users', 'user1', 'user2')
  AND coalesce(schema_name, 'appschema') IN ('appschema', 'pgabc123')
ORDER BY object_type, role_name, schema_name, object_name, column_name, permission;

/* report differences */

SELECT * FROM permission_diffs()
WHERE role_name IN ('users', 'user1', 'user2')
ORDER BY object_type, schema_name, object_name, column_name, role_name, permission, missing;

/* fix some of the differences */

UPDATE column_permissions SET
   granted = TRUE
WHERE role_name = 'user1'
  AND schema_name = 'appschema'
  AND object_name = 'apptable2'
  AND column_name = 'val'
  AND permission = 'REFERENCES';

UPDATE all_permissions SET
   granted = FALSE
WHERE object_type = 'TABLE'
  AND role_name = 'user2'
  AND schema_name = 'appschema'
  AND object_name = 'apptable'
  AND permission = 'INSERT';

/* check the fixed permissions */

SELECT * FROM permission_diffs()
WHERE role_name IN ('users', 'user1', 'user2')
ORDER BY object_type, schema_name, object_name, column_name, role_name, permission, missing;

/* clean up */

DROP FUNCTION appschema.appfun(integer);
DROP VIEW appschema.appview;
DROP SEQUENCE appschema.appseq;
DROP TABLE appschema.apptable;
DROP TABLE appschema.apptable2;
DROP TABLE pgabc123.sometable;
DROP SCHEMA appschema;
DROP SCHEMA pgabc123;
REVOKE ALL ON DATABASE contrib_regression FROM user1, user2, users;

DROP ROLE user1;
DROP ROLE user2;
DROP ROLE users;
