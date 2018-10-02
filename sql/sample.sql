CREATE EXTENSION pg_permissions;

/* test roles (will be removed afterwards) */

CREATE ROLE users;
CREATE ROLE user1 LOGIN IN ROLE users;
CREATE ROLE user2 LOGIN IN ROLE users;

/* database */

-- desired permissions
INSERT INTO permission_target
   (id, role_name, permissions, object_type, schema_name, object_name, column_name)
VALUES (1, 'users', ARRAY['CONNECT','TEMPORARY']::perm_type[], 'DATABASE', NULL, NULL, NULL),
       (2, 'user1', ARRAY['CONNECT','TEMPORARY']::perm_type[], 'DATABASE', NULL, NULL, NULL),
       (3, 'user2', ARRAY['CONNECT','TEMPORARY']::perm_type[], 'DATABASE', NULL, NULL, NULL);
-- this should fail
INSERT INTO permission_target
   (id, role_name, permissions, object_type, schema_name, object_name, column_name)
VALUES (4, 'user2', ARRAY['CREATE']::perm_type[], 'DATABASE', 'public', NULL, NULL);

-- actual permissions
REVOKE ALL ON DATABASE contrib_regression FROM PUBLIC;
GRANT CONNECT, TEMPORARY ON DATABASE contrib_regression TO users;
GRANT CREATE ON DATABASE contrib_regression TO user2; -- too much

/* schema */

-- desired permissions
INSERT INTO permission_target
   (id, role_name, permissions, object_type, schema_name, object_name, column_name)
VALUES (5, 'users', ARRAY['USAGE']::perm_type[], 'SCHEMA', 'appschema', NULL, NULL),
       (6, 'user1', ARRAY['USAGE','CREATE']::perm_type[], 'SCHEMA', 'appschema', NULL, NULL),
       (7, 'user2', ARRAY['USAGE']::perm_type[], 'SCHEMA', 'appschema', NULL, NULL);
-- this should fail
INSERT INTO permission_target
   (id, role_name, permissions, object_type, schema_name, object_name, column_name)
VALUES (8, 'user2', ARRAY['CREATE']::perm_type[], 'SCHEMA', 'appschema', 'sometable', NULL);
-- actual permissions
CREATE SCHEMA appschema;
GRANT USAGE ON SCHEMA appschema TO PUBLIC; -- missing CREATE for user1
GRANT CREATE ON SCHEMA appschema TO user2; -- too much

/* table */

-- desired permissions
INSERT INTO permission_target
   (id, role_name, permissions, object_type, schema_name, object_name, column_name)
VALUES (9,  'user1', ARRAY['SELECT','INSERT','UPDATE','DELETE']::perm_type[], 'TABLE', 'appschema', NULL, NULL),
       (10, 'user2', ARRAY['SELECT']::perm_type[], 'TABLE', 'appschema', NULL, NULL);
-- this should fail
INSERT INTO permission_target
   (id, role_name, permissions, object_type, schema_name, object_name, column_name)
VALUES (11, 'user2', ARRAY['INSERT']::perm_type[], 'TABLE', 'appschema', 'apptable', 'acolumn');
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
GRANT SELECT, INSERT, UPDATE ON appschema.apptable TO user1; -- missing DELETE
GRANT SELECT, INSERT ON appschema.apptable TO user2; -- extra privilege INSERT

/* column */

-- desired permissions
INSERT INTO permission_target
   (id, role_name, permissions, object_type, schema_name, object_name, column_name)
VALUES (12, 'user1', ARRAY['SELECT','INSERT','UPDATE','REFERENCES']::perm_type[], 'COLUMN', 'appschema', 'apptable2', 'val');
-- this should fail
INSERT INTO permission_target
   (id, role_name, permissions, object_type, schema_name, object_name, column_name)
VALUES (13, 'user2', ARRAY['DELETE']::perm_type[], 'COLUMN', 'appschema', 'apptable2', 'val');
-- actual permissions
GRANT REFERENCES (val) ON appschema.apptable2 TO user1; -- missing SELECT, INSERT, UPDATE
GRANT UPDATE (val) ON appschema.apptable2 TO user2; -- extra privilege UPDATE

/* view */

-- desired permissions
INSERT INTO permission_target
   (id, role_name, permissions, object_type, schema_name, object_name, column_name)
VALUES (14, 'user1', ARRAY['SELECT','INSERT','UPDATE','DELETE']::perm_type[], 'VIEW', 'appschema', 'appview', NULL),
       (15, 'user2', ARRAY['SELECT']::perm_type[], 'VIEW', 'appschema', 'appview', NULL);
-- actual permissions
CREATE VIEW appschema.appview AS
SELECT id, val FROM appschema.apptable;
GRANT SELECT ON appschema.appview TO users; -- extra permission to "users"
GRANT INSERT, DELETE ON appschema.appview TO user1; -- missing UPDATE

/* sequence */

-- desired permissions
INSERT INTO permission_target
   (id, role_name, permissions, object_type, schema_name, object_name, column_name)
VALUES (16, 'users', ARRAY['USAGE']::perm_type[], 'SEQUENCE', 'appschema', 'appseq', NULL),
       (17, 'user1', ARRAY['USAGE','SELECT']::perm_type[], 'SEQUENCE', 'appschema', 'appseq', NULL),
       (18, 'user2', ARRAY['USAGE']::perm_type[], 'SEQUENCE', 'appschema', 'appseq', NULL);
-- actual permissions
CREATE SEQUENCE appschema.appseq;
GRANT USAGE ON SEQUENCE appschema.appseq TO users; -- missing SELECT for user1
GRANT UPDATE ON SEQUENCE appschema.appseq TO user2; -- extra permission UPDATE

/* function */

-- desired permissions
INSERT INTO permission_target
   (id, role_name, permissions, object_type, schema_name, object_name, column_name)
VALUES (19, 'user1', ARRAY['EXECUTE']::perm_type[], 'FUNCTION', 'appschema', 'appfun(integer)', NULL),
       (20, 'user2', ARRAY['EXECUTE']::perm_type[], 'FUNCTION', 'appschema', 'appfun(integer)', NULL);
-- this should fail
INSERT INTO permission_target
   (id, role_name, permissions, object_type, schema_name, object_name, column_name)
VALUES (21, 'users', ARRAY['UPDATE']::perm_type[], 'FUNCTION', 'appschema', 'appfun(integer)', NULL);
-- actual permissions
CREATE FUNCTION appschema.appfun(i integer) RETURNS integer
   LANGUAGE sql IMMUTABLE AS
   'SELECT i + 2'; -- extra permission for "users"

/* report all permissions */

SELECT object_type, role_name, schema_name, object_name, column_name, permission
FROM all_permissions
WHERE granted
  AND role_name IN ('users', 'user1', 'user2')
  AND coalesce(schema_name, 'appschema') = 'appschema'
ORDER BY object_type, role_name, schema_name, object_name, column_name, permission;

/* report differences */

SELECT * FROM permission_diffs()
WHERE role_name IN ('users', 'user1', 'user2')
ORDER BY object_type, schema_name, object_name, column_name, role_name, permission, missing;

/* clean up */

DROP FUNCTION appschema.appfun(integer);
DROP VIEW appschema.appview;
DROP SEQUENCE appschema.appseq;
DROP TABLE appschema.apptable;
DROP TABLE appschema.apptable2;
DROP SCHEMA appschema;
REVOKE ALL ON DATABASE contrib_regression FROM user1, user2, users;

DROP ROLE user1;
DROP ROLE user2;
DROP ROLE users;
