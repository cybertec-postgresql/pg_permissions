-- Removing a role: reassign ownership, revoke privileges, drop the role.
\set VERBOSITY terse

DROP EXTENSION pg_permissions CASCADE;
CREATE EXTENSION pg_permissions;

CREATE ROLE drop_victim LOGIN;
CREATE ROLE drop_successor LOGIN;
CREATE ROLE drop_group;
GRANT drop_group TO drop_victim;

CREATE TABLE drop_owned(a int);
ALTER TABLE drop_owned OWNER TO drop_victim;
CREATE TABLE drop_granted(a int);
GRANT SELECT ON drop_granted TO drop_victim;
ALTER DEFAULT PRIVILEGES FOR ROLE drop_victim
   GRANT SELECT ON TABLES TO drop_successor;

-- what depends on the role?
SELECT kind, object FROM role_dependencies('drop_victim') ORDER BY kind, object;

-- reassign ownership and revoke privileges, but keep the role
SELECT * FROM role_drop('drop_victim', 'drop_successor', false);
SELECT count(*) AS dependencies FROM role_dependencies('drop_victim');
SELECT count(*) AS role_exists FROM pg_roles WHERE rolname = 'drop_victim';
SELECT relowner::regrole AS new_owner FROM pg_class WHERE relname = 'drop_owned';

-- now drop the role itself
SELECT * FROM role_drop('drop_victim', NULL, true);
SELECT count(*) AS role_exists FROM pg_roles WHERE rolname = 'drop_victim';

-- without a successor the owned objects are dropped
CREATE ROLE drop_victim2 LOGIN;
CREATE TABLE drop_owned2(a int);
ALTER TABLE drop_owned2 OWNER TO drop_victim2;
SELECT * FROM role_drop('drop_victim2');
SELECT count(*) AS table_exists FROM pg_class WHERE relname = 'drop_owned2';

-- error cases
SELECT * FROM role_drop('drop_nosuchrole');
SELECT * FROM role_drop('drop_successor', 'drop_successor');

DROP TABLE drop_owned;
DROP TABLE drop_granted;
DROP ROLE drop_successor;
DROP ROLE drop_group;
