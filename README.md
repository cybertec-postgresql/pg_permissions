PostgreSQL permission reports and checks
========================================

This extension allows you to review object permissions on a PostgreSQL database.

Cookbook
--------

First, you have to install the extension in the database:

    CREATE EXTENSION pg_permissions SCHEMA public;

Then you need to add entries to `permission_target` that correspond to your
desired permissions.

Let's assume we have a schema `appschema`, and `appuser` should have
`SELECT`, `UPDATE`, `DELETE` and `INSERT` permissions on all tables and
views in that schema:

    INSERT INTO public.permission_target
       (role_name, permissions,
        object_type, schema_name)
    VALUES
       ('appuser', '{SELECT,INSERT,UPDATE,DELETE}',
        'TABLE', 'appschema');
    INSERT INTO public.permission_target
       (role_name, permissions,
        object_type, schema_name)
    VALUES
       ('appuser', '{SELECT,INSERT,UPDATE,DELETE}',
        'VIEW', 'appschema');

Of course, the user will need the `USAGE` privilege on the schema:

    INSERT INTO public.permission_target
       (role_name, permissions,
        object_type, schema_name)
    VALUES
       ('appuser', '{USAGE}',
        'SCHEMA', 'appschema');

The user also needs `USAGE` privileges on the `appseq` sequence in
that schema:

    INSERT INTO public.permission_target
       (role_name, permissions,
        object_type, schema_name, object_name)
    VALUES
       ('appuser', '{USAGE}',
        'SEQUENCE', 'appschema', 'appseq');

Now we can review which permissions are missing and which additional
permissions are granted:

    SELECT * FROM public.permission_diffs()
    ORDER BY missing, role_name, object_type, schema_name, object_name,
             column_name, permission;

     missing | role_name | object_type | schema_name | object_name | column_name | permission
    ---------+-----------+-------------+-------------+-------------+-------------+------------
     f       | laurenz   | VIEW        | appschema   | appview     |             | SELECT
     t       | appuser   | TABLE       | appschema   | apptable    |             | DELETE
    (2 rows)

That means that `appuser` is missing the `DELETE` privilege on
`appschema.apptable` which should be granted, while user `laurenz`
has the additional `SELECT` privilege on `appschema.appview` (`missing`
is `FALSE`).

To review the actual permissions on an object, we can use the `*_permissions`
views:

    SELECT object_type, role_name, schema_name, object_name, column_name,
           permission, granted
    FROM schema_permissions
    WHERE role_name = 'appuser' AND schema_name = 'appschema'
    ORDER BY permission;

     object_type | role_name | schema_name | object_name | column_name | permission | granted
    -------------+-----------+-------------+-------------+-------------+------------+---------
     SCHEMA      | appuser   | appschema   |             |             | USAGE      | t
     SCHEMA      | appuser   | appschema   |             |             | CREATE     | f
    (2 rows)

Usage
-----

### Views ###

The extension provides a number of views:

- `database_permissions`: permissions granted on the current database

- `schema_permissions`: permissions granted on schemas

- `table_permissions`: permissions granted on tables

- `view_permissions`: permissions granted on views

- `column_permissions`: permissions granted on table and view columns

- `function_permissions`: permissions granted on functions

- `sequence_permissions`: permissions granted on sequences

- `all_permissions`: permissions on all objects (`UNION` of the above)

- `default_acl_permissions`: default privileges set with
  `ALTER DEFAULT PRIVILEGES` (read-only; see below)

- `permission_diff_summary`: `permission_diffs()` collapsed per role,
  object type, schema and privilege (see below)

All views except `default_acl_permissions` and `permission_diff_summary`
share the same columns:

- `object_type`: the kind of object (`TABLE`, `VIEW`, `COLUMN`, `SEQUENCE`,
  `FUNCTION`, `SCHEMA` or `DATABASE`)
- `role_name`: the role the permission applies to
- `schema_name`, `object_name`, `column_name`: identify the object
- `permission`: the privilege in question — `SELECT`, `INSERT`, `UPDATE`,
  `DELETE`, `TRUNCATE`, `REFERENCES`, `TRIGGER`, `USAGE`, `CREATE`,
  `EXECUTE`, `CONNECT`, `TEMPORARY` or `MAINTAIN`
- `granted`: whether the privilege is currently in effect (`t`) or not (`f`)
- `source`: why the privilege is held — `owner`, `direct`, `PUBLIC`, or
  `role:<name>` when it is inherited through role membership; NULL when the
  privilege is not granted

A column is NULL if it has no meaning for the current view; for example,
`column_name` is only set in `column_permissions`, and `schema_name` is
always NULL in `database_permissions`.

`default_acl_permissions` has its own shape: `object_type`, `for_role_name`
(the role whose objects the default applies to), `schema_name` (NULL for all
schemas), `role_name`, `permission` and `granted`.  `permission_diff_summary`
has `missing`, `role_name`, `object_type`, `schema_name`, `permission` and
`objects`.

`table_permissions` contains regular, partitioned and foreign tables (all
labeled `TABLE`), `view_permissions` contains views and materialized views
(both labeled `VIEW`), and `function_permissions` contains functions,
aggregates, window functions and procedures (all labeled `FUNCTION`).
Toast tables and the system catalogs are not covered.

These views can be used to examine the currently granted permissions on
database objects.

The `granted` column of the permission views can be updated, which causes the
appropriate `GRANT` or `REVOKE` command to be executed.  `default_acl_permissions`
and `permission_diff_summary` are read-only.

**Note:** Superusers are not shown in the views, as they automatically have all
permissions.

#### Examples ####

The examples in this section assume the following objects and grants:

    CREATE ROLE appuser LOGIN;
    CREATE ROLE reporting LOGIN;
    CREATE ROLE auditor LOGIN;

    CREATE SCHEMA appschema;
    CREATE TABLE appschema.invoice (
       id       integer PRIMARY KEY,
       customer text    NOT NULL,
       amount   numeric NOT NULL
    );
    CREATE VIEW appschema.invoice_v AS SELECT id, customer FROM appschema.invoice;
    CREATE SEQUENCE appschema.invoice_id_seq;
    CREATE FUNCTION appschema.total() RETURNS numeric LANGUAGE sql
       AS 'SELECT sum(amount) FROM appschema.invoice';

    GRANT USAGE ON SCHEMA appschema TO appuser, reporting, auditor;
    GRANT SELECT, INSERT, UPDATE, DELETE ON appschema.invoice TO appuser;
    GRANT SELECT ON appschema.invoice TO reporting;
    GRANT SELECT ON appschema.invoice_v TO reporting;
    GRANT SELECT (customer) ON appschema.invoice TO auditor;
    GRANT USAGE ON SEQUENCE appschema.invoice_id_seq TO appuser;
    REVOKE EXECUTE ON FUNCTION appschema.total() FROM PUBLIC;
    GRANT EXECUTE ON FUNCTION appschema.total() TO reporting;

`schema_permissions` shows the `USAGE` and `CREATE` privileges on schemas:

    SELECT object_type, role_name, schema_name, permission, granted
    FROM schema_permissions
    WHERE schema_name = 'appschema' AND role_name IN ('appuser', 'reporting');

     object_type | role_name | schema_name | permission | granted
    -------------+-----------+-------------+------------+---------
     SCHEMA      | appuser   | appschema   | USAGE      | t
     SCHEMA      | appuser   | appschema   | CREATE     | f
     SCHEMA      | reporting | appschema   | USAGE      | t
     SCHEMA      | reporting | appschema   | CREATE     | f

`table_permissions` lists every table privilege for each role; `granted` tells
you which ones are actually in effect:

    SELECT role_name, object_name, permission, granted
    FROM table_permissions
    WHERE schema_name = 'appschema' AND role_name IN ('appuser', 'reporting')
    ORDER BY role_name, permission;

     role_name | object_name | permission | granted
    -----------+-------------+------------+---------
     appuser   | invoice     | SELECT     | t
     appuser   | invoice     | INSERT     | t
     appuser   | invoice     | UPDATE     | t
     appuser   | invoice     | DELETE     | t
     appuser   | invoice     | TRUNCATE   | f
     appuser   | invoice     | REFERENCES | f
     appuser   | invoice     | TRIGGER    | f
     appuser   | invoice     | MAINTAIN   | f
     reporting | invoice     | SELECT     | t
     reporting | invoice     | INSERT     | f
     reporting | invoice     | UPDATE     | f
     reporting | invoice     | DELETE     | f
     reporting | invoice     | TRUNCATE   | f
     reporting | invoice     | REFERENCES | f
     reporting | invoice     | TRIGGER    | f
     reporting | invoice     | MAINTAIN   | f

`MAINTAIN` only appears on PostgreSQL 17 and later.

`view_permissions` is the same, but for views:

    SELECT role_name, object_name, permission, granted
    FROM view_permissions
    WHERE schema_name = 'appschema' AND role_name = 'reporting'
    ORDER BY permission;

     role_name | object_name | permission | granted
    -----------+-------------+------------+---------
     reporting | invoice_v   | SELECT     | t
     reporting | invoice_v   | INSERT     | f
     reporting | invoice_v   | UPDATE     | f
     reporting | invoice_v   | DELETE     | f
     reporting | invoice_v   | TRUNCATE   | f
     reporting | invoice_v   | REFERENCES | f
     reporting | invoice_v   | TRIGGER    | f
     reporting | invoice_v   | MAINTAIN   | f

`column_permissions` reports column level privileges.  Note that `granted` is
only `t` when the privilege is granted *on the column itself*; a privilege held
at the table level is not repeated here (use `table_permissions` for that).
Here `auditor` may read only the `customer` column:

    SELECT role_name, object_name, column_name, permission, granted
    FROM column_permissions
    WHERE schema_name = 'appschema' AND object_name = 'invoice' AND role_name = 'auditor'
    ORDER BY column_name, permission;

     role_name | object_name | column_name | permission | granted
    -----------+-------------+-------------+------------+---------
     auditor   | invoice     | amount      | SELECT     | f
     auditor   | invoice     | amount      | INSERT     | f
     auditor   | invoice     | amount      | UPDATE     | f
     auditor   | invoice     | amount      | REFERENCES | f
     auditor   | invoice     | customer    | SELECT     | t
     auditor   | invoice     | customer    | INSERT     | f
     auditor   | invoice     | customer    | UPDATE     | f
     auditor   | invoice     | customer    | REFERENCES | f
     auditor   | invoice     | id          | SELECT     | f
     auditor   | invoice     | id          | INSERT     | f
     auditor   | invoice     | id          | UPDATE     | f
     auditor   | invoice     | id          | REFERENCES | f

`sequence_permissions` covers the `SELECT`, `USAGE` and `UPDATE` privileges on
sequences:

    SELECT role_name, object_name, permission, granted
    FROM sequence_permissions
    WHERE schema_name = 'appschema' AND role_name IN ('appuser', 'reporting')
    ORDER BY role_name, permission;

     role_name |  object_name   | permission | granted
    -----------+----------------+------------+---------
     appuser   | invoice_id_seq | SELECT     | f
     appuser   | invoice_id_seq | UPDATE     | f
     appuser   | invoice_id_seq | USAGE      | t
     reporting | invoice_id_seq | SELECT     | f
     reporting | invoice_id_seq | UPDATE     | f
     reporting | invoice_id_seq | USAGE      | f

`function_permissions` reports the `EXECUTE` privilege on functions.  Keep in
mind that functions are executable by `PUBLIC` by default, so `REVOKE ... FROM
PUBLIC` is usually needed before per-role grants are meaningful:

    SELECT role_name, object_name, permission, granted
    FROM function_permissions
    WHERE schema_name = 'appschema' AND role_name IN ('appuser', 'reporting')
    ORDER BY role_name;

     role_name | object_name | permission | granted
    -----------+-------------+------------+---------
     appuser   | total()     | EXECUTE    | f
     reporting | total()     | EXECUTE    | t

`database_permissions` shows the `CREATE`, `CONNECT` and `TEMPORARY` privileges
on the current database (`CONNECT` and `TEMPORARY` are granted to `PUBLIC` by
default):

    SELECT role_name, permission, granted
    FROM database_permissions
    WHERE role_name IN ('appuser', 'reporting')
    ORDER BY role_name, permission;

     role_name | permission | granted
    -----------+------------+---------
     appuser   | CREATE     | f
     appuser   | CONNECT    | t
     appuser   | TEMPORARY  | t
     reporting | CREATE     | f
     reporting | CONNECT    | t
     reporting | TEMPORARY  | t

`all_permissions` is the union of all of the above.  Filtering on
`granted` gives a concise overview of everything a set of roles can actually do:

    SELECT object_type, role_name, object_name, column_name, permission
    FROM all_permissions
    WHERE granted AND role_name IN ('appuser', 'reporting', 'auditor')
      AND coalesce(schema_name, 'appschema') = 'appschema'
    ORDER BY object_type, role_name, object_name, column_name, permission;

     object_type | role_name |  object_name   | column_name | permission
    -------------+-----------+----------------+-------------+------------
     TABLE       | appuser   | invoice        |             | SELECT
     TABLE       | appuser   | invoice        |             | INSERT
     TABLE       | appuser   | invoice        |             | UPDATE
     TABLE       | appuser   | invoice        |             | DELETE
     TABLE       | reporting | invoice        |             | SELECT
     VIEW        | reporting | invoice_v      |             | SELECT
     COLUMN      | auditor   | invoice        | customer    | SELECT
     SEQUENCE    | appuser   | invoice_id_seq |             | USAGE
     FUNCTION    | reporting | total()        |             | EXECUTE
     SCHEMA      | appuser   |                |             | USAGE
     SCHEMA      | auditor   |                |             | USAGE
     SCHEMA      | reporting |                |             | USAGE
     DATABASE    | appuser   |                |             | CONNECT
     DATABASE    | appuser   |                |             | TEMPORARY
     DATABASE    | auditor   |                |             | CONNECT
     DATABASE    | auditor   |                |             | TEMPORARY
     DATABASE    | reporting |                |             | CONNECT
     DATABASE    | reporting |                |             | TEMPORARY

### Tables ###

The extension provides a table `permission_target` with which you can describe
the permissions that *should* be granted on database objects.

If you set a relevant column in `permission_target` to NULL (e.g., the
`object_name` and `column_name` columns in a `TABLE` entry), the meaning is
that the entry refers to *all* possible objects (in the example above, all
tables in the schema).

`permission_target` has the columns `id`, `role_name`, `permissions`,
`object_type`, `schema_name`, `object_name` and `column_name`.
`default_acl_target` has `id`, `for_role_name`, `schema_name`,
`object_type`, `role_name` and `permissions`.

Both tables validate their contents: the permission list must not be empty,
a `COLUMN` entry needs a `column_name`, a `TABLE` or `VIEW` entry must not
set one, the privileges must apply to the object type, the same target
cannot be entered twice, and the role must exist.  `MAINTAIN` is rejected
before PostgreSQL 17.

A second table, `default_acl_target`, describes the default privileges that
new objects should receive; see [Default privileges](#default-privileges).

Both tables are readable by `PUBLIC` but writable only by the extension owner
and roles that are explicitly granted write access.

### Functions ###

| Function | Purpose |
|---|---|
| `permission_diffs()` | compare `permission_target` with the actual grants |
| `default_acl_diffs()` | compare `default_acl_target` with `pg_default_acl` |
| `permission_fix_sql()` | the `GRANT`/`REVOKE` statements that would resolve every diff |
| `permission_apply(dry_run)` | execute those statements, or just return them |
| `permission_target_snapshot(role, schema)` | adopt the current grants as the baseline |
| `permission_source(role, type, oid, attnum, permission)` | why a privilege is held |
| `role_drop(role, new_owner, drop_role)` | reassign ownership, revoke privileges and drop a role |
| `role_dependencies(role)` | what still depends on a role |

The remaining functions (`permission_granted`, `permission_visible`,
`permission_objects`, `permission_roles`, `permission_acl`,
`permission_sql`, `permission_is_extension_object`, `default_acl_effective`,
`default_acl_objtype`, `permission_target_check`, `default_acl_target_check`,
`permissions_trigger_func`) are internal helpers; they are not part of the
supported interface.

The table function `permission_diffs()` checks the desired permissions in
`permission_target` against the actually granted permissions in the views
of the extension and returns a table of differences.

If the first column `missing` is `TRUE`, the result is a permission that should
be there but isn't; if `missing` is `FALSE`, the result row is a permission that
is there even though it is not defined in `permission_target` (an extra
permission).

**Note:** extra permissions are only searched for on objects that are
covered by at least one entry in `permission_target`: the audit checks the
scope described by the desired state, not the whole cluster.  Privileges on
objects that no target entry mentions are neither reported as missing nor
as extra.

Only the roles that appear in `permission_target`, plus the roles that inherit
from them, are examined.  A role that is not managed at all is out of scope;
use `all_permissions` for an unfiltered audit.

The table function `default_acl_diffs()` does the same for
`default_acl_target` and `ALTER DEFAULT PRIVILEGES`; see
[Default privileges](#default-privileges).

#### Comparing desired and actual state ####

Suppose `appuser` should be able to read and write all tables in `appschema`,
while `reporting` should only be allowed to read them.  We record that as the
desired state:

    INSERT INTO permission_target (role_name, permissions, object_type, schema_name)
    VALUES ('appuser',   '{SELECT,INSERT,UPDATE,DELETE}', 'TABLE', 'appschema'),
           ('reporting', '{SELECT}',                      'TABLE', 'appschema');

Over time the actual grants drifted: `appuser` never received `DELETE`, and
`reporting` was accidentally given `INSERT`:

    GRANT SELECT, INSERT, UPDATE ON appschema.invoice TO appuser;
    GRANT SELECT, INSERT         ON appschema.invoice TO reporting;

`permission_diffs()` reports exactly these two deviations:

    SELECT * FROM permission_diffs()
    WHERE role_name IN ('appuser', 'reporting')
    ORDER BY missing, role_name, permission;

     missing | role_name | object_type | schema_name | object_name | column_name | permission
    ---------+-----------+-------------+-------------+-------------+-------------+------------
     f       | reporting | TABLE       | appschema   | invoice     |             | INSERT
     t       | appuser   | TABLE       | appschema   | invoice     |             | DELETE

The `DELETE` privilege is missing for `appuser` (`missing` is `t`), while
`reporting` holds a surplus `INSERT` privilege (`missing` is `f`).  Because the
permission views are updatable, both can be corrected without writing `GRANT`
or `REVOKE` by hand:

    -- grant the missing privilege
    UPDATE table_permissions SET granted = true
    WHERE role_name = 'appuser' AND schema_name = 'appschema'
      AND object_name = 'invoice' AND permission = 'DELETE';

    -- revoke the surplus privilege
    UPDATE table_permissions SET granted = false
    WHERE role_name = 'reporting' AND schema_name = 'appschema'
      AND object_name = 'invoice' AND permission = 'INSERT';

Running `permission_diffs()` again now returns no rows: the actual state
matches the desired state.

### Bootstrapping a baseline ###

Writing the desired state by hand is tedious, so `permission_target_snapshot()`
adopts the current grants as the baseline:

    -- everything the role currently holds
    SELECT permission_target_snapshot('appuser');

    -- or only what it holds in one schema
    SELECT permission_target_snapshot('appuser', 'appschema');

It returns the number of targets it inserted, skips targets that already
exist, and ignores the extension's own tables and views.  The usual workflow
is to snapshot, then delete the rows that should *not* be there — the
remaining rows are the approved baseline.

### Why is a privilege held? ###

The `source` column of the permission views answers the question that
otherwise needs three catalog queries:

    SELECT role_name, permission, granted, source
    FROM table_permissions
    WHERE schema_name = 'appschema' AND object_name = 'invoice'
      AND role_name = 'reporting';

     role_name | permission | granted | source
    -----------+------------+---------+----------------
     reporting | SELECT     | t       | role:readers
     reporting | INSERT     | t       | direct

`owner` means the role owns the object, `direct` means the privilege is in
the object's ACL, `PUBLIC` means it comes from a grant to `PUBLIC`, and
`role:<name>` names the role it is inherited from.

### Reviewing and applying fixes ###

`permission_fix_sql()` returns the statement that would resolve each
difference, without executing anything:

    SELECT missing, role_name, object_name, permission, sql
    FROM permission_fix_sql();

     missing | role_name | object_name | permission |                  sql
    ---------+-----------+-------------+------------+----------------------------------------
     t       | appuser   | invoice     | DELETE     | GRANT DELETE ON appschema.invoice TO appuser
     f       | reporting | invoice     | INSERT     | REVOKE INSERT ON appschema.invoice FROM reporting

`permission_apply()` is a dry run by default and returns the same statements;
pass `false` to execute them:

    SELECT permission_apply();        -- review
    SELECT permission_apply(false);   -- execute

### Triaging a large diff ###

One target row can produce thousands of diff rows.  `permission_diff_summary`
collapses them per role, object type, schema and privilege:

    SELECT * FROM permission_diff_summary ORDER BY objects DESC;

     missing | role_name | object_type | schema_name | permission | objects
    ---------+-----------+-------------+-------------+------------+---------
     t       | appuser   | TABLE       | appschema   | SELECT     |     412
     f       | reporting | TABLE       | appschema   | INSERT     |       3

### PUBLIC ###

`PUBLIC` is not a row in `pg_roles`, but it is a grantee like any other.  The
`*_permissions` views therefore contain a `PUBLIC` row for every object, and
`PUBLIC` can be used in `permission_target`:

    INSERT INTO permission_target (role_name, permissions, object_type, schema_name)
    VALUES ('PUBLIC', '{SELECT}', 'TABLE', 'appschema');

A privilege granted to `PUBLIC` is held by every role, so it is reported as
granted for every role as well.  Targeting `PUBLIC` is the way to express
"everybody may read this".

### Role membership ###

`permission_diffs()` understands role membership.  If `reporting` is a member
of `readers` and `readers` is targeted with `SELECT`, then `reporting` is not
reported as holding a surplus `SELECT`: the privilege is inherited, not
granted directly.  A direct grant to `reporting` is still reported.

Only the roles that appear in `permission_target`, plus the roles that inherit
from them, are examined.  A role that is not managed at all is out of scope;
use `all_permissions` for an unfiltered audit.

### Default privileges ###

`ALTER DEFAULT PRIVILEGES` decides what new objects are granted, and in most
production setups it is where the real policy lives.  It is modelled
separately from the object permissions:

    INSERT INTO default_acl_target
       (for_role_name, schema_name, object_type, role_name, permissions)
    VALUES ('appowner', NULL, 'TABLE', 'appuser', '{SELECT,INSERT}');

This says that objects of type `TABLE` created by `appowner` (in any schema,
because `schema_name` is NULL) should grant `SELECT` and `INSERT` to
`appuser` by default.  `object_type` must be `TABLE`, `SEQUENCE` or
`FUNCTION`; `for_role_name` is the role whose objects the default applies
to, and `role_name` is the grantee (which may be `PUBLIC`).
`default_acl_diffs()` compares the target with `pg_default_acl` and returns
the same `missing` / extra shape as `permission_diffs()`, while
`default_acl_permissions` shows the entries that are actually present.

A per-schema entry takes precedence over the global one, exactly as
PostgreSQL applies them, so a target for a specific schema is satisfied by
the global entry when no per-schema entry exists.

### Protecting the desired state ###

`permission_target` and `default_acl_target` are the compliance baseline, so
they are readable by `PUBLIC` but not writable by it.  Only the extension
owner and roles that are explicitly granted write access may change them:

    GRANT INSERT, UPDATE, DELETE ON permission_target TO compliance_admin;
    GRANT USAGE ON SEQUENCE permission_target_id_seq TO compliance_admin;
    GRANT INSERT, UPDATE, DELETE ON default_acl_target TO compliance_admin;
    GRANT USAGE ON SEQUENCE default_acl_target_id_seq TO compliance_admin;

The `*_permissions` views are updatable, but by default only for the owner of
the extension (or a superuser), because the `INSTEAD OF` trigger issues
`GRANT` and `REVOKE` as the invoking user.  Granting `UPDATE` on a view to
another role lets that role change privileges too.

A target whose role does not exist is rejected when it is inserted.  If the
role is dropped later, the target stays behind and `permission_diffs()`
ignores it, so remove such rows when you drop a role:

    DELETE FROM permission_target
    WHERE role_name <> 'PUBLIC'
      AND role_name NOT IN (SELECT rolname FROM pg_roles);

### Removing a role ###

`DROP ROLE` fails while the role still owns objects or holds privileges.
`role_drop()` performs the three steps in one transaction:

    SELECT * FROM role_drop('olduser', 'newuser');

     step           | statement
    ----------------+------------------------------------------
     reassign owned | REASSIGN OWNED BY olduser TO newuser
     drop owned     | DROP OWNED BY olduser
     drop role      | DROP ROLE olduser

`REASSIGN OWNED` moves everything the role owns to `newuser`; `DROP OWNED`
revokes every privilege granted to the role and removes its default ACL
entries; `DROP ROLE` then removes the role.  Without a successor the owned
objects are dropped instead:

    SELECT * FROM role_drop('olduser');

`REASSIGN OWNED` and `DROP OWNED` only cover the current database (plus
shared objects such as databases and tablespaces).  If the role owns objects
in several databases, clean each one first and drop the role last:

    -- in every database that contains objects owned by olduser
    SELECT * FROM role_drop('olduser', 'newuser', false);

    -- once nothing depends on it any more
    SELECT * FROM role_drop('olduser', 'newuser', true);

`role_dependencies()` lists what still blocks the drop:

    SELECT * FROM role_dependencies('olduser');

     database | kind        | object
    ----------+-------------+------------------------
     postgres | default acl | TABLE (all schemas)
     postgres | relation    | invoice
     otherdb  | relation    |

A NULL `object` means the object lives in another database, whose catalog
cannot be read from here; a NULL `database` means a shared object.

The function runs as the caller, so it needs the same privileges as the
underlying commands: membership in both roles for `REASSIGN OWNED`,
membership in the role for `DROP OWNED`, and `CREATEROLE` or superuser for
`DROP ROLE`.

Installation
------------

Make sure the PostgreSQL extension building infrastructure is installed.
If you installed PostgreSQL with installation packages, you usually need to
install the "development"-Package.

Make sure that `pg_config` is on your `PATH`.  Then type

    make install

PostgreSQL 15 or later is required.

Then connect to the database where you want to run `pg_permissions` and use

    CREATE EXTENSION pg_permissions;

To upgrade from an older version of the extension, run one
`ALTER EXTENSION ... UPDATE TO` per step:

    ALTER EXTENSION pg_permissions UPDATE TO '1.1';
    ALTER EXTENSION pg_permissions UPDATE TO '1.2';
    ALTER EXTENSION pg_permissions UPDATE TO '1.3';
    ALTER EXTENSION pg_permissions UPDATE TO '1.4';
    ALTER EXTENSION pg_permissions UPDATE TO '1.5';
    ALTER EXTENSION pg_permissions UPDATE TO '1.6';

`ALTER EXTENSION pg_permissions UPDATE` without `TO` only works when a
direct update script from the installed version exists.

You need `CREATE` privileges on the schema where you install the extension.

Version 1.6 adds the update script from 1.2 to 1.3 that earlier releases
were missing, so a database created with 1.2 can be upgraded again.  The
1.5 to 1.6 step rewrites `permission_target`: entries with an empty
permission list are dropped, a `COLUMN` entry without a column name becomes
a table-level entry, and duplicate entries are merged.

### Installation without the extension building infrastructure ###

This is also what Windows users will have to do because there is no extension
building infrastructure for Windows.

Find out where your PostgreSQL share directory is:

    pg_config --sharedir

Then copy `pg_permissions.control` and the SQL files to the `extension`
subdirectory of that directory, e.g.

    copy pg_permissions.control *.sql "C:\Program Files\PostgreSQL\18\share\extension"

You still have to run `CREATE EXTENSION` as described above.

Compliance
----------

Virtually every security and data-protection framework requires that access to
data be limited to those who need it (the principle of least privilege), that
this access be reviewed regularly, and that the review be auditable.
`pg_permissions` supports those three obligations directly:

| Obligation | How the extension supports it |
|---|---|
| Least privilege | `permission_target` records the intended entitlements; `permission_diffs()` reports every privilege that is held but not intended (`missing = false`). |
| Periodic review | `permission_diffs()` and `default_acl_diffs()` return a machine-readable result set that can be scheduled, diffed between runs, and attached to a ticket. |
| Auditability | `all_permissions` is a complete, queryable snapshot of the current state; `permission_target` is the recorded intent, and both are ordinary tables and views that can be exported with `COPY`. |
| Segregation of duties | The desired state is readable by `PUBLIC` but writable only by explicitly authorised roles, so the person who reviews access need not be the person who can change the baseline. |
| Provisioning drift | `default_acl_target` and `default_acl_diffs()` cover `ALTER DEFAULT PRIVILEGES`, which is where most production policies actually live. |

### A review procedure ###

A quarterly access review can be run entirely from `psql`:

    -- 1. capture the current state as evidence
    \copy (SELECT * FROM all_permissions ORDER BY 1, 2, 3, 4, 5, 6, 7, 8) TO 'access-review-2026-Q4.csv' WITH (FORMAT csv, HEADER)

    -- 2. list every deviation from the recorded intent
    \copy (SELECT * FROM permission_diffs() ORDER BY 1, 2, 3, 4, 5, 6, 7) TO 'access-diffs-2026-Q4.csv' WITH (FORMAT csv, HEADER)

    -- 3. the same for default privileges
    \copy (SELECT * FROM default_acl_diffs() ORDER BY 1, 2, 3, 4, 5, 6) TO 'default-acl-diffs-2026-Q4.csv' WITH (FORMAT csv, HEADER)

`\copy` writes the file on the client, so no server-side file access is
needed.

An empty `permission_diffs()` result is the evidence that the database matches
the approved baseline.  A non-empty result is the work list: each row can be
corrected through the updatable views, or the baseline can be amended if the
grant was approved.

### Framework mapping ###

The extension is useful when demonstrating database access controls for,
among others:

- **SOX** (Sarbanes-Oxley): IT general controls under section 404 — evidence
  that access to financial data is restricted and periodically reviewed.

- **PCI DSS**: requirements 7 and 8, which mandate restricting access to
  cardholder data on a business need-to-know basis and reviewing it at least
  every six months.

- **GDPR**: Article 32 (security of processing), which expects access to
  personal data to be limited to what is necessary, and Article 30 records of
  processing activities, for which the permission snapshot is useful input.

- **HIPAA**: the Security Rule's access-control standard
  (§ 164.312(a)) for electronic protected health information, and the
  audit-control standard (§ 164.312(b)).

- **ISO/IEC 27001 / 27002**: the access-control objectives (Annex A.9 /
  control 5.15 and following) covering formal entitlement and periodic review.

- **SOC 2**: the Security and Confidentiality trust-services criteria around
  logical access, in particular CC6.1 and CC6.3.

- **DORA**: the EU Digital Operational Resilience Act's access-management
  requirements for financial entities.

- **NIST SP 800-53**: the AC-2 (account management) and AC-6 (least
  privilege) controls, which call for reviewing and reconciling accounts and
  privileges.

### What the extension does not do ###

It reports and reconciles; it does not enforce.  A `GRANT` issued outside the
extension takes effect immediately and is only visible the next time
`permission_diffs()` runs.  It also does not cover every object type: row-level
security policies, `SECURITY DEFINER` function ownership, tablespace, language,
type, domain, foreign-data-wrapper, server and large-object privileges, and
`pg_hba.conf` authentication rules are outside its scope.  Default privileges
are covered for tables, sequences and functions, not for types or schemas.
Treat it as one control in a layered access management programme, not as the
programme itself.

Support
-------

Open an [issue][issue] on GitHub if you have problems or questions.

For professional support, please contact
[CYBERTEC PostgreSQL International GmbH][cybertec].


 [issue]: https://github.com/cybertec-postgresql/pg_permissions/issues
 [cybertec]: https://www.cybertec-postgresql.com/
