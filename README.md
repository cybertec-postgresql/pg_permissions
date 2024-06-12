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

    SELECT * FROM public.permission_diffs();

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

    SELECT * FROM schema_permissions
       WHERE role_name = 'appuser' AND schema_name = 'appschema';

     object_type | role_name | schema_name | object_name | column_name | permissions | granted
    -------------+-----------+-------------+-------------+-------------+-------------+---------
     SCHEMA      | appuser   | appschema   |             |             | USAGE       | t
     SCHEMA      | appuser   | appschema   |             |             | CREATE      | f
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

All views have the same columns; a column is NULL if it has no meaning
for the current view.

These views can be used to examine the currently granted permissions on
database objects.

The `granted` column of these views can be updated, which causes the
appropriate `GRANT` or `REVOKE` command to be executed.

**Note:** Superusers are not shown in the views, as they automatically have all
permissions.

### Tables ###

The extension provides a table `permission_target` with which you can describe
the permissions that *should* be granted on database objects.

If you set a relevant column in `permission_target` to NULL (e.g., the
`object_name` and `column_name` columns in a `TABLE` entry), the meaning is
that the entry refers to *all* possible objects (in the example above, all
tables in the schema).

### Functions ###

The table function `permission_diffs()` checks the desired permissions in
`permission_target` against the actually granted permissions in the views
of the extension and returns a table of differences.

If the first column `missing` is `TRUE`, the result is a permission that should
be there but isn't; if `missing` is `FALSE`, the result row is a permission that
is there even though it is not defined in `permission_target` (an extra
permission).

Installation
------------

Make sure the PostgreSQL extension building infrastructure is installed.
If you installed PostgreSQL with installation packages, you usually need to
install the "development"-Package.

Make sure that `pg_config` is on your `PATH`.  Then type

    make install

Then connect to the database where you want to run `pg_permissions` and use

    CREATE EXTENSION pg_permissions;

To upgrade from an older version of the extension, run

    ALTER EXTENSION pg_permissions UPDATE;

You need `CREATE` privileges on the schema where you install the extension.

Note that you won't be able to upgrade the extension from version 1.2 or
earlier to 1.3 or later for technical reasons (an added enumeration value for
the `MAINTAIN` privilege).  You will have to drop and re-create the extension
to upgrade to 1.3 or later from an earlier release.  Don't forget to dump
the contents of `permission_target` before you do that, so that you can restore
them afterwards.

### Installation without the extension building infrastructure ###

This is also what Windows users will have to do because there is no extension
building infrastructure for Windows.

Find out where your PostgreSQL share directory is:

    pg_config --sharedir

Then copy `pg_permissions.control` and the SQL files to the `extension`
subdirectory of that directory, e.g.

    copy pg_permissions.control *.sql "C:\Program Files\PostgreSQL\10\share\extension"

You still have to run `CREATE EXTENSION` as described above.

Support
-------

Open an [issue][issue] on GitHub if you have problems or questions.

For professional support, please contact
[CYBERTEC PostgreSQL International GmbH][cybertec].


 [issue]: https://github.com/cybertec-postgresql/pg_permissions/issues
 [cybertec]: https://www.cybertec-postgresql.com/
