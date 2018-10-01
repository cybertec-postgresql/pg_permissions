PostgreSQL permission reports and checks
========================================

This extension allows you to review object permissions on a PostgreSQL database.

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

The `subobject_name` column only has a meaning in `column_permissions`, where
it denotes the column name.

These views can be used to examine the currently granted permissions on
database objects.

**Note:** Superusers are not show in the view, as they automatically have
all permissions.

### Tables ###

The extension provides a table `permission_target` with which you can describe
the permissions that *should* be granted on database objects.

If you set a relevant column in `permission_target` to NULL (e.g., the
`object_name` and `subobject_name` columns in a `TABLE` entry), the meaning is
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

You need `CREATE` privileges on the schema where you install the extension.

### Installation without the extension building infrastructure ###

This is also what Windows users will have to dom because there is no extension
building infrastructure for Windows.

Find out where your PostgreSQL share directory is:

    pg_config --sharedir

Then copy `pg_permissions.control` and the SQL files to the `extension`
subdirectory of that directory, e.g.

    copy pg_permissions.control *.sql "C:\Program Files\PostgreSQL\10\share\extension"

You still have to run `CREATE EXTENSION` as described above.
