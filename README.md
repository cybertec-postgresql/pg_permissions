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

All views share the same columns:

- `object_type`: the kind of object (`TABLE`, `VIEW`, `COLUMN`, `SEQUENCE`,
  `FUNCTION`, `SCHEMA` or `DATABASE`)
- `role_name`: the role the permission applies to
- `schema_name`, `object_name`, `column_name`: identify the object
- `permission`: the privilege in question (`SELECT`, `USAGE`, `EXECUTE`, ...)
- `granted`: whether the privilege is currently in effect (`t`) or not (`f`)

A column is NULL if it has no meaning for the current view; for example,
`column_name` is only set in `column_permissions`, and `schema_name` is
always NULL in `database_permissions`.

`table_permissions` contains regular, partitioned and foreign tables (all
labeled `TABLE`), `view_permissions` contains views and materialized views
(both labeled `VIEW`), and `function_permissions` contains functions,
aggregates, window functions and procedures (all labeled `FUNCTION`).
Toast tables and the system catalogs are not covered.

These views can be used to examine the currently granted permissions on
database objects.

The `granted` column of these views can be updated, which causes the
appropriate `GRANT` or `REVOKE` command to be executed.

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
    WHERE schema_name = 'appschema' AND role_name IN ('appuser', 'reporting');

     role_name | object_name | permission | granted
    -----------+-------------+------------+---------
     appuser   | invoice     | SELECT     | t
     appuser   | invoice     | INSERT     | t
     appuser   | invoice     | UPDATE     | t
     appuser   | invoice     | DELETE     | t
     appuser   | invoice     | TRUNCATE   | f
     appuser   | invoice     | REFERENCES | f
     appuser   | invoice     | TRIGGER    | f
     reporting | invoice     | SELECT     | t
     reporting | invoice     | INSERT     | f
     reporting | invoice     | UPDATE     | f
     reporting | invoice     | DELETE     | f
     reporting | invoice     | TRUNCATE   | f
     reporting | invoice     | REFERENCES | f
     reporting | invoice     | TRIGGER    | f

`view_permissions` is the same, but for views:

    SELECT role_name, object_name, permission, granted
    FROM view_permissions
    WHERE schema_name = 'appschema' AND role_name = 'reporting';

     role_name | object_name | permission | granted
    -----------+-------------+------------+---------
     reporting | invoice_v   | SELECT     | t
     reporting | invoice_v   | INSERT     | f
     reporting | invoice_v   | UPDATE     | f
     reporting | invoice_v   | DELETE     | f
     reporting | invoice_v   | TRUNCATE   | f
     reporting | invoice_v   | REFERENCES | f
     reporting | invoice_v   | TRIGGER    | f

`column_permissions` reports column level privileges.  Note that `granted` is
only `t` when the privilege is granted *on the column itself*; a privilege held
at the table level is not repeated here (use `table_permissions` for that).
Here `auditor` may read only the `customer` column:

    SELECT role_name, object_name, column_name, permission, granted
    FROM column_permissions
    WHERE schema_name = 'appschema' AND object_name = 'invoice' AND role_name = 'auditor';

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
    WHERE schema_name = 'appschema' AND role_name IN ('appuser', 'reporting');

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
    WHERE schema_name = 'appschema' AND role_name IN ('appuser', 'reporting');

     role_name | object_name | permission | granted
    -----------+-------------+------------+---------
     appuser   | total()     | EXECUTE    | f
     reporting | total()     | EXECUTE    | t

`database_permissions` shows the `CREATE`, `CONNECT` and `TEMPORARY` privileges
on the current database (`CONNECT` and `TEMPORARY` are granted to `PUBLIC` by
default):

    SELECT role_name, permission, granted
    FROM database_permissions
    WHERE role_name IN ('appuser', 'reporting');

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

### Functions ###

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
    WHERE role_name IN ('appuser', 'reporting');

     missing | role_name | object_type | schema_name | object_name | column_name | permission
    ---------+-----------+-------------+-------------+-------------+-------------+------------
     t       | appuser   | TABLE       | appschema   | invoice     |             | DELETE
     f       | reporting | TABLE       | appschema   | invoice     |             | INSERT

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

    copy pg_permissions.control *.sql "C:\Program Files\PostgreSQL\18\share\extension"

You still have to run `CREATE EXTENSION` as described above.

Compliance
----------

Virtually every security and data-protection framework requires that access to
data be limited to those who need it (the principle of least privilege), that
this access be reviewed regularly, and that the review be auditable.
`pg_permissions` directly supports those obligations: you declare the intended
permissions in `permission_target`, prove the current state with the
`*_permissions` views, and detect any drift with `permission_diffs()`.

This makes the extension useful when demonstrating database access controls
for, among others:

- **SOX** (Sarbanes-Oxley): IT general controls under section 404 — evidence
  that access to financial data is restricted and periodically reviewed.

- **PCI DSS**: requirements 7 and 8, which mandate restricting access to
  cardholder data on a business need-to-know basis.

- **GDPR**: Article 32 (security of processing), which expects access to
  personal data to be limited to what is necessary.

- **HIPAA**: the Security Rule's access-control standard
  (§ 164.312(a)) for electronic protected health information.

- **ISO/IEC 27001 / 27002**: the access-control objectives (Annex A.9 /
  control 5.15 and following) covering formal entitlement and periodic review.

- **SOC 2**: the Security and Confidentiality trust-services criteria around
  logical access.

- **DORA**: the EU Digital Operational Resilience Act's access-management
  requirements for financial entities.

The extension does not enforce these controls on its own; it provides the
reporting and reconciliation you need to define a desired state, prove the
current state, and catch any divergence between audits.

Support
-------

Open an [issue][issue] on GitHub if you have problems or questions.

For professional support, please contact
[CYBERTEC PostgreSQL International GmbH][cybertec].


 [issue]: https://github.com/cybertec-postgresql/pg_permissions/issues
 [cybertec]: https://www.cybertec-postgresql.com/
