-- TODO: later in development we will use CREATE EXTENSION
--
-- Documentation:
--
-- this package has been made to give people a quick overview of 
-- permissions assigned to people. basically it is a set of view
-- which all have the same structure to make sure that we can
-- query ONE view to fetch all the data at once.
-- it will allow you to fetch ALL information for a user in ONE
-- step easily.
-- 
-- just run ... SELECT * FROM permissions.all_permissions 
-- to figure out.

------------------------------------------------------------------
BEGIN;

CREATE SCHEMA permissions;

SET search_path TO permissions;

CREATE FUNCTION generate_tablename(name, name) 
RETURNS text AS
$$
	SELECT quote_ident($1) || '.' || quote_ident($2);
$$
LANGUAGE 'sql' IMMUTABLE PARALLEL SAFE;

-- permissions on tables
CREATE VIEW table_permissions AS
	WITH list AS (SELECT unnest AS perm 
			FROM unnest ('{"INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"}'::text[]))
	SELECT		'table' AS object_type,
			rolname AS username,
			schemaname AS object,
			tablename  AS sub_object,
			NULL::text AS sub_sub_object,
			perm_list.perm AS permission,
			has_table_privilege(rolname, generate_tablename(schemaname, tablename), perm_list.perm) AS has_permission
	FROM		pg_tables, pg_authid, LATERAL (SELECT * FROM list) AS perm_list 
	WHERE		schemaname NOT IN ('information_schema', 'pg_catalog')
	ORDER BY 1, 2, 3, 4
;

-- permissions on views
CREATE VIEW view_permissions AS
	WITH list AS (SELECT unnest AS perm 
			FROM unnest ('{"INSERT", "UPDATE", "DELETE", "TRIGGER"}'::text[]))
	SELECT		'view' AS object_type,
			rolname AS username,
			schemaname AS object,
			viewname  AS sub_object,
			NULL::text AS sub_sub_object,
			perm_list.perm AS permission,
			has_table_privilege(rolname, generate_tablename(schemaname, viewname), perm_list.perm) AS has_permission
	FROM		pg_views, pg_authid, LATERAL (SELECT * FROM list) AS perm_list 
	WHERE		schemaname NOT IN ('information_schema', 'pg_catalog')
	ORDER BY 1, 2, 3, 4
;

-- column permissions
CREATE VIEW column_permissions AS
	WITH list AS (SELECT unnest AS perm 
			FROM unnest ('{"SELECT", "INSERT", "UPDATE", "REFERENCES"}'::text[]))
	SELECT		'column' AS object_type,
			rolname AS username,
			schemaname AS object,
			tablename  AS sub_object,
			col.colname::text AS sub_sub_object,
			perm_list.perm AS permission,
			has_column_privilege(rolname, generate_tablename(schemaname, tablename), 
				col.colname, perm_list.perm) AS has_permission
	FROM		(SELECT	schemaname, tablename
				FROM pg_tables
			 UNION ALL
			 SELECT schemaname, viewname
				FROM pg_views) AS relations, 
			pg_authid, 
			LATERAL (SELECT * FROM list) AS perm_list, 
			LATERAL (SELECT a.attname AS colname
				 FROM pg_catalog.pg_attribute a
				 WHERE a.attrelid = generate_tablename(schemaname, tablename)::regclass::oid 
					AND a.attnum > 0 
					AND NOT a.attisdropped
					ORDER BY a.attnum
				) AS col
	WHERE		schemaname NOT IN ('information_schema', 'pg_catalog')
	ORDER BY 1, 2, 3, 4
;

-- SELECT * FROM column_permissions;

-- permissions on procedures
CREATE VIEW function_permissions AS
	SELECT  'function' AS object_type,
		rolname AS username,
	        n.nspname AS object,
       	 	p.proname AS sub_object,
        	pg_catalog.pg_get_function_arguments(p.oid) AS sub_sub_object,
		'EXECUTE' AS permission,
        	has_function_privilege(rolname, p.oid, 'EXECUTE') AS has_permission
	FROM 	pg_catalog.pg_proc p
     		LEFT JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace,
		LATERAL (SELECT * FROM pg_authid) AS auth
	WHERE 	n.nspname NOT IN ('pg_catalog', 'information_schema')
	ORDER BY 1, 2;

-- SELECT * FROM function_permissions;

-- schema permissions
CREATE VIEW schema_permissions AS
	WITH list AS (SELECT unnest AS perm 
			FROM unnest ('{"USAGE", "CREATE"}'::text[]))
	SELECT 	'schema' AS object_type,
		rolname AS username,
		n.nspname AS object,
		NULL::text AS sub_object,
		NULL::text AS sub_sub_object,
		perm_list.perm AS permissions,
		has_schema_privilege(rolname, n.nspname, perm_list.perm) AS has_permission
	FROM 	pg_catalog.pg_namespace n, pg_authid, list AS perm_list
	WHERE 	n.nspname !~ '^pg_' 
		AND n.nspname <> 'information_schema'
	ORDER BY 1, 2, 3, 4;

-- SELECT * FROM schema_permissions;

-- database permissions
CREATE VIEW database_permissions AS
	WITH list AS (SELECT unnest AS perm 
			FROM unnest ('{"CREATE", "CONNECT", "TEMPORARY"}'::text[]))
	SELECT 	'database' AS object_type,
		rolname AS username,
		datname AS object,
		NULL::text AS sub_object,
		NULL::text AS sub_sub_object,
		perm_list.perm AS permissions,
		has_database_privilege(rolname, datname, perm_list.perm) AS has_permission
	FROM 	pg_database, pg_authid, list AS perm_list
	ORDER BY 1, 2, 3, 4;

-- SELECT * FROM database_permissions;

CREATE VIEW all_permissions
AS
	SELECT	* FROM table_permissions
	UNION ALL
	SELECT 	* FROM view_permissions
	UNION ALL
	SELECT	* FROM column_permissions
	UNION ALL
	SELECT	* FROM function_permissions
	UNION ALL
	SELECT	* FROM schema_permissions
	UNION ALL
	SELECT	* FROM database_permissions
;

-- SELECT * FROM all_permissions;

COMMIT;

