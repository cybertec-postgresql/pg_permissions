BEGIN;

CREATE TABLE permissions.t_desired_permission
(
	id		int4	PRIMARY KEY,
	rolname		text,
	perms		text[],
	operation	text,
	obj		text,
	sub_obj		text
);

INSERT INTO permissions.t_desired_permission
	VALUES	(1, 'anon', '{"SELECT", "INSERT"}', 'all_tables_in_schema', 'public', NULL), 
			-- anon should have SELECT and INSERT in all tables in schema public
	      
		(2, NULL, '{"SELECT"}', 'all_tables_in_schema', 'sales', NULL),
			-- everbody should have SELECT on all tables in schema sales

		(3, NULL, '{"USAGE"}', 'all_schemas', NULL, NULL),
			-- everybody should have usage rights in all schemas

		(4, 'joe', '{"SELECT"}', 'on_table', 'public', 't_test'),
			-- joe should have SELECT on table public.t_test

		(5, NULL, '{"SELECT", "INSERT"}', NULL, NULL, NULL),
			-- everbody should have SELECT and INSERT on all tables and views in all schemas

		(6, 'joe', '{"SELECT"}', 'on_view', 'public', 'v_test'),
			-- joe should have SELECT on view public.v_test

		(7, NULL, '{"EXECUTE"}', 'on_functions_in_schema', 'public', NULL)
			-- everbody should have EXECUTE on all function in schema public
;

ROLLBACK;

