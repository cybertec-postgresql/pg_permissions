BEGIN;

CREATE MATERIALIZED VIEW security_status AS SELECT * FROM permissions.all_permissions;

SELECT count(*) FROM security_status;


CREATE TABLE track_security_changes (LIKE security_status);
ALTER TABLE track_security_changes ADD COLUMN t timestamptz DEFAULT now();
ALTER TABLE track_security_changes ADD COLUMN change text CHECK (change IN ('added', 'removed')) NOT NULL;

-- create a function and an event trigger
CREATE OR REPLACE FUNCTION detect_permission_change()
RETURNS event_trigger AS
$$
	BEGIN
		RAISE NOTICE 'checking security situation for % and %', tg_event, tg_tag;
		INSERT INTO track_security_changes
		SELECT	*, now(), 'added'
		FROM (
			SELECT 	* FROM permissions.all_permissions
			EXCEPT
			SELECT  * FROM security_status
      		     ) AS x
		UNION ALL
		SELECT	*, now(), 'removed'
		FROM (
			SELECT  * FROM security_status
			EXCEPT
			SELECT 	* FROM permissions.all_permissions
		     ) AS x;
	END;
$$ LANGUAGE 'plpgsql';

CREATE EVENT TRIGGER detect_permission_change
	ON ddl_command_end
	EXECUTE PROCEDURE detect_permission_change();


-- test the code
-- CREATE TABLE t_abc (id int);
-- GRANT ALL ON t_abc TO jane;
-- DROP TABLE t_test;

-- SELECT * FROM track_security_changes WHERE object_type <> 'column';

