-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "ALTER EXTENSION pg_permissions UPDATE" to load this file. \quit

CREATE SEQUENCE permission_target_id_seq OWNED BY permission_target.id;
ALTER TABLE permission_target ALTER id
   SET DEFAULT nextval('permission_target_id_seq'::regclass);

GRANT USAGE ON SEQUENCE permission_target_id_seq TO PUBLIC;

SELECT pg_catalog.pg_extension_config_dump('permission_target_id_seq', '');
