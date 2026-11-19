-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "ALTER EXTENSION pg_permissions UPDATE" to load this file. \quit

/*
 * Version 1.3 added the MAINTAIN privilege, which is a new value of the
 * perm_type enumeration.  A new enumeration value cannot be used in the
 * transaction that adds it, so this script only adds the value; the views
 * that reference it are created by the 1.3 -> 1.4 script, which runs in a
 * later transaction.
 *
 * Without this script a database that was created with version 1.2 could
 * never be upgraded: there was no update path from 1.2 to 1.3.
 */
ALTER TYPE perm_type ADD VALUE 'MAINTAIN';
