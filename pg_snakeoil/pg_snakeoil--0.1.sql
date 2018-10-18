\echo Use "CREATE EXTENSION pg_snakeoil" to load this file. \quit

CREATE FUNCTION pg_snakeoil_scan (text) RETURNS bool
AS 'MODULE_PATHNAME', 'pg_snakeoil_scan'
LANGUAGE C IMMUTABLE STRICT;
