\echo Use "CREATE EXTENSION pg_snakeoil" to load this file. \quit

-- Returns true if given data matches signature in virus database
-- Shows the virus name as notice
CREATE FUNCTION pg_snakeoil_find_virus (text) RETURNS bool
AS 'MODULE_PATHNAME', 'pg_snakeoil_find_virus'
LANGUAGE C IMMUTABLE STRICT;

-- Returns name if given data matches signature in virus database
CREATE FUNCTION pg_snakeoil_virus_name (text) RETURNS text
AS 'MODULE_PATHNAME', 'pg_snakeoil_virus_name'
LANGUAGE C IMMUTABLE STRICT;
