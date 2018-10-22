\echo Use "CREATE EXTENSION pg_snakeoil" to load this file. \quit

-- Returns true if the given data matches a signature in the virus database
-- Will only show the virus name as a notice
CREATE FUNCTION pg_snakeoil_find_virus (text) RETURNS bool
AS 'MODULE_PATHNAME', 'pg_snakeoil_find_virus'
LANGUAGE C IMMUTABLE STRICT;

-- Returns virus name if the given data matches a signature in the
-- virus database, empty string otherwise
CREATE FUNCTION pg_snakeoil_virus_name (text) RETURNS text
AS 'MODULE_PATHNAME', 'pg_snakeoil_virus_name'
LANGUAGE C IMMUTABLE STRICT;
