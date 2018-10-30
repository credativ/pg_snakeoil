\echo Use "CREATE EXTENSION pg_snakeoil" to load this file. \quit

-- ------------------------------------------------------------------------
-- Text Functions
-- ------------------------------------------------------------------------

-- Returns true if the given data matches a signature in the virus database
CREATE FUNCTION so_is_infected (text) RETURNS bool
AS 'MODULE_PATHNAME', 'so_is_infected'
LANGUAGE C IMMUTABLE STRICT;

-- Returns virus name if the given data matches a signature in the
-- virus database, empty string otherwise
CREATE FUNCTION so_virus_name (text) RETURNS text
AS 'MODULE_PATHNAME', 'so_virus_name'
LANGUAGE C IMMUTABLE STRICT;

-- ------------------------------------------------------------------------
-- bytea Functions
-- ------------------------------------------------------------------------

-- Returns true if the given data matches a signature in the virus database
CREATE FUNCTION so_is_infected (bytea) RETURNS bool
AS 'MODULE_PATHNAME', 'so_is_infected'
LANGUAGE C IMMUTABLE STRICT;

-- Returns virus name if the given data matches a signature in the
-- virus database, empty string otherwise
CREATE FUNCTION so_virus_name (bytea) RETURNS text
AS 'MODULE_PATHNAME', 'so_virus_name'
LANGUAGE C IMMUTABLE STRICT;