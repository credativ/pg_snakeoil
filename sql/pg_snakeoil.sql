CREATE EXTENSION pg_snakeoil;

-- ------------------------------------------------------------------------
-- Management Functions
-- ------------------------------------------------------------------------

SELECT so_update_signatures();

-- ------------------------------------------------------------------------
-- Text Functions
-- ------------------------------------------------------------------------

SELECT so_is_infected('the quick brown fox jumps over the lazy dog');
SELECT so_virus_name('the quick brown fox jumps over the lazy dog');
SELECT so_is_infected('Hello World!');
SELECT so_virus_name('Hello World!');

-- ------------------------------------------------------------------------
-- bytea Functions
-- ------------------------------------------------------------------------

SELECT so_is_infected('the quick brown fox jumps over the lazy dog'::bytea);
SELECT so_virus_name('the quick brown fox jumps over the lazy dog'::bytea);
SELECT so_is_infected('Hello World!'::bytea);
SELECT so_virus_name('Hello World!'::bytea);
