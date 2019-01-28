CREATE EXTENSION pg_snakeoil;

-- ------------------------------------------------------------------------
-- Management Functions
-- ------------------------------------------------------------------------

SELECT so_update_signatures();

-- ------------------------------------------------------------------------
-- Text Functions
-- ------------------------------------------------------------------------

SELECT so_is_infected('X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*');
SELECT so_virus_name('X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*');
SELECT so_is_infected('Hello World!');
SELECT so_virus_name('Hello World!');

-- ------------------------------------------------------------------------
-- bytea Functions
-- ------------------------------------------------------------------------

SELECT so_is_infected(E'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'::bytea);
SELECT so_virus_name(E'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'::bytea);
SELECT so_is_infected(E'Hello World!'::bytea);
SELECT so_virus_name(E'Hello World!'::bytea);
