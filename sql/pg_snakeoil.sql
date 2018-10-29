CREATE EXTENSION pg_snakeoil;

SELECT pg_snakeoil_find_virus('X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*');
SELECT pg_snakeoil_virus_name('X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*');
SELECT pg_snakeoil_find_virus('Hello World!');
SELECT pg_snakeoil_virus_name('Hello World!');
