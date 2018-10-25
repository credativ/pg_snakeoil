/*-------------------------------------------------------------------------
 *
 * pg_snakeoil.c
 * 		ClamAV antivirus integration, can check given data with ClamAV
 *
 * Copyright (c) 2018, Alexander Sosna <alexander.sosna@credativ.de>
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include <ctype.h>

#include "utils/builtins.h"
#include "utils/varlena.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <clamav.h>

PG_MODULE_MAGIC;

void _PG_init(void);
void _PG_fini(void);
struct scan_result scan_data(const char *data, size_t data_size);
Datum pg_snakeoil_find_virus(PG_FUNCTION_ARGS);
Datum pg_snakeoil_virus_name(PG_FUNCTION_ARGS);


/*
 * Holds the data of a virus scan
 */
struct scan_result
{
	int return_code;
	const char *virus_name;
	long unsigned int scanned;
};

/*
 * Global variable to access the clamav engine
 */
struct cl_engine *engine;

/*
 * Initialize the engine for further use, this takes some time!
 */
void _PG_init()
{
	const char *dbDir;
	unsigned int signatureNum;

	elog(NOTICE, "pg_snakeoil starts the clamav engine, this can take a while");

	if (CL_SUCCESS != cl_init(CL_INIT_DEFAULT))
	{
		elog(ERROR, "cl_init failed");
	}

	engine = cl_engine_new();
	dbDir = cl_retdbdir();
	signatureNum = 0;
	elog(DEBUG1, "Use default db dir '%s'", dbDir);

	if (CL_SUCCESS != cl_load(dbDir, engine, &signatureNum, CL_DB_STDOPT))
	{
		elog(ERROR, "cl_load failed");
	}

	elog(DEBUG1, "(cl_engine_compile)");
	if (CL_SUCCESS != cl_engine_compile(engine))
	{
		elog(ERROR, "cl_engine_compile failed");
	}
}

void _PG_fini()
{
	cl_engine_free(engine);
}

struct scan_result scan_data(const char *data, size_t data_size)
{
	struct scan_result result = {0, "", 0};
	cl_fmap_t *map;

	/*
	* Open a map for scanning custom data, where the data is already in memory,
	* either in the form of a buffer, a memory mapped file, etc.
	* Note that the memory [start, start+len) must be the _entire_ file,
	* you can't give it parts of a file and expect detection to work.
	*/
	elog(DEBUG2, "cl_fmap_open_memory");
	map = cl_fmap_open_memory(data, data_size);

	elog(DEBUG2, "data_size: %lu", data_size);
	elog(DEBUG2, "data: %s", pnstrdup(data, data_size)); // TODO: FIX OUTPUT

	/*
	 * Scan data
	 */
	elog(DEBUG2, "cl_scanmap_callback");
	result.return_code = cl_scanmap_callback(map, &result.virus_name, &result.scanned, engine, CL_SCAN_STDOPT, NULL);
	elog(DEBUG2, "cl_scanmap_callback returned: %d virusname: %s", result.return_code, result.virus_name);

	/*
	 * Releases resources associated with the map, you should release any resources
	 * you hold only after (handles, maps) calling this function
	 */
	elog(DEBUG2, "cl_fmap_close");
	cl_fmap_close(map);

	return result;
}

PG_FUNCTION_INFO_V1(pg_snakeoil_find_virus);
Datum
pg_snakeoil_find_virus(PG_FUNCTION_ARGS)
{
	bytea	   *input = PG_GETARG_BYTEA_P(0);

	const char *data;
	size_t data_size;
	struct scan_result result;

	/*
	 * Extract a pointer to the actual character data
	 */
	data = VARDATA_ANY(input);
	data_size = VARSIZE_ANY_EXHDR(input);

	result = scan_data(data, data_size);

	if (result.return_code == 0)
	{
		PG_RETURN_BOOL(false);
	} else
	{
		elog(NOTICE, "Virus found: %s", result.virus_name);
		PG_RETURN_BOOL(true);
	}
}

PG_FUNCTION_INFO_V1(pg_snakeoil_virus_name);
Datum
pg_snakeoil_virus_name(PG_FUNCTION_ARGS)
{
	bytea 	   *input = PG_GETARG_BYTEA_P(0);

	const char *data;
	size_t data_size;
	struct scan_result result;

	/*
	 * Extract a pointer to the actual character data
	 */
	data = VARDATA_ANY(input);
	data_size = VARSIZE_ANY_EXHDR(input);

	result = scan_data(data, data_size);

	if (result.return_code == 0)
	{
		PG_RETURN_NULL();
	} else
	{
		PG_RETURN_TEXT_P(cstring_to_text(result.virus_name));
	}
}