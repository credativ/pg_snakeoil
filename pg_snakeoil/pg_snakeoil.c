/*
 * pg_snakeoil.c
 * Alexander Sosna <alexander.sosna@credativ.de>
 *
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

// Global variable to access the clamav engine
struct cl_engine *engine;

//extern void _PG_init(void);
//extern void _PG_fini(void);

void _PG_init(void)
{
	if (CL_SUCCESS != cl_init(CL_INIT_DEFAULT))
	{
		elog(NOTICE, "cl_init failed");
		//return 1;
	}

	engine = cl_engine_new();
	const char *dbDir = cl_retdbdir();
	int signatureNum = 0;
	elog(NOTICE, "Use default db dir '%s'", dbDir);

	elog(NOTICE, "(cl_load)");
	if (CL_SUCCESS != cl_load(dbDir, engine, &signatureNum, CL_DB_STDOPT))
	{
		elog(NOTICE, "cl_load failed");
		//return 1;
	}

	elog(NOTICE, "(cl_engine_compile)");
	if (CL_SUCCESS != cl_engine_compile(engine))
	{
		elog(NOTICE, "cl_engine_compile failed");
		//return 1;
	}
	elog(NOTICE, "_PG_init() done");
	printf("_PG_init() done");
}

void _PG_fini(void)
{
	cl_engine_free(engine);
}


PG_FUNCTION_INFO_V1(pg_snakeoil_scan);
Datum
pg_snakeoil_scan(PG_FUNCTION_ARGS)
{
	text	   *input = PG_GETARG_BYTEA_P(0);

	const char *data;
	size_t data_size;

	/* Extract a pointer to the actual character data */
	data = VARDATA_ANY(input);
	data_size = VARSIZE_ANY_EXHDR(input);

	int ret = 0;
	int idx = 0;
	int scanRet = 0;
	const char *virusName = NULL;
	long unsigned int scanned = 0;
	cl_fmap_t *map;

	/*
	* Open a map for scanning custom data, where the data is already in memory,
	* either in the form of a buffer, a memory mapped file, etc.
	* Note that the memory [start, start+len) must be the _entire_ file,
	* you can't give it parts of a file and expect detection to work.
	*/
	map = cl_fmap_open_memory(data, data_size);
	elog(NOTICE, "sizeof: %d", data_size);

	{
		char *output_data = palloc(data_size+1);
		strncpy(output_data, data, data_size);
		elog(NOTICE, "data: %s", output_data); // TODO: FIX OUTPUT
	}

	// Scan custom data
	elog(NOTICE, "cl_scanmap_callback");
	ret = cl_scanmap_callback(map, &virusName, &scanned, engine, CL_SCAN_STDOPT, NULL);

	/*
	* Releases resources associated with the map, you should release any resources
	* you hold only after (handles, maps) calling this function
	*/
	elog(NOTICE, "datcl_fmap_close");
	cl_fmap_close(map);


	elog(NOTICE, "cl_scanmap_callback returned: %d virusname: %s", ret, virusName);
	if (ret == 0)
	{
		PG_RETURN_BOOL(true);
	} else
	{
		PG_RETURN_BOOL(false);
	}
}