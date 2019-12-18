/*-------------------------------------------------------------------------
 *
 * pg_snakeoil.c
 * 		ClamAV antivirus integration, can check given data with ClamAV
 *
 * Copyright (c) 2018-2019, Alexander Sosna <alexander.sosna@credativ.de>
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include <ctype.h>

#include "utils/builtins.h"
#include "utils/guc.h"
#if PG_VERSION_NUM >= 100000
#include "utils/varlena.h"
#endif
#include "miscadmin.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <clamav.h>

/*
 * Set SNAKEOIL_DEBUG to 1 to enable additional debug output
 * This can produce overhead, only enable when needed
 */
#define SNAKEOIL_DEBUG 0

/* ClamAV defines */
#define NO_SIGNATURE_CHANGE 0
#define SIGNATURE_CHANGE 1


PG_MODULE_MAGIC;

void		reload_engine(void);
bool		update_signatures(void);
void		_PG_init(void);
void		_PG_fini(void);
struct scan_result scan_data(const char *data, size_t data_size);
Datum		pg_snakeoil_find_virus(PG_FUNCTION_ARGS);
Datum		pg_snakeoil_virus_name(PG_FUNCTION_ARGS);


/*
 * Holds the data of a virus scan
 */
struct scan_result
{
	int			return_code;
	const char *virus_name;
	long unsigned int scanned;
};

/*
 * Global variable to access the ClamAV engine
 */
struct cl_engine *engine = NULL;
char	   *signatureDir;
struct cl_stat signatureStat;


void
_PG_init()
{
	int			rv;

	/*
	 * Get different randomness for each process, recommended by ClamAV
	 */
	srand(getpid());

	elog(DEBUG1, "initializing the pg_snakeoil extension");

	rv = cl_init(CL_INIT_DEFAULT);

	if (CL_SUCCESS != rv)
	{
		elog(ERROR, "can't initialize libclamav: %s", cl_strerror(rv));
	}

	DefineCustomStringVariable("pg_snakeoil.signature_dir",
							   "ClamAV signature directory",
							   "ClamAV signature directory",
							   &signatureDir,
							   cl_retdbdir(),	/* ClamAV default signature directory */
#if PG_VERSION_NUM >= 90500
							   PGC_SU_BACKEND,	/* forbid changing directory after startup, restrict to superusers */
#else
							   PGC_SUSET,
#endif
							   0,	/* no flags */
							   NULL,	/* GucStringCheckHook check_hook, */
							   NULL,	/* GucStringAssignHook assign_hook, */
							   NULL);	/* GucShowHook show_hook) */

	EmitWarningsOnPlaceholders("pg_snakeoil");

	reload_engine();
}

void
_PG_fini()
{
	cl_engine_free(engine);
}

/*
 * Initialize the engine for further use, this takes some time!
 */
void
reload_engine()
{
	unsigned int signatureNum = 0;
	int			rv;

	elog(DEBUG1, "reloading ClamAV engine");

	if (engine != NULL)
	{
		elog(DEBUG1, "free existing ClamAV engine");
		cl_engine_free(engine);
	}

	engine = cl_engine_new();
	elog(DEBUG1, "using signature dir '%s'", signatureDir);

	/*
	 * Get the current state of the signatures
	 */
	memset(&signatureStat, 0, sizeof(struct cl_stat));
	cl_statinidir(signatureDir, &signatureStat);

	/*
	 * Load the signatures from signatureDir
	 */
	rv = cl_load(signatureDir, engine, &signatureNum, CL_DB_STDOPT);
	if (CL_SUCCESS != rv)
	{
		elog(ERROR, "failure loading ClamAV databases: %s", cl_strerror(rv));
	}

	elog(DEBUG1, "(cl_engine_compile)");
	rv = cl_engine_compile(engine);
	if (CL_SUCCESS != rv)
	{
		elog(ERROR, "cannot create ClamAV engine: %s", cl_strerror(rv));
		cl_engine_free(engine);
	}

	/*
	 * Only log start info if loaded via shared_preload_libraries, othervise
	 * we could spam the log.
	 */
	if (process_shared_preload_libraries_in_progress)
	{
		elog(LOG, "ClamAV engine started with signatureNum %d from %s",
			 signatureNum, signatureDir);
	}
}

bool
update_signatures()
{
	/*
	 * If signatures have changed, reload the engine
	 */
	if (cl_statchkdir(&signatureStat) == SIGNATURE_CHANGE)
	{
		elog(DEBUG1, "newer ClamAV signatures found");
		reload_engine();
		return true;
	}

	return false;
}

struct scan_result
scan_data(const char *data, size_t data_size)
{
	struct scan_result result = {0, "", 0};
	cl_fmap_t  *map;

	/*
	 * Open a map for scanning custom data, where the data is already in
	 * memory, either in the form of a buffer, a memory mapped file, etc. Note
	 * that the memory [start, start+len) must be the _entire_ file, you can't
	 * give it parts of a file and expect detection to work.
	 */
	map = cl_fmap_open_memory(data, data_size);

#ifdef SNAKEOIL_DEBUG
	elog(DEBUG4, "data_size: %lu", data_size);
	elog(DEBUG4, "data: %s", pnstrdup(data, data_size));
#endif

	/*
	 * Scan data
	 */
#if defined(CL_SCAN_STDOPT)		/* test for incompatible API change in 0.101 */
	/* version 0.100 */
	result.return_code = cl_scanmap_callback(map, &result.virus_name,
											 &result.scanned, engine, CL_SCAN_STDOPT, NULL);
#else
	{
		/* version 0.101 */
		static struct cl_scan_options cl_scan_options = {
			.parse = CL_SCAN_PARSE_ARCHIVE | CL_SCAN_PARSE_ELF
			| CL_SCAN_PARSE_PDF | CL_SCAN_PARSE_SWF | CL_SCAN_PARSE_HWP3
			| CL_SCAN_PARSE_XMLDOCS | CL_SCAN_PARSE_MAIL
			| CL_SCAN_PARSE_OLE2 | CL_SCAN_PARSE_HTML | CL_SCAN_PARSE_PE
		};

		result.return_code =
			cl_scanmap_callback(map,
								NULL,
								&result.virus_name,
								&result.scanned,
								engine,
								&cl_scan_options,
								NULL);
	}
#endif
	elog(DEBUG2, "cl_scanmap_callback returned: %d virusname: %s",
		 result.return_code, result.virus_name);

	/*
	 * Releases resources associated with the map, you should release any
	 * resources you hold only after (handles, maps) calling this function
	 */
	cl_fmap_close(map);
	return result;
}

PG_FUNCTION_INFO_V1(so_update_signatures);
Datum
so_update_signatures(PG_FUNCTION_ARGS)
{
	PG_RETURN_BOOL(update_signatures());
}

PG_FUNCTION_INFO_V1(so_is_infected);
Datum
so_is_infected(PG_FUNCTION_ARGS)
{
	bytea	   *input = PG_GETARG_BYTEA_P(0);

	const char *data;
	size_t		data_size;
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
	}
	else
	{
		elog(DEBUG1, "Virus found: %s", result.virus_name);
		PG_RETURN_BOOL(true);
	}
}

PG_FUNCTION_INFO_V1(so_virus_name);
Datum
so_virus_name(PG_FUNCTION_ARGS)
{
	bytea	   *input = PG_GETARG_BYTEA_P(0);

	const char *data;
	size_t		data_size;
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
	}
	else
	{
		PG_RETURN_TEXT_P(cstring_to_text(result.virus_name));
	}
}
