#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <clamav.h>

int main(int argc, char *argv[])
{
    if (CL_SUCCESS != cl_init(CL_INIT_DEFAULT)) {
        printf("cl_init failed\n");
        return 1;
    }

    struct cl_engine *engine = cl_engine_new();
    const char *dbDir = cl_retdbdir();
    int signatureNum = 0;
    printf("Use default db dir '%s'\n", dbDir);
    
    printf("(cl_load)\n");
    if (CL_SUCCESS != cl_load(dbDir, engine, &signatureNum, CL_DB_STDOPT)) {
        printf("cl_load failed\n");
        return 1;
    }

    printf("(cl_engine_compile)\n");
    if (CL_SUCCESS != cl_engine_compile(engine)) {
        printf("cl_engine_compile failed\n");
        return 1;
    }

    int ret = 0;
    int idx = 0;
    int scanRet = 0;
    const char *virusName = NULL;
    long unsigned int scanned = 0;
    cl_fmap_t *map;

    char data_to_scan[1024] = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

    /* Open a map for scanning custom data, where the data is already in memory,
    * either in the form of a buffer, a memory mapped file, etc.
    * Note that the memory [start, start+len) must be the _entire_ file,
    * you can't give it parts of a file and expect detection to work.
    */
    printf("Open a map for scanning custom data (cl_fmap_open_memory)\n");
    map = cl_fmap_open_memory(data_to_scan, sizeof(data_to_scan));

    /* Releases resources associated with the map, you should release any resources
    * you hold only after (handles, maps) calling this function */    
    printf("Releases resources associated with the map (cl_fmap_close)\n");
    cl_fmap_close(map);

    // Scan custom data
    printf("Scan custom data (cl_scanmap_callback)\n");
    ret = cl_scanmap_callback(map, &virusName, &scanned, engine, CL_SCAN_STDOPT, NULL);

    printf("ret: %d scanned: %lu virus: %s\n", ret, scanned, virusName);

    printf("(cl_engine_free)\n");
    cl_engine_free(engine);

    return ret;
}
