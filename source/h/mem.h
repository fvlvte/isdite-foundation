#ifndef ISDITE_FOUNDATION_MEM
#define ISDITE_FOUNDATION_MEM

#include <stdlib.h>

#define isdite_fdn_mem_dynAlloc(x) malloc(x)
#define isdite_fdn_mem_dynFree(x) free(x)

int isdite_fdn_mem_getVirtualFree(void);

#endif
