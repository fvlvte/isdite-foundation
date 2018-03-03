#ifndef ISDITE_FOUNDATION_MEM
#define ISDITE_FOUNDATION_MEM

#include <stdlib.h>

#define isdite_mem_heapCharge(x) calloc(1, x)
#define isdite_mem_heapCommit(x) malloc(x)
#define isdite_mem_heapFree(x) free(x)
#define isdite_mem_clear(x, y) memset(x, 0, y)

int isdite_fdn_mem_getVirtualFree(void);

#endif
