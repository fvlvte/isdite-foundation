#include "mem.h"

#include <sys/sysinfo.h>

#if ISDITE_PLATFORM == 0

int isdite_fdn_mem_getVirtualFree(void)
{
  struct sysinfo nfo;
  if(sysinfo(&nfo) == -1)
    return -1;

  return nfo.freeram;
}

#else

#error "Not implemented."

#endif
