#include <unistd.h>

int isdite_fl_getAvailableCpuCount(void)
{
  return sysconf(_SC_NPROCESSORS_ONLN);
}
