#ifndef ISDITE_FOUNDATION_PROCESS
#define ISDITE_FOUNDATION_PROCESS

#include <stdlib.h>
#include <isdite/foundation/log.h>

#define isResult int

#define isSuccess 0
#define isFailure 1

#define ISDITE_APP(x) int main(int a, char**b) \
{ \
  isdite_fdn_logInit();\
  int n = x(a, b);\
  isdite_fdn_logDestroy();\
  return n == isSuccess ? EXIT_SUCCESS : EXIT_FAILURE;\
}

int isdite_fl_getAvailableCpuCount(void);

#endif
