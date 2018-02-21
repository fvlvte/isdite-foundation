#include "log.h"
#include <stdio.h>
#include <time.h>
#include <xmmintrin.h>
#include <sys/time.h>
#include <unistd.h>
#include <string.h>

// [{SPEC}\s
// TRAC, INFO, WARN, ERRO, CRIT
const u_int64_t logDefinition[] = { 0x303220434152545B, 0x3032204F464E495B, 0x3032204E5241575B, 0x3032204F5252455B, 0x303220544952435B };

/* x8664 High performance log header formatter. */
/* We use SSE with precached buffer to archieve code as fast as possible. */
/* Year is hardcoded in form 201X, subject to change after 2019 :D */

void _isdite_fn_syslog_idtoa(int severity, void * dst)
{
  u_int64_t templated[] = { 0, 0x44442D4D4D2D5931, 0x733A6D6D3A484820, 0x00205D7575752E73 };
  templated[0] = logDefinition[severity];

  time_t t = time(NULL);
  struct tm tm = *localtime(&t);

  struct timeval tv;
  gettimeofday(&tv, NULL);

  tm.tm_mon += 1;
  tv.tv_usec /= 1000;

  ((char*)&templated[1])[1] = '0' + (tm.tm_year - 100) % 10;

  ((char*)&templated[1])[3] = '0' + tm.tm_mon / 10;
  ((char*)&templated[1])[4] = '0' + tm.tm_mon % 10;

  ((char*)&templated[1])[6] = '0' + tm.tm_mday / 10;
  ((char*)&templated[1])[7] = '0' + tm.tm_mday % 10;

  ((char*)&templated[2])[1] = '0' + tm.tm_hour / 10;
  ((char*)&templated[2])[2] = '0' + tm.tm_hour % 10;

  ((char*)&templated[2])[4] = '0' + tm.tm_min / 10;
  ((char*)&templated[2])[5] = '0' + tm.tm_min % 10;

  ((char*)&templated[2])[7] = '0' + tm.tm_sec / 10;
  ((char*)&templated[3])[0] = '0' + tm.tm_sec % 10;

  ((char*)&templated[3])[2] = '0' + tv.tv_usec / 100;
  tv.tv_usec = tv.tv_usec % 100;
  ((char*)&templated[3])[3] = '0' + tv.tv_usec / 10;
  ((char*)&templated[3])[4] = '0' + tv.tv_usec % 10;

  /* SSE ALIGNED MEMMOVE (movdqa) */

  *((__m128*)dst) = *((__m128*)templated);
  *((__m128*)dst+1) = *((__m128*)templated+1);
}

void _isdite_fn_syslog_makeLogHeader(int severity, char * data)
{
  char dtimeBuffer[160];
  _isdite_fn_syslog_idtoa(severity, dtimeBuffer);

  write(STDOUT_FILENO, dtimeBuffer, 8 * 4 - 1);
  write(STDOUT_FILENO, data, strlen(data));
  write(STDOUT_FILENO, "\n", 1);
}

void isdite_fn_syslog(int sev, const char * str)
{
  _isdite_fn_syslog_makeLogHeader(sev, (char*)str);
}

void isdite_fn_fsyslog(int sev, const char * fmt, ...)
{

}
