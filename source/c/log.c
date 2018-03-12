#include "log.h"
#include <stdio.h>
#include <time.h>
#include <xmmintrin.h>
#include <sys/time.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <pthread.h>

pthread_spinlock_t lock;

void isdite_fdn_logInit(void)
{
  pthread_spin_init(&lock, PTHREAD_PROCESS_PRIVATE);
}

void isdite_fdn_logDestroy(void)
{
  pthread_spin_destroy(&lock);
}

static char fSyslogBuff[4096];
static char fSyslogBuffEx[4096];

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

void _isdite_fdn_syslog_makeLog(int severity, char * data, int ex)
{
  char dtimeBuffer[160];
  _isdite_fn_syslog_idtoa(severity, dtimeBuffer);

  printf("%s", dtimeBuffer);
  printf("%s", data);
  if(ex == 0)
    printf("\n");
}

void isdite_fn_syslog(int sev, const char * str)
{
  pthread_spin_lock(&lock);

  _isdite_fdn_syslog_makeLog(sev, (char*)str, 0);

  pthread_spin_unlock(&lock);
}

void isdite_fn_fsyslog(int sev, const char * fmt, ...)
{
  pthread_spin_lock(&lock);

  va_list argptr;
  va_start(argptr, fmt);
  vsprintf(fSyslogBuff, fmt, argptr);
  va_end(argptr);

  _isdite_fdn_syslog_makeLog(sev, fSyslogBuff, 0);

  pthread_spin_unlock(&lock);
}

void isdite_fdn_fsyslog(int sev, char * file, int ln, const char * fmt, ...)
{
  pthread_spin_lock(&lock);

  va_list argptr;
  va_start(argptr, fmt);
  vsprintf(fSyslogBuff, fmt, argptr);
  va_end(argptr);

  sprintf(fSyslogBuffEx, "(%s @ %d) %s\n", file, ln, fSyslogBuff);

  _isdite_fdn_syslog_makeLog(sev, fSyslogBuffEx, 1);

  pthread_spin_unlock(&lock);
}
