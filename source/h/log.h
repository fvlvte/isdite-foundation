#ifndef ISDITE_FOUNDATION_LOG
#define ISDITE_FOUNDATION_LOG

#define ISDITE_LOG_SEVERITY_TRAC 0
#define ISDITE_LOG_SEVERITY_INFO 1
#define ISDITE_LOG_SEVERITY_WARN 2
#define ISDITE_LOG_SEVERITY_ERRO 3
#define ISIDTE_LOG_SEVERITY_CRIT 4

void isdite_fn_syslog(int sev, const char * str);
void isdite_fn_fsyslog(const char * fmt, ...);

#endif
