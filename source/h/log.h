#ifndef ISDITE_FOUNDATION_LOG
#define ISDITE_FOUNDATION_LOG

#define ISDITE_LOG_SEVERITY_TRAC 0
#define ISDITE_LOG_SEVERITY_INFO 1
#define ISDITE_LOG_SEVERITY_WARN 2
#define ISDITE_LOG_SEVERITY_ERRO 3
#define ISDITE_LOG_SEVERITY_CRIT 4

#define IL_TRAC 0,__FILE__,__LINE__
#define IL_INFO 1,__FILE__,__LINE__
#define IL_WARN 2,__FILE__,__LINE__
#define IL_ERRO 3,__FILE__,__LINE__
#define IL_CRIT 4,__FILE__,__LINE__

void isdite_fdn_logInit(void);
void isdite_fdn_logDestroy(void);
void isdite_fn_syslog(int sev, const char * str);
void isdite_fn_fsyslog(int sev, const char * fmt, ...);
void isdite_fdn_fsyslog(int sev, char * file, int ln, const char * fmt, ...);

#endif
