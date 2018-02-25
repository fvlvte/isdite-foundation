#ifndef ISDITE_FOUNDATION_QTLS
#define ISDITE_FOUNDATION_QTLS

#define ISDITE_QTLS_INSUFFICIENT_DATA -9
#define ISDITE_QTLS_INVALID_DATA -10
#define ISDITE_QTLS_NOT_FINISHED_YET 1

struct isdite_fdn_qtls_context
{
  int tlsState;
  int sockFd;
  char buf[8192];
  int cstData;
  int pktTop;
  int dataSz;
};

void _isdite_fdn_qtls_initCert();
int isdite_fdn_qtls_processInput(struct isdite_fdn_qtls_context * ctx);

int isdite_fdn_qtls_recv(struct isdite_fdn_qtls_context * ctx, void * buffer, int sz);
int isdite_fdn_qtls_send(struct isdite_fdn_qtls_context * ctx, void * data, int sz);

#endif
