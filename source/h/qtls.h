#ifndef ISDITE_FOUNDATION_QTLS
#define ISDITE_FOUNDATION_QTLS

#define ISDITE_QTLS_INSUFFICIENT_DATA -9
#define ISDITE_QTLS_INVALID_DATA -10
#define ISDITE_QTLS_NOT_FINISHED_YET 1

#include "ext/aes.h"

struct isdite_fdn_qtls_context
{
  int tlsState;
  int sockFd;
  void * dataPtr;
  char buf[8192];
  char cliKey[65];
  int iFlag;
  char shared[512];
  void * msg_hash;
  struct AES_ctx aesCtx;
  unsigned long sharedSz;
  int cstData;
  int pktTop;
  int dataSz;
};

void _isdite_fdn_qtls_initCert();
int isdite_fdn_qtls_processInput(struct isdite_fdn_qtls_context * ctx);

int isdite_fdn_qtls_recv(struct isdite_fdn_qtls_context * ctx, void * buffer, int sz);
int isdite_fdn_qtls_send(struct isdite_fdn_qtls_context * ctx, void * data, int sz);

#endif
