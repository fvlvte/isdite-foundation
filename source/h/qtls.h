#ifndef ISDITE_FOUNDATION_QTLS
#define ISDITE_FOUNDATION_QTLS

#define ISDITE_QTLS_INSUFFICIENT_DATA -9
#define ISDITE_QTLS_INVALID_DATA -10
#define ISDITE_QTLS_NOT_FINISHED_YET 1
#define ISDITE_QTLS_DATA_READY 0

#include "ext/aes.h"

struct isdite_fdn_qtls_context
{
  int tlsState;
  int sockFd;
  void * dataPtr;
  char cliRand[32];
  char srvRand[32];
  char keyExpansion[192];
  char clientWriteKey[16];
  char serverWriteKey[16];
  char clientIv[12];
  char serverIv[12];

  void * local_ctx;
  void * remote_ctx;
  char buf[8192];
  char cliKey[65];
  int iFlag;
  char shared[128];
  char masterSecret[48];
  void * msg_hash;
  struct AES_ctx aesCtx;
  unsigned long sharedSz;
  int cstData;
  int pktTop;
  int dataSz;
  int nonce;
  char conDataBuffer[4096];
  int conDataSz;
};

void _isdite_fdn_qtls_initCert();
int isdite_fdn_qtls_processInput(struct isdite_fdn_qtls_context * ctx);
void isdite_fdn_qtls_sendData(struct isdite_fdn_qtls_context * ctx, void * data, int dataSz);

int isdite_fdn_qtls_recv(struct isdite_fdn_qtls_context * ctx, void * buffer, int sz);
int isdite_fdn_qtls_send(struct isdite_fdn_qtls_context * ctx, void * data, int sz);

#endif
