#ifndef ISDITE_FOUNDATION_QTLS
#define ISDITE_FOUNDATION_QTLS

#define ISDITE_QTLS_INSUFFICIENT_DATA -9
#define ISDITE_QTLS_INVALID_DATA -10
#define ISDITE_QTLS_NOT_FINISHED_YET 1
#define ISDITE_QTLS_DATA_READY 12

#define _ISDITE_QTLS_HASH_CONTEXT_SIZE 272
#define _ISDITE_QTLS_GCM_CONTEXT_SIZE 69904

#include <stdint.h>

struct isdite_fdn_qtls_context
{
  int iState;
  int iFlag;
  int iNonce;

  union {
    uint8_t early_handshake_data[64 + 48 + 40]; // Client/server random, master secret, keys, iv
    uint8_t local_ctx[_ISDITE_QTLS_GCM_CONTEXT_SIZE];
  } lctx;
  uint8_t remote_ctx[_ISDITE_QTLS_GCM_CONTEXT_SIZE];

  uint8_t msg_hash[_ISDITE_QTLS_HASH_CONTEXT_SIZE];

  uint8_t clientIv[12];
  uint8_t serverIv[12];

  void * cert;

  char conDataBuffer[4096];
  int conDataSz;
};

#define IS_QTLS_SERVER_CERT void*

#define IS_QTLS_CERT_RSA4096_WITH_SHA512 0
#define IS_QTLS_CERT_MAX 0

int is_qtls_loadCertificateFromFile
(
  int iType,
  const char * pCertPath,
  const char * pPrivKeyPath,
  IS_QTLS_SERVER_CERT * pInstance
);

int isdite_qtls_processInput(void * sdesc, void * desc, struct isdite_fdn_qtls_context * ctx, uint8_t * input, int inputSize);
void isdite_fdn_qtls_sendData(struct isdite_fdn_qtls_context * pContext, void * pData, int iDataSz, void * pServerDesc, void * pClientDesc);
int isdite_fdn_qtls_recv(struct isdite_fdn_qtls_context * ctx, void * buffer, int sz);
int isdite_fdn_qtls_send(struct isdite_fdn_qtls_context * ctx, void * data, int sz);

#endif
