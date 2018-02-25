#include "qtls.h"
#include "def.h"

#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>


#define _ISDITE_QTLS_PREHELLO 0
#define _ISDITE_QTLS_ST_SHELLODONE 1
#define _ISDITE_QTLS_ST_EST 5

#define _ISDITE_QTLS_TLS_RECORD_HDR_LEN 5

struct _isdite_fdn_qtls_tlsRecordLayerHeader
{
  uint8_t type;
  uint16_t version;
  uint16_t length;
} ISDITE_PACKED;

struct _isdite_fdn_qtls_clientHello
{
  uint8_t identMagic;
  uint8_t align;
  uint16_t size;
  uint16_t version;
  uint8_t random[32];
  uint8_t sid_len;
} ISDITE_PACKED;

struct _isdite_fdn_qtls_serverHello
{
  struct _isdite_fdn_qtls_tlsRecordLayerHeader rlh;
  uint8_t identMagic; // 2
  uint8_t align;
  uint16_t len;
  uint16_t ver;
  uint8_t random[32];
  uint8_t sidLen; // 0
//  uint8_t siz[32];
  uint16_t cipherSuite;
  uint8_t comprMeth;
} ISDITE_PACKED;

struct _isdite_fdn_qtls_certificate
{
  uint8_t identMagic; // 2
  uint8_t align;
  uint16_t len;
  uint8_t align2;
  uint16_t certLen;
} ISDITE_PACKED;

struct _isdite_fdn_qtls_serverHelloDone
{
  uint8_t identMagic;
  uint8_t align;
  uint16_t len;
} ISDITE_PACKED;

char certBuf[4096];
int certSz = 0;

char keyBuf[4096];
int keySz = 0;

void _isdite_fdn_qtls_initCert()
{
  FILE * h = fopen("cert.bin", "rb");
  if(h == NULL)
  {
    printf("Failed to open cert data!\n");

    return;
  }

  certSz = fread(certBuf, 1, 4096, h);
  fclose(h);

  h = fopen("key.bin", "rb");
  keySz = fread(keyBuf, 1, 4096, h);

  fclose(h);
}

static inline int _isdite_fdn_qtls_handler_preHello(struct isdite_fdn_qtls_context * ctx, int rs)
{
  if(((struct _isdite_fdn_qtls_tlsRecordLayerHeader*)ctx->buf+ctx->pktTop)->type != 22)
    return ISDITE_QTLS_INVALID_DATA;

  struct _isdite_fdn_qtls_serverHello shello;

  shello.rlh.type = 22; // handshake
  shello.rlh.version = 0x0303;
  //shello.rlh.length = htons(sizeof(shello) - 5 + sizeof(struct _isdite_fdn_qtls_certificate) + certSz + sizeof(struct _isdite_fdn_qtls_serverHelloDone) + keySz);
  shello.rlh.length = htons(sizeof(shello) - 5 + sizeof(struct _isdite_fdn_qtls_serverHelloDone) + keySz);

  shello.identMagic = 2; // server hello
  shello.align = 0;
  shello.len = htons(sizeof(shello) - 5 - 4);
  shello.ver = 0x0303;
  shello.sidLen = 0;
  shello.cipherSuite = 0x2bc0; //
  shello.comprMeth = 0;

  for(int i = 0; i < 32;i++)
    shello.random[i] = i * 13 + i;

  send(ctx->sockFd, &shello, sizeof(shello), 0);

  printf("%d\n", sizeof(shello));

  struct _isdite_fdn_qtls_certificate cert;

  cert.identMagic = 11;//cert
  cert.align = 0;
  cert.len = htons(sizeof(cert) + certSz - 4);
  cert.align2 = 0;
  cert.certLen = htons(certSz);

  char fbaCert[4096];

  memcpy(fbaCert, &cert, sizeof(cert));
  memcpy(fbaCert+sizeof(cert), certBuf, certSz);
  //send(ctx->sockFd, fbaCert, sizeof(cert) + certSz, 0);

  send(ctx->sockFd, keyBuf, keySz, 0);

  struct _isdite_fdn_qtls_serverHelloDone  hdone;

  hdone.identMagic = 14;
  hdone.align = 0;
  hdone.len = 0;

  send(ctx->sockFd, &hdone, sizeof(hdone), 0);

  ctx->tlsState = _ISDITE_QTLS_ST_SHELLODONE;
  return ISDITE_QTLS_NOT_FINISHED_YET;
}

static inline int _isdite_fdn_qtls_isPacketComplete(struct isdite_fdn_qtls_context * ctx, int rs)
{
  return ((struct _isdite_fdn_qtls_tlsRecordLayerHeader*)ctx->buf+ctx->pktTop)->length >= rs ? 1 : 0;
}

int isdite_fdn_qtls_processInput(struct isdite_fdn_qtls_context * ctx)
{
  int realDataSz = ctx->dataSz - ctx->pktTop;
  if
  (
    realDataSz < sizeof(struct _isdite_fdn_qtls_tlsRecordLayerHeader) ||
    !_isdite_fdn_qtls_isPacketComplete(ctx, realDataSz)
  )
    return ISDITE_QTLS_INSUFFICIENT_DATA;

  int res = 0;
  switch(ctx->tlsState)
  {
    case _ISDITE_QTLS_PREHELLO:
    {
      res = _isdite_fdn_qtls_handler_preHello(ctx, realDataSz);
    }
    default:
    {
      break;
    }
  }

  if(realDataSz == ((struct _isdite_fdn_qtls_tlsRecordLayerHeader*)ctx->buf+ctx->pktTop)->length)
  {
    ctx->pktTop = 0;
    ctx->dataSz = 0;
  }
  else
    ctx->pktTop += ((struct _isdite_fdn_qtls_tlsRecordLayerHeader*)ctx->buf+ctx->pktTop)->length;

  return res;
}
