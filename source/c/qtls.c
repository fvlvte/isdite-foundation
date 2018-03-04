#include "qtls.h"
#include "def.h"
#include "log.h"

#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>

#include "ext/tomcrypt.c"

extern void _isdite_tcpServer_sendPacketDropOnError(void *, void *, void *, int);

#define _ISDITE_QTLS_PREHELLO 0
#define _ISDITE_QTLS_ST_SHELLODONE 1
#define _ISDITR_QTLS_ST_DATA_READY 2
#define _ISDITE_QTLS_ST_EST 5

#define _ISDITE_QTLS_TLS_RECORD_HDR_LEN 5

#define _ISDITE_QTLS_GOT_KEY 0x1
#define _ISDITE_QTLS_CIPHER_SPEC 0x10

rsa_key key;
const struct ltc_hash_descriptor * hash_desc = &sha512_desc;
const struct ltc_hash_descriptor * hash_desc256 = &sha256_desc;
int hash_idx;
int hash_idx256;
int prng_idx;

struct ECCCurveParameters {
    int size;
    int iana;
    const char *name;
    const char *P;
    const char *A;
    const char *B;
    const char *Gx;
    const char *Gy;
    const char *order;
    ltc_ecc_set_type dp;
};

void init_curve(struct ECCCurveParameters *curve) {
    curve->dp.size = curve->size;
    curve->dp.name = (char *)curve->name;
    curve->dp.B = (char *)curve->B;
    curve->dp.prime = (char *)curve->P;
    curve->dp.Gx = (char *)curve->Gx;
    curve->dp.Gy = (char *)curve->Gy;
    curve->dp.order = (char *)curve->order;
}

static struct ECCCurveParameters secp256r1 = {
    32,
    23,
    "secp256r1",
    "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", // P
    "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", // A
    "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", // B
    "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", // Gx
    "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5", // Gy
    "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"  // order (n)
};

char certBuf[4096];
int certSz = 0;

char keyBuf[4096];
int keySz = 0;

ecc_key ek;
char eccKey[4096];
int ecKeySz = 0;

char eccExpKey[4096];
long eccExpKeySz = 0;

#include "qtls_helper.in"

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

  // priv key

  char privKey[4096];

  h = fopen("priv.der", "r");
  int keySz = fread(privKey, 1, 4096, h);

  fclose(h);

  ltc_mp = ltm_desc;

  const int padding = LTC_LTC_PKCS_1_V1_5;
  init_curve(&secp256r1);
  prng_idx = register_prng(&sprng_desc);
  hash_idx = register_hash(&sha512_desc);
  hash_idx256 = register_hash(&sha256_desc);
  register_cipher(&aes_desc);

  void *prime, *b, *t1, *t2;
  mp_init_multi(&prime, &b, &t1, &t2, NULL);

  ecc_make_key_ex(NULL, find_prng("sprng"), &ek, &secp256r1.dp);

  eccExpKeySz = 4096;
  ecc_ansi_x963_export(&ek, eccExpKey, &eccExpKeySz);

	int err = rsa_import(privKey, keySz, &key);
}

// REGION: HANDLERS

static inline int _isdite_qtls_handler_clientHello
(
  struct isdite_fdn_qtls_context * pContext,
  uint8_t * pInput,
  int iRealSize,
  void * pServerDesc,
  void * pClientDesc
)
{
	hash_desc256->init((hash_state*)pContext->msg_hash);

	hash_desc256->process
  (
    (hash_state*)pContext->msg_hash,
    pInput,
    iRealSize
  );

  pContext->iNonce = 1;

  uint8_t aResponseData[4096];

  /* RECORD LAYER HEADER */

  aResponseData[0] = 0x16; // Handshake
  (*(uint16_t*)(aResponseData+1)) = 0x0303; // TLS 1.2
  (*(uint16_t*)(aResponseData+3)) = htons(645 + certSz);

  /* SERVER HELLO */

  aResponseData[5] = 0x02; // Server hello.
  aResponseData[6] = 0x00; // Length align.
  (*(uint16_t*)(aResponseData+7)) = htons(38);

  (*(uint16_t*)(aResponseData+9)) = 0x0303; // TLS 1.2

  for(int i = 0; i < 32;i++) // Server random.
    aResponseData[11 + i] = i * 13 + i;

  aResponseData[43] = 0x00; // Session ID length.

  // Cipher suite (TLC_ECDHE_RSA_WITH_AES_128_GCM_SHA256).
  (*(uint16_t*)(aResponseData+44)) = 0x2FC0;

  aResponseData[46] = 0x00; // Compression methods.

  /* CERTIFICATE */

  aResponseData[47] = 0x0B; // Certificate.
  aResponseData[48] = 0x00; // Align.
  (*(uint16_t*)(aResponseData+49)) = htons(6 + certSz); // Size.
  aResponseData[51] = 0x00; // Align.
  (*(uint16_t*)(aResponseData+52)) = htons(certSz + 3);
  aResponseData[54] = 0x00; // Align.
  (*(uint16_t*)(aResponseData+55)) = htons(certSz);
  memcpy(aResponseData + 57, certBuf, certSz);

  /* SERVER KEY EXCHANGE */

  aResponseData[57 + certSz] = 0x0C; // Server key exchange.
  aResponseData[58 + certSz] = 0x00; // Align.
  (*(uint16_t*)(aResponseData+59 + certSz)) = htons(585);

  aResponseData[61 + certSz] = 0x03; // Curve type - named curve.
  (*(uint16_t*)(aResponseData+62 + certSz)) = 0x1700; // Algorithm - secp256r1.
  aResponseData[64 + certSz] = 65; // Public key length.
  memcpy(aResponseData + 65 + certSz, eccExpKey, 65); // Public key.
  // Signing algorithm - rsa pkcs1 sha512.
  (*(uint16_t*)(aResponseData+130 + certSz)) = 0x0106;
  (*(uint16_t*)(aResponseData+132 + certSz)) = htons(512); // Signature length.

  uint8_t aToSign[133];
  memcpy(aToSign, pInput + 6, 32);
  memcpy(aToSign+32, aResponseData+11, 32);
  memcpy(aToSign+64, aResponseData + 61 + certSz, 69);

  _isdite_fdn_qtls_signSha512RSA(aToSign, 133, aResponseData + 134 + certSz);

  /* SERVER HELLO DONE */
  aResponseData[646 + certSz] = 0x0E; // Server hello done.
  aResponseData[647 + certSz] = 0x00; // Align.
  (*(uint16_t*)(aResponseData+ 648 + certSz)) = 0x00; // Length.

  /* INTERNAL LOGIC */

  hash_desc256->process
  (
    (hash_state*)pContext->msg_hash,
    aResponseData + 5,
    645 + certSz
  );

  memcpy(pContext->lctx.early_handshake_data, pInput + 6, 32);
  memcpy(pContext->lctx.early_handshake_data + 32, aResponseData + 11, 32);

  pContext->iState = _ISDITE_QTLS_ST_SHELLODONE;

  _isdite_tcpServer_sendPacketDropOnError
  (
    pServerDesc,
    pClientDesc,
    aResponseData,
    650 + certSz
  );
  return ISDITE_QTLS_NOT_FINISHED_YET;
}

static inline int _isdite_fdn_qtls_handler_clientKeyExchange
(
  struct isdite_fdn_qtls_context * pContext,
  uint8_t * pInput,
  int iRealSize,
  void * pServerDesc,
  void * pClientDesc
)
{
  // Update handshake hash.
  hash_desc256->process
  (
    (hash_state*)pContext->msg_hash,
    pInput,
    iRealSize
  );

  ecc_key sRemoteKey;
  __private_tls_ecc_import_key
  (
    ek.k,
    256,
    pInput + 5, // Key offset in packet.
    65,
    &sRemoteKey,
    &secp256r1.dp
  );

  uint8_t aSharedSecret[128];
  unsigned long outSz = 128;
  ecc_shared_secret(&ek, &sRemoteKey, aSharedSecret, &outSz);

  __private_tls_prf
  (
    pContext->lctx.early_handshake_data+64,
    48,
    aSharedSecret,
    outSz,
    "master secret",
    13,
    pContext->lctx.early_handshake_data,
    32,
    pContext->lctx.early_handshake_data+32,
    32
  );

  __private_tls_prf
  (
    pContext->lctx.early_handshake_data+64+48,
    40,
    pContext->lctx.early_handshake_data+64,
    48,
    "key expansion",
    13,
    pContext->lctx.early_handshake_data+32,
    32,
    pContext->lctx.early_handshake_data,
    32
  );

  memcpy(pContext->clientIv, pContext->lctx.early_handshake_data+64+48+32, 4);
  memcpy(pContext->serverIv, pContext->lctx.early_handshake_data+64+48+36, 4);

  pContext->iFlag |= _ISDITE_QTLS_GOT_KEY;
  return ISDITE_QTLS_NOT_FINISHED_YET;
}

static inline int _isdite_fdn_qtls_handler_changeCipherSpec
(
  struct isdite_fdn_qtls_context * pContext,
  uint8_t * pInput,
  int iRealSize,
  void * pServerDesc,
  void * pClientDesc
)
{
  if(!(pContext->iFlag & _ISDITE_QTLS_GOT_KEY))
    return ISDITE_QTLS_INVALID_DATA;

  pContext->iFlag |= _ISDITE_QTLS_CIPHER_SPEC;
  return ISDITE_QTLS_NOT_FINISHED_YET;
}

static inline int _isdite_fdn_qtls_handler_clientFinished
(
  struct isdite_fdn_qtls_context * pContext,
  uint8_t * pInput,
  int iRealSize,
  void * pServerDesc,
  void * pClientDesc
)
{
  uint8_t aData[80];
  memcpy(aData, pContext->lctx.early_handshake_data+64, 80);

  gcm_init
  (
    (gcm_state*)pContext->remote_ctx,
    find_cipher("aes"),
    aData+48,
    16
  );

  gcm_init
  (
    (gcm_state*)pContext->lctx.local_ctx,
    find_cipher("aes"),
    aData+48+16,
    16
  );

  uint8_t aPlainText[16];

  uint8_t aAAD[13];
  memset(aAAD, 0, 13);
  aAAD[8] = 22;
  aAAD[9] = 3;
  aAAD[10] = 3;
  aAAD[11] = 0;
  aAAD[12] = 16;

  memset(pContext->clientIv+4, 0, 8);
  gcm_add_iv((gcm_state*)pContext->remote_ctx, pContext->clientIv, 12);
  gcm_add_aad((gcm_state*)pContext->remote_ctx, aAAD, 13);
  gcm_process
  (
    (gcm_state*)pContext->remote_ctx,
    aPlainText,
    16,
    pInput + 8,
    GCM_DECRYPT
  );

  hash_desc256->process((hash_state*)pContext->msg_hash, aPlainText, 16);

  uint8_t aHash[32];
  hash_desc256->done((hash_state*)pContext->msg_hash, aHash);

  uint8_t aResponsePlainText[] =
    {
      0x14, 0x00, 0x00, 0x0C,
      0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00
    };

  __private_tls_prf
  (
    aResponsePlainText + 4,
    12,
    aData,
    48,
    "server finished",
    strlen("server finished"),
    aHash,
    32,
    NULL,
    0
  );

  memset(pContext->serverIv+4, 0, 8);
  gcm_add_iv((gcm_state*)pContext->lctx.local_ctx, pContext->serverIv, 12);
  gcm_add_aad((gcm_state*)pContext->lctx.local_ctx, aAAD, 13);

  uint8_t aResponseData[1024];

  // Change cipher spec.
  aResponseData[0] = 0x14; // Change cipher spec.
  (*(uint16_t*)(aResponseData+1)) = 0x0303; // TLS Version (1.2).
  (*(uint16_t*)(aResponseData+3)) = htons(1); // Length.
  aResponseData[5] = 1; // Value (always 1).

  /* SERVER DONE */

  aResponseData[6] = 0x16; // Handshake.
  (*(uint16_t*)(aResponseData+7)) = 0x0303; // TLS Version (1.2).
  (*(uint16_t*)(aResponseData+9)) = htons(40); // Length.

  memset(aResponseData+11, 0, 8); // Nonce, in handshake always 0.

  gcm_process
  (
    (gcm_state*)pContext->lctx.local_ctx,
    aResponsePlainText,
    16,
    aResponseData+19,
    GCM_ENCRYPT
  );

  unsigned long ulTagLen = 16;
  gcm_done((gcm_state*)pContext->lctx.local_ctx, aResponseData+35, &ulTagLen);

  pContext->iState = _ISDITR_QTLS_ST_DATA_READY;

  _isdite_tcpServer_sendPacketDropOnError
  (
    pServerDesc,
    pClientDesc,
    aResponseData,
    51
  );

  return ISDITE_QTLS_NOT_FINISHED_YET;
}

static inline int _isdite_fdn_qtls_handler_applicationData
(
  struct isdite_fdn_qtls_context * pContext,
  uint8_t * pInput,
  int iRealSize,
  void * pServerDesc,
  void * pClientDesc
)
{
  uint8_t aAAD[13];
  memset(aAAD, 0, 13);
  aAAD[8] = 22;
  aAAD[9] = 3;
  aAAD[10] = 3;
  aAAD[11] = 0;
  aAAD[12] = 16;

  unsigned int uiPlainTextSize = iRealSize - 24;

  uint8_t * aResultBuffer[8192];
  gcm_reset((gcm_state*)pContext->remote_ctx);

  memcpy(pContext->clientIv+4, pInput, 8);
  memcpy(aAAD, pInput, 8);

  gcm_add_iv((gcm_state*)pContext->remote_ctx, pContext->clientIv, 12);
  gcm_add_aad((gcm_state*)pContext->remote_ctx, aAAD, 13);
  gcm_process
  (
    (gcm_state*)pContext->remote_ctx,
    pContext->conDataBuffer,
    uiPlainTextSize,
    pInput + 8,
    GCM_DECRYPT
  );

  pContext->conDataSz = uiPlainTextSize;

  return ISDITE_QTLS_DATA_READY;
}

void isdite_fdn_qtls_sendData(struct isdite_fdn_qtls_context * pContext, void * pData, int iDataSz, void * pServerDesc, void * pClientDesc)
{
  uint8_t aOutputBuffer[8192];

  aOutputBuffer[0] = 0x17; // RL: Application data.
  *((uint16_t*)(aOutputBuffer+1))= 0x0303;
  *((uint16_t*)(aOutputBuffer+3))= htons(24 + iDataSz);
  *((uint32_t*)(aOutputBuffer+5)) = 0;
  *((uint32_t*)(aOutputBuffer+9)) = htonl(pContext->iNonce);

  uint8_t aAAD[13];
  memset(aAAD, 0, 13);
  aAAD[7] = pContext->iNonce++;
  aAAD[8] = 23;
  aAAD[9] = 3;
  aAAD[10] = 3;
  aAAD[12] = iDataSz;

  memcpy(pContext->serverIv+4, aAAD, 8);
  gcm_reset((gcm_state*)pContext->lctx.local_ctx);
  gcm_add_iv((gcm_state*)pContext->lctx.local_ctx, pContext->serverIv, 12);
  gcm_add_aad((gcm_state*)pContext->lctx.local_ctx, aAAD, 13);
  gcm_process
  (
    (gcm_state*)pContext->lctx.local_ctx,
    pData,
    iDataSz,
    aOutputBuffer + 5 + 8,
    GCM_ENCRYPT
  );

  unsigned long ulTagLen = 16;
  gcm_done((gcm_state*)pContext->lctx.local_ctx, aOutputBuffer + 5 + 8 + iDataSz, &ulTagLen);

  _isdite_tcpServer_sendPacketDropOnError
  (
    pServerDesc,
    pClientDesc,
    aOutputBuffer,
    24 + iDataSz + 5
  );
}

int isdite_qtls_processInput(void * sdesc, void * desc, struct isdite_fdn_qtls_context * ctx, uint8_t * input, int inputSize)
{
  if(inputSize < 5)
    return ISDITE_QTLS_INVALID_DATA;
  else
  {
    uint16_t ui16RecordLayerSize = ntohs(*(uint16_t*)(input+3)) + 5;
    if(ui16RecordLayerSize > 8192)
      return ISDITE_QTLS_INVALID_DATA;

    if(inputSize >= ui16RecordLayerSize)
    {
      int res = 0;

      if(ctx->iState == _ISDITR_QTLS_ST_DATA_READY)
      {
        if(input[0] != 21)
          res = _isdite_fdn_qtls_handler_applicationData(ctx, input + 5, ui16RecordLayerSize - 5, sdesc, desc);
        else
          res = ISDITE_QTLS_INSUFFICIENT_DATA;
      }
      else if(ctx->iState == _ISDITE_QTLS_ST_SHELLODONE)
      {
        if(ctx->iFlag & _ISDITE_QTLS_GOT_KEY && ctx->iFlag & _ISDITE_QTLS_CIPHER_SPEC)
          res = _isdite_fdn_qtls_handler_clientFinished(ctx, input + 5, ui16RecordLayerSize - 5, sdesc, desc);
        else if(ctx->iFlag & _ISDITE_QTLS_GOT_KEY)
          res = _isdite_fdn_qtls_handler_changeCipherSpec(ctx, input + 5, ui16RecordLayerSize - 5, sdesc, desc);
        else
          res = _isdite_fdn_qtls_handler_clientKeyExchange(ctx, input + 5, ui16RecordLayerSize - 5, sdesc, desc);
      }
      else
        res = _isdite_qtls_handler_clientHello(ctx, input + 5, ui16RecordLayerSize - 5, sdesc, desc);


      if(res == ISDITE_QTLS_INVALID_DATA)
        return res;

      if(ui16RecordLayerSize == inputSize)
        return res;
      else
        return isdite_qtls_processInput
        (
          sdesc,
          desc,
          ctx,
          input+ui16RecordLayerSize,
          inputSize - ui16RecordLayerSize
        );
    }
    else
      return ISDITE_QTLS_INVALID_DATA;
  }
}
