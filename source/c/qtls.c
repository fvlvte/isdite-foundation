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
  uint16_t ver;
  uint8_t random[32];
  uint8_t sidLen;
  uint16_t cipherSuite;
  uint8_t comprMeth;
} ISDITE_PACKED;

struct _isdite_fdn_qtls_certificate
{
  uint8_t align2;
  uint16_t certsLen;
  uint8_t align3;
  uint16_t certLen;
} ISDITE_PACKED;

struct _isdite_fdn_qtls_changeCipherSpec
{
  uint8_t identMagic; // 20
  uint16_t version;
  uint16_t len; // 1
  uint8_t data; // 1
} ISDITE_PACKED;

struct _isdite_fdn_qtls_serverFinished
{
  uint8_t identMagic; // 20
  uint16_t version;
  uint16_t len; // 1
  uint8_t data[40]; // 1
} ISDITE_PACKED;

struct _isdite_fdn_qtls_serverKeyExchange
{
  uint8_t identMagic; // 12
  uint8_t align;
  uint16_t len;
  uint8_t curveType; // 3
  uint16_t curveAlg; // 0x1700 secp256r1
  uint8_t pubKeyLen; // 65
  uint8_t pubKey[65];
  uint16_t sigAlg; // rsa pkcs1 sha512 0x0106
  uint16_t sigLen; // 256
  uint8_t sig[512];
} ISDITE_PACKED;

struct _isdite_fdn_qtls_serverHelloDone
{
  uint8_t identMagic;
  uint8_t align;
  uint16_t len;
} ISDITE_PACKED;

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

static int __private_tls_is_point(ecc_key *key) {
    void *prime, *b, *t1, *t2;
    int  err;

    if ((err = mp_init_multi(&prime, &b, &t1, &t2, NULL)) != CRYPT_OK) {
        return err;
    }

    /* load prime and b */
    if ((err = mp_read_radix(prime, key->dp->prime, 16)) != CRYPT_OK) {
        goto error;
    }
    if ((err = mp_read_radix(b, key->dp->B, 16)) != CRYPT_OK) {
        goto error;
    }

    /* compute y^2 */
    if ((err = mp_sqr(key->pubkey.y, t1)) != CRYPT_OK) {
        goto error;
    }

    /* compute x^3 */
    if ((err = mp_sqr(key->pubkey.x, t2)) != CRYPT_OK) {
        goto error;
    }
    if ((err = mp_mod(t2, prime, t2)) != CRYPT_OK) {
        goto error;
    }
    if ((err = mp_mul(key->pubkey.x, t2, t2)) != CRYPT_OK) {
        goto error;
    }

    /* compute y^2 - x^3 */
    if ((err = mp_sub(t1, t2, t1)) != CRYPT_OK) {
        goto error;
    }

    /* compute y^2 - x^3 + 3x */
    if ((err = mp_add(t1, key->pubkey.x, t1)) != CRYPT_OK) {
        goto error;
    }
    if ((err = mp_add(t1, key->pubkey.x, t1)) != CRYPT_OK) {
        goto error;
    }
    if ((err = mp_add(t1, key->pubkey.x, t1)) != CRYPT_OK) {
        goto error;
    }
    if ((err = mp_mod(t1, prime, t1)) != CRYPT_OK) {
        goto error;
    }
    while (mp_cmp_d(t1, 0) == LTC_MP_LT) {
        if ((err = mp_add(t1, prime, t1)) != CRYPT_OK) {
            goto error;
        }
    }
    while (mp_cmp(t1, prime) != LTC_MP_LT) {
        if ((err = mp_sub(t1, prime, t1)) != CRYPT_OK) {
            goto error;
        }
    }

    /* compare to b */
    if (mp_cmp(t1, b) != LTC_MP_EQ) {
        err = CRYPT_INVALID_PACKET;
    } else {
        err = CRYPT_OK;
    }

error:
    mp_clear_multi(prime, b, t1, t2, NULL);
    return err;
}

int __private_tls_ecc_import_key(const unsigned char *private_key, int private_len, const unsigned char *public_key, int public_len, ecc_key *key, const ltc_ecc_set_type *dp) {
    int           err;

    if ((!key) || (!ltc_mp.name))
        return CRYPT_MEM;

    key->type = PK_PRIVATE;

    if (mp_init_multi(&key->pubkey.x, &key->pubkey.y, &key->pubkey.z, &key->k, NULL) != CRYPT_OK)
        return CRYPT_MEM;

    if ((public_len) && (!public_key[0])) {
        public_key++;
        public_len--;
    }
    if ((err = mp_read_unsigned_bin(key->pubkey.x, (unsigned char *)public_key + 1, (public_len - 1) >> 1)) != CRYPT_OK) {
        mp_clear_multi(key->pubkey.x, key->pubkey.y, key->pubkey.z, key->k, NULL);
        return err;
    }

    if ((err = mp_read_unsigned_bin(key->pubkey.y, (unsigned char *)public_key + 1 + ((public_len - 1) >> 1), (public_len - 1) >> 1)) != CRYPT_OK) {
        mp_clear_multi(key->pubkey.x, key->pubkey.y, key->pubkey.z, key->k, NULL);
        return err;
    }

    if ((err = mp_read_unsigned_bin(key->k, (unsigned char *)private_key, private_len)) != CRYPT_OK) {
        mp_clear_multi(key->pubkey.x, key->pubkey.y, key->pubkey.z, key->k, NULL);
        return err;
    }

    key->idx = -1;
    key->dp  = dp;

    /* set z */
    if ((err = mp_set(key->pubkey.z, 1)) != CRYPT_OK) {
        mp_clear_multi(key->pubkey.x, key->pubkey.y, key->pubkey.z, key->k, NULL);
        return err;
    }

    /* is it a point on the curve?  */
    if ((err = __private_tls_is_point(key)) != CRYPT_OK) {
        mp_clear_multi(key->pubkey.x, key->pubkey.y, key->pubkey.z, key->k, NULL);
        return err;
    }

    /* we're good */
    return CRYPT_OK;
}

void _isdite_fdn_qtls_initCert()
{
  printf("HS SIZE %d\n", sizeof(gcm_state));
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

static inline void _isdite_fdn_qtls_signSha512RSA(void * toCrypt, int toSignLen, void * signature)
{
  unsigned char hash[64];
  hash_state md;
	hash_desc->init(&md);
	hash_desc->process(&md, (const unsigned char*)toCrypt, (unsigned long)toSignLen);
	hash_desc->done(&md, hash);

	// Define padding scheme.
	const int padding = LTC_LTC_PKCS_1_V1_5;
	const unsigned long saltlen = 0;

	// Sign hash.
	unsigned long siglen = 512;
	rsa_sign_hash_ex(hash, hash_desc->hashsize, signature, &siglen, padding, NULL, prng_idx, hash_idx, saltlen, &key);
}

void __private_tls_prf_helper(int hash_idx, unsigned long dlen, unsigned char *output, unsigned int outlen, const unsigned char *secret, const unsigned int secret_len,
                              const unsigned char *label, unsigned int label_len, unsigned char *seed, unsigned int seed_len,
                              unsigned char *seed_b, unsigned int seed_b_len) {
    unsigned char digest_out0[64];
    unsigned char digest_out1[64];
    unsigned int i;
    hmac_state hmac;

    hmac_init(&hmac, hash_idx, secret, secret_len);
    hmac_process(&hmac, label, label_len);

    hmac_process(&hmac, seed, seed_len);
    if ((seed_b) && (seed_b_len))
        hmac_process(&hmac, seed_b, seed_b_len);
    hmac_done(&hmac, digest_out0, &dlen);
    int idx = 0;
    while (outlen) {
        hmac_init(&hmac, hash_idx, secret, secret_len);
        hmac_process(&hmac, digest_out0, dlen);
        hmac_process(&hmac, label, label_len);
        hmac_process(&hmac, seed, seed_len);
        if ((seed_b) && (seed_b_len))
            hmac_process(&hmac, seed_b, seed_b_len);
        hmac_done(&hmac, digest_out1, &dlen);

        unsigned int copylen = outlen;
        if (copylen > dlen)
            copylen = dlen;

        for (i = 0; i < copylen; i++) {
            output[idx++] ^= digest_out1[i];
            outlen--;
        }

        if (!outlen)
            break;

        hmac_init(&hmac, hash_idx, secret, secret_len);
        hmac_process(&hmac, digest_out0, dlen);
        hmac_done(&hmac, digest_out0, &dlen);
    }
}

void __private_tls_prf(
                       unsigned char *output, unsigned int outlen, const unsigned char *secret, const unsigned int secret_len,
                       const unsigned char *label, unsigned int label_len, unsigned char *seed, unsigned int seed_len,
                       unsigned char *seed_b, unsigned int seed_b_len) {

        // sha256_hmac
        unsigned char digest_out0[64];
        unsigned char digest_out1[64];
        unsigned long dlen = 32;
        int hash_idx;
        unsigned int mac_length = 32;

        hash_idx = find_hash("sha256");
        unsigned int i;
        hmac_state hmac;

        hmac_init(&hmac, hash_idx, secret, secret_len);
        hmac_process(&hmac, label, label_len);

        hmac_process(&hmac, seed, seed_len);
        if ((seed_b) && (seed_b_len))
            hmac_process(&hmac, seed_b, seed_b_len);
        hmac_done(&hmac, digest_out0, &dlen);
        int idx = 0;
        while (outlen) {
            hmac_init(&hmac, hash_idx, secret, secret_len);
            hmac_process(&hmac, digest_out0, dlen);
            hmac_process(&hmac, label, label_len);
            hmac_process(&hmac, seed, seed_len);
            if ((seed_b) && (seed_b_len))
                hmac_process(&hmac, seed_b, seed_b_len);
            hmac_done(&hmac, digest_out1, &dlen);

            unsigned int copylen = outlen;
            if (copylen > dlen)
                copylen = (unsigned int)dlen;

            for (i = 0; i < copylen; i++) {
                output[idx++] = digest_out1[i];
                outlen--;
            }

            if (!outlen)
                break;

            hmac_init(&hmac, hash_idx, secret, secret_len);
            hmac_process(&hmac, digest_out0, dlen);
            hmac_done(&hmac, digest_out0, &dlen);
        }

}

// REGION: HANDLERS

static inline int _isdite_fdn_qtls_handler_preHello
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
  memcpy(pContext->lctx.early_handshake_data + 32, aResponseData + 11, 32); //649 + certSz

  pContext->iState = _ISDITE_QTLS_ST_SHELLODONE;

  _isdite_tcpServer_sendPacketDropOnError(pServerDesc, pClientDesc, aResponseData, 650 + certSz);
  return ISDITE_QTLS_NOT_FINISHED_YET;
}

static inline int _isdite_fdn_qtls_handler_afterHello(struct isdite_fdn_qtls_context * ctx, int rs)
{
  if((int)((struct _isdite_fdn_qtls_tlsRecordLayerHeader*)ctx->dataPtr)->type != 22 && (int)((struct _isdite_fdn_qtls_tlsRecordLayerHeader*)ctx->dataPtr)->type != 20)
    return ISDITE_QTLS_INVALID_DATA;

  if(*(((uint8_t*)(ctx->dataPtr))+5) == 16 && (int)((struct _isdite_fdn_qtls_tlsRecordLayerHeader*)ctx->dataPtr)->type == 22)
  {
    hash_desc256->process((hash_state*)ctx->msg_hash, ((char*)ctx->dataPtr) + 5, ntohs(((struct _isdite_fdn_qtls_tlsRecordLayerHeader*)ctx->dataPtr)->length));

    isdite_fdn_fsyslog(IL_TRAC, "QTLS TLS 1.2: Received 'Client Key Exchange' packet.");


    ecc_key remoteKey;
    __private_tls_ecc_import_key(ek.k, 256, (((uint8_t*)(ctx->dataPtr))+10), 65, &remoteKey, &secp256r1.dp);

    uint8_t aSharedSecret[128];
    unsigned long outSz = 128;

    ecc_shared_secret(&ek, &remoteKey, aSharedSecret, &outSz);

    __private_tls_prf(ctx->lctx.early_handshake_data+64, 48, aSharedSecret, outSz, "master secret", 13, ctx->lctx.early_handshake_data, 32, ctx->lctx.early_handshake_data+32, 32);
    __private_tls_prf(ctx->lctx.early_handshake_data+64+48, 40, ctx->lctx.early_handshake_data+64, 48, "key expansion", 13, ctx->lctx.early_handshake_data+32, 32, ctx->lctx.early_handshake_data, 32);

    memcpy(ctx->clientIv, ctx->lctx.early_handshake_data+64+48+32, 4);
    memcpy(ctx->serverIv, ctx->lctx.early_handshake_data+64+48+36, 4);

    ctx->iFlag |= _ISDITE_QTLS_GOT_KEY;
  }
  else if((int)((struct _isdite_fdn_qtls_tlsRecordLayerHeader*)ctx->dataPtr)->type == 20 && ctx->iFlag & _ISDITE_QTLS_GOT_KEY)
  {
    isdite_fdn_fsyslog(IL_TRAC, "QTLS TLS 1.2: Received 'Change Cipher Spec'.");

    ctx->iFlag |= _ISDITE_QTLS_CIPHER_SPEC;
  }
  else
  {
      isdite_fdn_fsyslog(IL_TRAC, "QTLS TLS 1.2: Received 'Client Finished' packet.");

    uint8_t aData[80];
    memcpy(aData, ctx->lctx.early_handshake_data+64, 80);

    gcm_init((gcm_state*)ctx->remote_ctx, find_cipher("aes"), aData+48, 16);
    gcm_init((gcm_state*)ctx->lctx.local_ctx, find_cipher("aes"), aData+48+16, 16);


    char aad[13];
    memset(aad, 0, 13);
    aad[8] = 22;
    aad[9] = 3;
    aad[10] = 3;
    aad[11] = 0;
    aad[12] = 16;

    char ptBuf[32];
    char macTag[32];
    gcm_reset((gcm_state*)ctx->remote_ctx);
    memset(ctx->clientIv+4, 0, 8);
    gcm_add_iv((gcm_state*)ctx->remote_ctx, ctx->clientIv, 12);
    gcm_add_aad((gcm_state*)ctx->remote_ctx, aad, 13);
    gcm_process((gcm_state*)ctx->remote_ctx, ptBuf, 16, ctx->dataPtr + 5 + 8, GCM_DECRYPT);
    unsigned long taglen = 16;
    gcm_done((gcm_state*)ctx->lctx.local_ctx, macTag, &taglen);
    hash_desc256->process((hash_state*)ctx->msg_hash, ptBuf, 16);

    struct _isdite_fdn_qtls_changeCipherSpec ccs;
    ccs.identMagic = 20;
    ccs.version = 0x0303;
    ccs.len = htons(1);
    ccs.data = 1;
    send(ctx->iSockFd, &ccs, sizeof(ccs), 0);

    char hash[32];
    hash_desc256->done((hash_state*)ctx->msg_hash, hash);


    uint8_t rdata[40];
    memset(rdata, 0, 8);
    uint8_t data[] = {0x14, 0x00, 0x00, 0x0C};
    memcpy(rdata+8, data, 4);
    __private_tls_prf(rdata+12, 12, aData, 48, "server finished", strlen("server finished"), hash, 32, NULL, 0);

    uint8_t encRes[16];

    char aad2[13];
    memset(aad2, 0, 13);
    aad2[8] = 22;
    aad2[9] = 3;
    aad2[10] = 3;
    aad2[11] = 0;
    aad2[12] = 16;

    memset(ctx->serverIv+4, 0, 8);
    gcm_reset((gcm_state*)ctx->lctx.local_ctx);
    gcm_add_iv((gcm_state*)ctx->lctx.local_ctx, ctx->serverIv, 12);
    gcm_add_aad((gcm_state*)ctx->lctx.local_ctx, aad2, 13);
    gcm_process((gcm_state*)ctx->lctx.local_ctx, rdata+8, 16, encRes, GCM_ENCRYPT);

    memcpy(rdata+8, encRes, 16);

    taglen = 16;
    gcm_done((gcm_state*)ctx->lctx.local_ctx, rdata+24, &taglen);


    struct _isdite_fdn_qtls_serverFinished fin;

    fin.identMagic = 22;
    fin.version = 0x0303;
    fin.len = htons(40);
    memcpy(fin.data, rdata, 40);

    send(ctx->iSockFd, &fin, sizeof(fin), 0);

    ctx->iState = _ISDITR_QTLS_ST_DATA_READY;
  }

  return ISDITE_QTLS_INSUFFICIENT_DATA;
}

static inline int _isdite_fdn_qtls_handler_apdata(struct isdite_fdn_qtls_context * ctx, int rs)
{

  uint8_t * realData = ctx->dataPtr;

  if(*realData == 21)
  {
    isdite_fdn_fsyslog(IL_TRAC, "QTLS TLS 1.2: Received network alert.");

    return ISDITE_QTLS_INSUFFICIENT_DATA;
  }
  else
  {
    isdite_fdn_fsyslog(IL_TRAC, "QTLS TLS 1.2: Received 'Application Data' packet.");

    char aad[13];
    memset(aad, 0, 13);
    aad[8] = 22;
    aad[9] = 3;
    aad[10] = 3;
    aad[11] = 0;
    aad[12] = 16;

    int ptextSz = ntohs(((struct _isdite_fdn_qtls_tlsRecordLayerHeader*)ctx->dataPtr)->length) - 24;

    ctx->conDataSz = ptextSz;

    char ptBuf[4096];
    char macTag[32];
    gcm_reset((gcm_state*)ctx->remote_ctx);
    memcpy(ctx->clientIv+4, realData+5, 8);
    memcpy(aad, realData+5, 8);
    gcm_add_iv((gcm_state*)ctx->remote_ctx, ctx->clientIv, 12);
    gcm_add_aad((gcm_state*)ctx->remote_ctx, aad, 13);
    gcm_process((gcm_state*)ctx->remote_ctx, ctx->conDataBuffer, ptextSz, ctx->dataPtr + 5 + 8, GCM_DECRYPT);
    unsigned long taglen = 16;
    gcm_done((gcm_state*)ctx->lctx.local_ctx, macTag, &taglen);

    return ISDITE_QTLS_DATA_READY;
  }

  return ISDITE_QTLS_INSUFFICIENT_DATA;
}

void isdite_fdn_qtls_sendData(struct isdite_fdn_qtls_context * ctx, void * data, int dataSz)
{
  isdite_fdn_fsyslog(IL_TRAC, "QTLS TLS 1.2: Sending response.");
  uint8_t outputBuffer[4096];

  outputBuffer[0] = 23;
  outputBuffer[1] = 3;
  outputBuffer[2] = 3;
  outputBuffer[3] = 0;
  outputBuffer[4] = 24 + dataSz;

  *((uint32_t*)(outputBuffer+5)) = 0;
  *((uint32_t*)(outputBuffer+5 + 4)) = htonl(ctx->iNonce);

  uint8_t aad[13];
  memset(aad, 0, 13);
  aad[7] = ctx->iNonce++;
  aad[8] = 23;
  aad[9] = 3;
  aad[10] = 3;
  aad[12] = dataSz;

  memcpy(ctx->serverIv+4, aad, 8);
  gcm_reset((gcm_state*)ctx->lctx.local_ctx);
  gcm_add_iv((gcm_state*)ctx->lctx.local_ctx, ctx->serverIv, 12);
  gcm_add_aad((gcm_state*)ctx->lctx.local_ctx, aad, 13);
  gcm_process((gcm_state*)ctx->lctx.local_ctx, data, dataSz, outputBuffer + 5 + 8, GCM_ENCRYPT);

  unsigned long taglen = 16;
  gcm_done((gcm_state*)ctx->lctx.local_ctx, outputBuffer + 5 + 8 + dataSz, &taglen);

  send(ctx->iSockFd, outputBuffer, 5 + 24 + dataSz, 0);
}

int isdite_qtls_processInput(void * sdesc, void * desc, struct isdite_fdn_qtls_context * ctx, uint8_t * input, int inputSize)
{
  if(inputSize < sizeof(struct _isdite_fdn_qtls_tlsRecordLayerHeader))
    return ISDITE_QTLS_INVALID_DATA;
  else
  {
    ctx->dataPtr = input;

    uint16_t ui16RecordLayerSize = ntohs(*(uint16_t*)(input+3)) + 5;
    if(ui16RecordLayerSize > 8192)
      return ISDITE_QTLS_INVALID_DATA;

    if(inputSize >= ui16RecordLayerSize)
    {
      int res = 0;
      switch(ctx->iState)
      {
        case _ISDITE_QTLS_PREHELLO:
        {
          res = _isdite_fdn_qtls_handler_preHello(ctx, input + 5, ui16RecordLayerSize - 5, sdesc, desc);
          break;
        }
        case _ISDITE_QTLS_ST_SHELLODONE:
        {
          res = _isdite_fdn_qtls_handler_afterHello(ctx, ui16RecordLayerSize);
          break;
        }
        case _ISDITR_QTLS_ST_DATA_READY:
        {
          res = _isdite_fdn_qtls_handler_apdata(ctx, ui16RecordLayerSize);
          break;
        }
        default:
        {
          break;
        }
      }

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
