#include "qtls.h"
#include "def.h"

#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include "ext/tomcrypt.c"


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
  uint8_t data[64]; // 1
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

#define DEBUG_PRINT

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
        DEBUG_PRINT("KEY IS NOT ON CURVE\n");
        mp_clear_multi(key->pubkey.x, key->pubkey.y, key->pubkey.z, key->k, NULL);
        return err;
    }

    /* we're good */
    return CRYPT_OK;
}

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
  //void *Yc = NULL;
//  ltc_mp.init(&Yc);
  ecc_make_key_ex(NULL, find_prng("sprng"), &ek, &secp256r1.dp);
//  ltc_mp.deinit(Yc);

  eccExpKeySz = 4096;
  ecc_ansi_x963_export(&ek, eccExpKey, &eccExpKeySz);

  printf("%d\n", eccExpKeySz);

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

static inline int _isdite_fdn_qtls_handler_preHello(struct isdite_fdn_qtls_context * ctx, int rs)
{

  ctx->msg_hash = malloc(sizeof(hash_state));
	hash_desc256->init((hash_state*)ctx->msg_hash);
	hash_desc256->process((hash_state*)ctx->msg_hash, (const unsigned char*)ctx->dataPtr+5, ntohs(((struct _isdite_fdn_qtls_tlsRecordLayerHeader*)ctx->dataPtr)->length));

  printf("pID %d nT %d\n", ntohs(((struct _isdite_fdn_qtls_tlsRecordLayerHeader*)ctx->dataPtr)->length), (int)((struct _isdite_fdn_qtls_tlsRecordLayerHeader*)ctx->dataPtr)->type);
  if((int)((struct _isdite_fdn_qtls_tlsRecordLayerHeader*)ctx->dataPtr)->type != 22)
    return ISDITE_QTLS_INVALID_DATA;

  struct _isdite_fdn_qtls_serverHello shello;

  shello.rlh.type = 22; // handshake
  shello.rlh.version = 0x0303;
  shello.rlh.length = htons(sizeof(shello) - 5 + sizeof(struct _isdite_fdn_qtls_certificate) + certSz + sizeof(struct _isdite_fdn_qtls_serverKeyExchange) + sizeof(struct _isdite_fdn_qtls_serverHelloDone));

  shello.identMagic = 2; // server hello
  shello.align = 0;
  shello.len = htons(sizeof(shello) - 5 - 4);
  shello.ver = 0x0303;
  shello.sidLen = 0;
  shello.cipherSuite = 0x2fc0; //
  shello.comprMeth = 0;

  for(int i = 0; i < 32;i++)
    shello.random[i] = i * 13 + i;

  hash_desc256->process((hash_state*)ctx->msg_hash, ((const unsigned char*)&shello)+sizeof(shello.rlh), sizeof(shello) - sizeof(shello.rlh));

  send(ctx->sockFd, &shello, sizeof(shello), 0);

  struct _isdite_fdn_qtls_certificate cert;

  cert.identMagic = 11;//cert
  cert.align = 0;
  cert.len = htons(sizeof(cert) + certSz - 4);
  cert.align2 = 0;
  cert.certsLen = htons(certSz + 3) ;
  cert.align3 = 0;
  cert.certLen = htons(certSz);

  char fbaCert[4096];

  memcpy(fbaCert, &cert, sizeof(cert));
  memcpy(fbaCert+sizeof(cert), certBuf, certSz);
  send(ctx->sockFd, fbaCert, sizeof(cert) + certSz, 0);

  hash_desc256->process((hash_state*)ctx->msg_hash, ((const unsigned char*)&cert), sizeof(cert));
  hash_desc256->process((hash_state*)ctx->msg_hash, ((const unsigned char*)certBuf), certSz);

  //
  struct _isdite_fdn_qtls_serverKeyExchange kxchg;
  kxchg.identMagic = 12;
  kxchg.align = 0;
  kxchg.len = htons(sizeof(kxchg) - 4);
  kxchg.curveType = 3;
  kxchg.curveAlg = 0x1700;
  kxchg.pubKeyLen = eccExpKeySz;
  memcpy(kxchg.pubKey, eccExpKey, eccExpKeySz);
  kxchg.sigAlg = 0x0106;
  kxchg.sigLen = htons(512);

  unsigned char * ptr = (unsigned char*)&kxchg;
  ptr += 4;

  char toCrypt[1024];
  memcpy(toCrypt, ((struct _isdite_fdn_qtls_clientHello*)((((char*)(struct _isdite_fdn_qtls_tlsRecordLayerHeader*)ctx->dataPtr))+ 5))->random, 32);
  memcpy(toCrypt+32, shello.random, 32);
  memcpy(toCrypt+64, ptr, 69); // -sig

  memcpy(ctx->cliRand, ((struct _isdite_fdn_qtls_clientHello*)((((char*)(struct _isdite_fdn_qtls_tlsRecordLayerHeader*)ctx->dataPtr))+ 5))->random, 32);
  memcpy(ctx->srvRand, shello.random, 32);

  int toSignLen = 64 + 69;
  _isdite_fdn_qtls_signSha512RSA(toCrypt, toSignLen, kxchg.sig);

  send(ctx->sockFd, &kxchg, sizeof(kxchg), 0);

  hash_desc256->process((hash_state*)ctx->msg_hash, ((const unsigned char*)&kxchg), sizeof(kxchg));

  struct _isdite_fdn_qtls_serverHelloDone  hdone;

  hdone.identMagic = 14;
  hdone.align = 0;
  hdone.len = 0;

  send(ctx->sockFd, &hdone, sizeof(hdone), 0);

  hash_desc256->process((hash_state*)ctx->msg_hash, ((const unsigned char*)&hdone), sizeof(hdone));

  ctx->tlsState = _ISDITE_QTLS_ST_SHELLODONE;
  return ISDITE_QTLS_NOT_FINISHED_YET;
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


static inline int _isdite_fdn_qtls_handler_afterHello(struct isdite_fdn_qtls_context * ctx, int rs)
{
  printf("pID %d nT %d\n", ntohs(((struct _isdite_fdn_qtls_tlsRecordLayerHeader*)ctx->dataPtr)->length), (int)((struct _isdite_fdn_qtls_tlsRecordLayerHeader*)ctx->dataPtr)->type);

  if((int)((struct _isdite_fdn_qtls_tlsRecordLayerHeader*)ctx->dataPtr)->type != 22 && (int)((struct _isdite_fdn_qtls_tlsRecordLayerHeader*)ctx->dataPtr)->type != 20)
    return ISDITE_QTLS_INVALID_DATA;

  if(*(((uint8_t*)(ctx->dataPtr))+5) == 16)
  {
    printf("Client key exchange\n");

    void * ptr = (void*)(((uint8_t*)(ctx->dataPtr))+10);
    memcpy(ctx->cliKey, ptr, 65);

    for(int i = 0; i < 65; i++)
    {
      printf("%x ", (uint8_t)ctx->cliKey[i]);
    }

    printf("\n");

    ecc_key remoteKey;
    memset(&remoteKey, 0, sizeof(ecc_key));
    int iRes = __private_tls_ecc_import_key(ek.k, 256, ctx->cliKey, 65, &remoteKey, &secp256r1.dp);

      printf("%s\n", ek.dp->name);
        printf("%d\n", iRes);

    unsigned long outSz = 128;
    iRes = ecc_shared_secret(&ek, &remoteKey, ctx->shared, &outSz);
      printf("%d\n", outSz);

    __private_tls_prf(ctx->masterSecret, 48, ctx->shared, outSz, "master secret", strlen("master secret"), ctx->cliRand, 32, ctx->srvRand, 32);
    __private_tls_prf(ctx->keyExpansion, 192, ctx->masterSecret, 48, "key expansion", strlen("key expansion"), ctx->srvRand, 32, ctx->cliRand, 32);

    memcpy(ctx->clientWriteKey, ctx->keyExpansion, 16);
    memcpy(ctx->serverWriteKey, ctx->keyExpansion+16, 16);
    memcpy(ctx->clientIv, ctx->keyExpansion+32, 12);
    memcpy(ctx->serverIv, ctx->keyExpansion+36, 12);

    ctx->local_ctx = malloc(sizeof(gcm_state));
    ctx->remote_ctx = malloc(sizeof(gcm_state));

    gcm_init((gcm_state*)ctx->local_ctx, find_cipher("aes"), ctx->serverWriteKey, 16);
    gcm_init((gcm_state*)ctx->remote_ctx, find_cipher("aes"), ctx->clientWriteKey, 16);

    hash_desc256->process((hash_state*)ctx->msg_hash, ptr - 5, ntohs(((struct _isdite_fdn_qtls_tlsRecordLayerHeader*)ctx->dataPtr)->length));

    ctx->iFlag |= _ISDITE_QTLS_GOT_KEY;
  }
  else if((int)((struct _isdite_fdn_qtls_tlsRecordLayerHeader*)ctx->dataPtr)->type == 20)
  {
    printf("Change cipher spec\n");

    hash_desc256->process((hash_state*)ctx->msg_hash, ((char*)ctx->dataPtr) + 5, ntohs(((struct _isdite_fdn_qtls_tlsRecordLayerHeader*)ctx->dataPtr)->length));
    ctx->iFlag |= _ISDITE_QTLS_CIPHER_SPEC;
  }
  else
  {
    printf("Encrypted hs message\n");

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
    unsigned long taglen = 32;
    gcm_done((gcm_state*)ctx->local_ctx, macTag, &taglen);

    for(int i = 0; i < 12; i++)
    {
      printf("%x ", (uint8_t)ptBuf[i]);
    }

    printf("\n");


    hash_desc256->process((hash_state*)ctx->msg_hash, ptBuf, 16);

    struct _isdite_fdn_qtls_changeCipherSpec ccs;
    ccs.identMagic = 20;
    ccs.version = 0x0303;
    ccs.len = htons(1);
    ccs.data = 1;
    send(ctx->sockFd, &ccs, sizeof(ccs), 0);

    struct _isdite_fdn_qtls_serverFinished fin;
    fin.identMagic = 22;
    fin.version = 0x0303;
    fin.len = htons(64);

    char hash[32];
    hash_desc256->done((hash_state*)ctx->msg_hash, hash);

    //uint8_t data[] = {0x14, 0x00, 0x00, 0x0C};
  //  memcpy(fin.data, data, 4);

  //  __private_tls_prf(fin.data+4, 12, ctx->shared, ctx->sharedSz, "server finished", strlen("server finished"), hash, 32, NULL, 0);
  //  memcpy(fin.data+16, hash, 32);

  //  AES_CBC_encrypt_buffer(&ctx->aesCtx, fin.data, 64);

    //send(ctx->sockFd, &fin, sizeof(fin), 0);

    ctx->tlsState = _ISDITR_QTLS_ST_DATA_READY;
  }

  return ISDITE_QTLS_INSUFFICIENT_DATA;
}

static inline int _isdite_fdn_qtls_handler_apdata(struct isdite_fdn_qtls_context * ctx, int rs)
{
  //uint8_t * realData = ctx->dataPtr + 11;

//  int rrs = rs - 11;
  //realData[rrs] = 0x00;


  //AES_CBC_decrypt_buffer(&ctx->aesCtx, realData, rrs);
//
  //printf(realData);

  return ISDITE_QTLS_INSUFFICIENT_DATA;
}


static inline int _isdite_fdn_qtls_isPacketComplete(struct isdite_fdn_qtls_context * ctx, int rs)
{
  return rs >= ntohs(((struct _isdite_fdn_qtls_tlsRecordLayerHeader*)ctx->dataPtr)->length) ? 1 : 0;
}

int isdite_fdn_qtls_processInput(struct isdite_fdn_qtls_context * ctx)
{
  int realDataSz = ctx->dataSz - ctx->pktTop;
  printf("rds %d\n", realDataSz);
  if
  (
    realDataSz < sizeof(struct _isdite_fdn_qtls_tlsRecordLayerHeader) ||
    !_isdite_fdn_qtls_isPacketComplete(ctx, realDataSz)
  )
  {
    printf("insufficient\n");
    return ISDITE_QTLS_INSUFFICIENT_DATA;
  }


  int res = 0;
  switch(ctx->tlsState)
  {
    case _ISDITE_QTLS_PREHELLO:
    {
      res = _isdite_fdn_qtls_handler_preHello(ctx, realDataSz);
      break;
    }
    case _ISDITE_QTLS_ST_SHELLODONE:
    {
      res = _isdite_fdn_qtls_handler_afterHello(ctx, realDataSz);
      break;
    }
    case _ISDITR_QTLS_ST_DATA_READY:
    {
      res = _isdite_fdn_qtls_handler_apdata(ctx, realDataSz);
      break;
    }
    default:
    {
      break;
    }
  }

  int procDataSz = ntohs(((struct _isdite_fdn_qtls_tlsRecordLayerHeader*)ctx->dataPtr)->length) + 5;
  printf("pds %d\n", procDataSz);

  if(realDataSz == procDataSz)
  {
    printf("clear\n");
    ctx->dataPtr = ctx->buf;
    ctx->pktTop = 0;
    ctx->dataSz = 0;
  }
  else
  {
    ctx->dataPtr += procDataSz;
    ctx->pktTop += procDataSz;

    return isdite_fdn_qtls_processInput(ctx);
  }

  return res;
}
