#ifndef __GTJACRYPT_H__
#define __GTJACRYPT_H__

#include <openssl/ossl_typ.h>
#include "openssl/md5.h"
#include "openssl/evp.h"
#include <openssl/crypto.h>
#include <openssl/sm2.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef NULL
#define NULL 0
#endif

static int get_sign_info(const char *alg, int *ppkey_type, const EVP_MD **pmd, int *pec_scheme);
static int get_pke_info(const char *alg, int *ppkey_type, int *pec_scheme, int *pec_encrypt_param);
int getMD5(const char *pIn, char **pOut);
int getSM3(const unsigned char *pIn, int inlen, char **pOut);
int getSM2Sign(const unsigned char *pIn, int inlen, const unsigned char *pPriKey, int keylen,
               char **pOut);
bool getSM2Verify(const unsigned char *pSigned, int signedlen, const unsigned char *pOriginal,
                  int originallen, const unsigned char *pPubKey, int keylen);

int getSM2Encrypt(const unsigned char *pIn, int inlen, const unsigned char *pPubKey, int keylen,
                  char **pOut);
int getSM2Decrypt(const unsigned char *pIn, int inlen, const unsigned char *pPriKey, int keylen,
                  char **pOut);

int getSM4Encrypt(const unsigned char *pIn, int inlen, const unsigned char *pKey, int keylen,
                  const unsigned char *pIv, int ivlen, char **pOut);

int getSM4Decrypt(const unsigned char *pIn, int inlen, const unsigned char *pKey, int keylen,
                  const unsigned char *pIv, int ivlen, char **pOut);

#ifdef __cplusplus
}
#endif

#endif
