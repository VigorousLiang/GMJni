#include "GTCryptUtil.h"
#include <stdio.h>
#include <string.h>


static int get_sign_info(const char *alg, int *ppkey_type,
                         const EVP_MD **pmd, int *pec_scheme) {
    int pkey_type;
    const EVP_MD *md = NULL;
    int ec_scheme = -1;

    switch (OBJ_txt2nid(alg)) {
#ifndef OPENSSL_NO_SM2
        case NID_sm2sign:
            pkey_type = EVP_PKEY_EC;
            ec_scheme = NID_sm_scheme;
            break;
#endif
        case NID_ecdsa_with_Recommended:
            pkey_type = EVP_PKEY_EC;
            ec_scheme = NID_secg_scheme;
            break;
#ifndef OPENSSL_NO_SHA
        case NID_ecdsa_with_SHA1:
            pkey_type = EVP_PKEY_EC;
            md = EVP_sha1();
            ec_scheme = NID_secg_scheme;
            break;
        case NID_ecdsa_with_SHA256:
            pkey_type = EVP_PKEY_EC;
            md = EVP_sha256();
            ec_scheme = NID_secg_scheme;
            break;
        case NID_ecdsa_with_SHA512:
            pkey_type = EVP_PKEY_EC;
            md = EVP_sha512();
            ec_scheme = NID_secg_scheme;
            break;
# ifndef OPENSSL_NO_RSA
        case NID_sha1WithRSAEncryption:
            pkey_type = EVP_PKEY_RSA;
            md = EVP_sha1();
            break;
        case NID_sha256WithRSAEncryption:
            pkey_type = EVP_PKEY_RSA;
            md = EVP_sha256();
            break;
        case NID_sha512WithRSAEncryption:
            pkey_type = EVP_PKEY_RSA;
            md = EVP_sha512();
            break;
# endif
# ifndef OPENSSL_NO_DSA
        case NID_dsaWithSHA1:
            pkey_type = EVP_PKEY_DSA;
            md = EVP_sha1();
            break;
# endif
#endif
        default:
            return 0;
    }

    *ppkey_type = pkey_type;
    *pmd = md;
    *pec_scheme = ec_scheme;

    return 1;
}

static int get_pke_info(const char *alg, int *ppkey_type,
                        int *pec_scheme, int *pec_encrypt_param) {
    int pkey_type = 0;
    int ec_scheme = 0;
    int ec_encrypt_param = 0;

    switch (OBJ_txt2nid(alg)) {
#ifndef OPENSSL_NO_RSA
        case NID_rsaesOaep:
            pkey_type = EVP_PKEY_RSA;
            break;
#endif
#ifndef OPENSSL_NO_ECIES
        case NID_ecies_recommendedParameters:
        case NID_ecies_specifiedParameters:
# ifndef OPENSSL_NO_SHA
        case NID_ecies_with_x9_63_sha1_xor_hmac:
        case NID_ecies_with_x9_63_sha256_xor_hmac:
        case NID_ecies_with_x9_63_sha512_xor_hmac:
        case NID_ecies_with_x9_63_sha1_aes128_cbc_hmac:
        case NID_ecies_with_x9_63_sha256_aes128_cbc_hmac:
        case NID_ecies_with_x9_63_sha512_aes256_cbc_hmac:
        case NID_ecies_with_x9_63_sha256_aes128_ctr_hmac:
        case NID_ecies_with_x9_63_sha512_aes256_ctr_hmac:
        case NID_ecies_with_x9_63_sha256_aes128_cbc_hmac_half:
        case NID_ecies_with_x9_63_sha512_aes256_cbc_hmac_half:
        case NID_ecies_with_x9_63_sha256_aes128_ctr_hmac_half:
        case NID_ecies_with_x9_63_sha512_aes256_ctr_hmac_half:
        case NID_ecies_with_x9_63_sha1_aes128_cbc_cmac:
        case NID_ecies_with_x9_63_sha256_aes128_cbc_cmac:
        case NID_ecies_with_x9_63_sha512_aes256_cbc_cmac:
        case NID_ecies_with_x9_63_sha256_aes128_ctr_cmac:
        case NID_ecies_with_x9_63_sha512_aes256_ctr_cmac:
# endif
            pkey_type = EVP_PKEY_EC;
            ec_scheme = NID_secg_scheme;
            ec_encrypt_param = OBJ_txt2nid(alg);
            break;
#endif
#ifndef OPENSSL_NO_SM2
        case NID_sm2encrypt_with_sm3:
            pkey_type = EVP_PKEY_EC;
            ec_scheme = NID_sm_scheme;
            ec_encrypt_param = NID_sm3;
            break;
# ifndef OPENSSL_NO_SHA
        case NID_sm2encrypt_with_sha1:
            pkey_type = EVP_PKEY_EC;
            ec_scheme = NID_sm_scheme;
            ec_encrypt_param = NID_sha1;
            break;
        case NID_sm2encrypt_with_sha256:
            pkey_type = EVP_PKEY_EC;
            ec_scheme = NID_sm_scheme;
            ec_encrypt_param = NID_sha256;
            break;
        case NID_sm2encrypt_with_sha512:
            pkey_type = EVP_PKEY_EC;
            ec_scheme = NID_sm_scheme;
            ec_encrypt_param = NID_sha512;
            break;
# endif
#endif
        default:
            return 0;
    }

    *ppkey_type = pkey_type;
    *pec_scheme = ec_scheme;
    *pec_encrypt_param = ec_encrypt_param;

    return 1;
}

int getMD5(const char *pIn, char **pOut) {
    int ret = 0;
    unsigned char md[MD5_DIGEST_LENGTH] = {0};
    MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx, pIn, strlen(pIn));
    MD5_Final(md, &ctx);
    *pOut = (char *) malloc(MD5_DIGEST_LENGTH * 2 + 1);
    if (*pOut) {
        memset(*pOut, 0x00, MD5_DIGEST_LENGTH * 2 + 1);
        char *pTemp = *pOut;
        for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
            sprintf(pTemp, "%02x", md[i]);
            pTemp += 2;
        }
    }
    return ret;
}

int getSM3(const unsigned char *pIn, int inlen, char **pOut) {
    int ret = 0;
    unsigned char outbuf[EVP_MAX_MD_SIZE];
    unsigned int outlen = sizeof(outbuf);

    if (!EVP_Digest(pIn, inlen, outbuf, &outlen, EVP_sm3(), NULL)) {
        return ret;
    }
    *pOut = (char *) malloc(EVP_MAX_MD_SIZE * 2 + 1);
    if (*pOut) {
        memset(*pOut, 0x00, EVP_MAX_MD_SIZE * 2 + 1);
        char *pTemp = *pOut;
        for (int i = 0; i < outlen; i++) {
            sprintf(pTemp, "%02x", outbuf[i]);
            pTemp += 2;
        }
        ret = 1;
    }
    return ret;
}

int getSM2Sign(const unsigned char *pIn, int inlen, const unsigned char *pPriKey, int keylen,
               char **pOut) {
    int ret = 0;
    const char *alg = "sm2sign";
    unsigned char outbuf[1024];
    unsigned int outlen = sizeof(outbuf);
    const unsigned char *cp;
    int ec_scheme = -1;

    const EVP_MD *md = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pkctx = NULL;

    int pkey_type = 0;
    if (!get_sign_info(alg, &pkey_type, &md, &ec_scheme)) {
        return ret;
    }

    cp = pPriKey;

    if (!(pkey = d2i_PrivateKey(pkey_type, NULL, &cp, keylen))) {
        return ret;
    }

    if (!(pkctx = EVP_PKEY_CTX_new(pkey, NULL))) {
        return ret;
    }

    if (EVP_PKEY_sign_init(pkctx) <= 0) {
        return ret;
    }
    if (md) {
        if (!EVP_PKEY_CTX_set_signature_md(pkctx, md)) {
            return ret;
        }
    }

    if (!EVP_PKEY_CTX_set_ec_scheme(pkctx, OBJ_txt2nid(alg) == NID_sm2sign ?
                                           NID_sm_scheme : NID_secg_scheme)) {
        return ret;
    }
    if (pkey_type == EVP_PKEY_RSA) {
#ifndef OPENSSL_NO_RSA
        if (!EVP_PKEY_CTX_set_rsa_padding(pkctx, RSA_PKCS1_PSS_PADDING)) {
            return ret;
        }
#endif
    } else if (pkey_type == EVP_PKEY_EC) {
#ifndef OPENSSL_NO_SM2
        if (!EVP_PKEY_CTX_set_ec_scheme(pkctx, OBJ_txt2nid(alg) == NID_sm2sign ?
                                               NID_sm_scheme : NID_secg_scheme)) {
            return ret;
        }
#endif
    }

    if (EVP_PKEY_sign(pkctx, outbuf, &outlen, pIn, inlen) <= 0) {
        return ret;
    }
    *pOut = (char *) malloc(outlen * 2 + 1);
    if (*pOut) {
        memset(*pOut, 0x00, outlen * 2 + 1);
        char *pTemp = *pOut;
        for (int i = 0; i < outlen; i++) {
            sprintf(pTemp, "%02x", outbuf[i]);
            pTemp += 2;
        }
        ret = 1;
    }
    return ret;
}

bool getSM2Verify(const unsigned char *pSigned, int signedlen, const unsigned char *pOriginal,
                  int originallen, const unsigned char *pPubKey, int keylen) {
    bool ret = false;
    const char *alg = "sm2sign";
    const unsigned char *cp;
    int pkey_type = 0;
    const EVP_MD *md = NULL;
    int ec_scheme = -1;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pkctx = NULL;

    if (!get_sign_info(alg, &pkey_type, &md, &ec_scheme)) {
        return ret;
    }

    cp = pPubKey;
    if (!(pkey = d2i_PUBKEY(NULL, &cp, (long) keylen))) {
        return ret;
    }

    if (EVP_PKEY_id(pkey) != pkey_type) {
        return ret;
    }
    if (!(pkctx = EVP_PKEY_CTX_new(pkey, NULL))) {
        return ret;
    }

    if (EVP_PKEY_verify_init(pkctx) <= 0) {
        return ret;
    }

    if (md && !EVP_PKEY_CTX_set_signature_md(pkctx, md)) {
        return ret;
    }


    if (pkey_type == EVP_PKEY_RSA) {
#ifndef OPENSSL_NO_RSA
        if (!EVP_PKEY_CTX_set_rsa_padding(pkctx, RSA_PKCS1_PSS_PADDING)) {
            return ret;
        }
#endif
    } else if (pkey_type == EVP_PKEY_EC) {
#ifndef OPENSSL_NO_SM2
        if (!EVP_PKEY_CTX_set_ec_scheme(pkctx, OBJ_txt2nid(alg) == NID_sm2sign ?
                                               NID_sm_scheme : NID_secg_scheme)) {
            return ret;
        }
#endif
    }

    if (EVP_PKEY_verify(pkctx, pSigned, signedlen, pOriginal, originallen) <= 0) {
        return ret;
    } else {
        return true;
    }
}

int getSM2Encrypt(const unsigned char *pIn, int inlen, const unsigned char *pPubKey, int keylen,
                  char **pOut) {
    int ret = 0;
    const char *alg = "sm2encrypt-with-sm3";
    const unsigned char *cp;
    const EVP_MD *md = NULL;
    int pkey_type = NID_undef;
    int ec_scheme = NID_undef;
    int ec_encrypt_param = NID_undef;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pkctx = NULL;
    unsigned char *outbuf = NULL;
    size_t outlen;

    cp = pPubKey;
    outlen = inlen + 1024;

    if (!get_pke_info(alg, &pkey_type, &ec_scheme, &ec_encrypt_param)) {
        return ret;
    }

    if (!(outbuf = (unsigned char *) OPENSSL_malloc(outlen))) {
        return ret;
    }
    if (!(pkey = d2i_PUBKEY(NULL, &cp, (long) keylen))) {
        return ret;
    }
    if (EVP_PKEY_id(pkey) != pkey_type) {
        return ret;
    }
    if (!(pkctx = EVP_PKEY_CTX_new(pkey, NULL))) {
        return ret;
    }

    if (EVP_PKEY_encrypt_init(pkctx) <= 0) {
        return ret;
    }

    if (pkey_type == EVP_PKEY_EC) {
#if !defined(OPENSSL_NO_ECIES) || !defined(OPENSSL_NO_SM2)
        if (!EVP_PKEY_CTX_set_ec_scheme(pkctx, ec_scheme)) {
            return ret;
        }
        if (!EVP_PKEY_CTX_set_ec_encrypt_param(pkctx, ec_encrypt_param)) {
            return ret;
        }
#endif
    }

    if (EVP_PKEY_encrypt(pkctx, outbuf, &outlen, pIn, inlen) <= 0) {
        return ret;
    }

    *pOut = (char *) malloc(outlen * 2 + 1);
    if (*pOut) {
        memset(*pOut, 0x00, outlen * 2 + 1);
        char *pTemp = *pOut;
        for (int i = 0; i < outlen; i++) {
            sprintf(pTemp, "%02x", outbuf[i]);
            pTemp += 2;
        }
        ret = 1;
    }
    return ret;
}

int getSM2Decrypt(const unsigned char *pIn, int inlen, const unsigned char *pPriKey, int keylen,
                  char **pOut) {
    int ret = 0;
    const char *alg = "sm2encrypt-with-sm3";
    const unsigned char *cp;
    const EVP_MD *md = NULL;
    int pkey_type = NID_undef;
    int ec_scheme = NID_undef;
    int ec_encrypt_param = NID_undef;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pkctx = NULL;
    unsigned char *outbuf = NULL;
    size_t outlen;

    cp = pPriKey;
    outlen = inlen;


    if (!get_pke_info(alg, &pkey_type, &ec_scheme, &ec_encrypt_param)) {
        return ret;
    }

    if (!(outbuf = (unsigned char *) OPENSSL_malloc(outlen))) {
        return ret;
    }
    if (!(pkey = d2i_PrivateKey(pkey_type, NULL, &cp, (long) keylen))) {
        return ret;
    }
    if (!(pkctx = EVP_PKEY_CTX_new(pkey, NULL))) {
        return ret;
    }
    if (EVP_PKEY_decrypt_init(pkctx) <= 0) {
        return ret;
    }

    if (pkey_type == EVP_PKEY_EC) {
#if !defined(OPENSSL_NO_ECIES) || !defined(OPENSSL_NO_SM2)
        if (!EVP_PKEY_CTX_set_ec_scheme(pkctx, ec_scheme)) {
            return ret;
        }

        if (!EVP_PKEY_CTX_set_ec_encrypt_param(pkctx, ec_encrypt_param)) {
            return ret;
        }
#endif
    }

    if (EVP_PKEY_decrypt(pkctx, outbuf, &outlen, pIn, inlen) <= 0) {
        return ret;
    }

    *pOut = (char *) malloc(outlen + 1);
    if (*pOut) {
        memset(*pOut, 0x00, outlen + 1);
        char *pTemp = *pOut;
        for (int i = 0; i < outlen; i++) {
            sprintf(pTemp, "%c", outbuf[i]);
            pTemp += 1;
        }
        ret = 1;
    }
    return ret;
}

int getSM4Encrypt(const unsigned char *pIn, int inlen, const unsigned char *pKey, int keylen,
                  const unsigned char *pIv, int ivlen, char **pOut) {
    int ret = 0;
    const char *alg = "SMS4";
    unsigned char *outbuf = NULL;
    int outlen, lastlen;
    const EVP_CIPHER *cipher;
    EVP_CIPHER_CTX *cctx = NULL;

    if (!(cipher = EVP_get_cipherbyname(alg))) {
        return ret;
    }
    if (keylen != EVP_CIPHER_key_length(cipher)) {
        return ret;
    }
    if (ivlen != EVP_CIPHER_iv_length(cipher)) {
        return ret;
    }

    if (!(outbuf = (unsigned char *) OPENSSL_malloc(inlen + 2 * EVP_CIPHER_block_size(cipher)))) {
        return ret;
    }
    if (!(cctx = EVP_CIPHER_CTX_new())) {
        return ret;
    }
    if (!EVP_EncryptInit_ex(cctx, cipher, NULL, pKey, pIv)) {
        return ret;
    }
    if (!EVP_EncryptUpdate(cctx, outbuf, &outlen, pIn, inlen)) {
        return ret;
    }
    if (!EVP_EncryptFinal_ex(cctx, outbuf + outlen, &lastlen)) {
        return ret;
    }
    outlen += lastlen;

    *pOut = (char *) malloc(outlen * 2 + 1);
    if (*pOut) {
        memset(*pOut, 0x00, outlen * 2 + 1);
        char *pTemp = *pOut;
        for (int i = 0; i < outlen; i++) {
            sprintf(pTemp, "%02x", outbuf[i]);
            pTemp += 2;
        }
        ret = 1;
    }
    return ret;
}

int getSM4Decrypt(const unsigned char *pIn, int inlen, const unsigned char *pKey, int keylen,
                  const unsigned char *pIv, int ivlen, char **pOut) {
    int ret = 0;
    const char *alg = "SMS4";
    unsigned char *outbuf = NULL;
    int outlen, lastlen;
    const EVP_CIPHER *cipher;
    EVP_CIPHER_CTX *cctx = NULL;

    if (!(cipher = EVP_get_cipherbyname(alg))) {
        return ret;
    }
    if (keylen != EVP_CIPHER_key_length(cipher)) {
        return ret;
    }
    if (ivlen != EVP_CIPHER_iv_length(cipher)) {
        return ret;
    }
    if (!(outbuf = (unsigned char *) OPENSSL_malloc(inlen))) {
        return ret;
    }
    if (!(cctx = EVP_CIPHER_CTX_new())) {
        return ret;
    }
    if (!EVP_DecryptInit_ex(cctx, cipher, NULL, pKey, pIv)) {
        return ret;
    }
    if (!EVP_DecryptUpdate(cctx, outbuf, &outlen, pIn, inlen)) {
        return ret;
    }
    if (!EVP_DecryptFinal_ex(cctx, outbuf + outlen, &lastlen)) {
        return ret;
    }
    outlen += lastlen;

    *pOut = (char *) malloc(outlen + 1);
    if (*pOut) {
        memset(*pOut, 0x00, outlen + 1);
        char *pTemp = *pOut;
        for (int i = 0; i < outlen; i++) {
            sprintf(pTemp, "%c", outbuf[i]);
            pTemp += 1;
        }
        ret = 1;
    }
    return ret;
}