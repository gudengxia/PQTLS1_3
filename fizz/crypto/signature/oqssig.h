#pragma once

#include <openssl/evp.h>

typedef struct
{
  /* OpenSSL NID */
  int nid;
  /* OQS signature context */
  OQS_SIG *s;
  /* OQS public key */
  uint8_t *pubkey;
  /* OQS private key */
  uint8_t *privkey;
  /* Classical key pair for hybrid schemes; either a private or public key depending on context */
  EVP_PKEY *classical_pkey;
  /* Security bits for the scheme */
  int security_bits;
} OQS_KEY;

/*
 * OQS key type
 */
typedef enum
{
    KEY_TYPE_PUBLIC,
    KEY_TYPE_PRIVATE,
} oqs_key_type_t;

typedef struct evp_pkey_oqs_st {
    int type;
    int save_type;
    volatile int references;
    const EVP_PKEY_ASN1_METHOD *ameth;
    ENGINE *engine;
    ENGINE *pmeth_engine;
    OQS_KEY* pkey;
    int save_parameters;
    STACK_OF(X509_ATTRIBUTE) *attributes; 
    CRYPTO_RWLOCK *lock;
} EVP_PKEY_OQS;

int pkey_oqs_digestsign(EVP_PKEY *pkey, unsigned char *sig, size_t *siglen, const unsigned char *tbs, size_t tbslen);

int pkey_oqs_digestverify(EVP_PKEY *pkey, const unsigned char *sig, size_t siglen, const unsigned char *tbs, size_t tbslen);

