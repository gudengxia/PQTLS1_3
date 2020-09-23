#include "fizz/crypto/signature/oqssig.h"
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <stdexcept>
#include <iostream>
#define SIZE_OF_UINT32 4
#define ENCODE_UINT32(pbuf, i)  (pbuf)[0] = (unsigned char)((i>>24) & 0xff); \
                                (pbuf)[1] = (unsigned char)((i>>16) & 0xff); \
				(pbuf)[2] = (unsigned char)((i>> 8) & 0xff); \
				(pbuf)[3] = (unsigned char)((i    ) & 0xff)
#define DECODE_UINT32(i, pbuf)  i  = ((uint32_t) (pbuf)[0]) << 24; \
                                i |= ((uint32_t) (pbuf)[1]) << 16; \
				i |= ((uint32_t) (pbuf)[2]) <<  8; \
				i |= ((uint32_t) (pbuf)[3])


/*static char* get_oqs_alg_name(int openssl_nid)
{
  switch (openssl_nid)
  {
///// OQS_TEMPLATE_FRAGMENT_ASSIGN_SIG_ALG_START
    case NID_oqs_sig_default:
    case NID_p256_oqs_sig_default:
    case NID_rsa3072_oqs_sig_default:
      return OQS_SIG_alg_default;
    case NID_dilithium2:
    case NID_p256_dilithium2:
    case NID_rsa3072_dilithium2:
      return OQS_SIG_alg_dilithium_2;
    case NID_dilithium3:
	case NID_p256_dilithium3:
      return OQS_SIG_alg_dilithium_3;
    case NID_dilithium4:
    case NID_p384_dilithium4:
      return OQS_SIG_alg_dilithium_4;
    case NID_picnicl1fs:
    case NID_p256_picnicl1fs:
    case NID_rsa3072_picnicl1fs:
      return OQS_SIG_alg_picnic_L1_FS;
    case NID_picnic2l1fs:
    case NID_p256_picnic2l1fs:
    case NID_rsa3072_picnic2l1fs:
      return OQS_SIG_alg_picnic2_L1_FS;
    case NID_qteslapi:
    case NID_p256_qteslapi:
    case NID_rsa3072_qteslapi:
      return OQS_SIG_alg_qTesla_p_I;
    case NID_qteslapiii:
    case NID_p384_qteslapiii:
      return OQS_SIG_alg_qTesla_p_III;
    case NID_mulan:
	case NID_p256_mulan:
      return OQS_SIG_alg_mulan;
	case NID_aigis:
	case NID_p256_aigis:
      return OQS_SIG_alg_aigis;
///// OQS_TEMPLATE_FRAGMENT_ASSIGN_SIG_ALG_END
    default:
      return NULL;
  }
}*/

static int is_oqs_hybrid_alg(int openssl_nid)
{
  switch (openssl_nid)
  {
///// OQS_TEMPLATE_FRAGMENT_LIST_HYBRID_NIDS_START
    case NID_p256_oqs_sig_default:
    case NID_rsa3072_oqs_sig_default:
    case NID_p256_dilithium2:
    case NID_rsa3072_dilithium2:
    case NID_p384_dilithium4:
    case NID_p256_mulan:
	case NID_p256_aigis:
	case NID_p256_dilithium3:
	case NID_p256_falcon512:
	case NID_p521_falcon1024:
///// OQS_TEMPLATE_FRAGMENT_LIST_HYBRID_NIDS_END
      return 1;
    default:
      return 0;
  }
}


static int get_classical_nid(int hybrid_id)
{
  switch (hybrid_id)
  {
///// OQS_TEMPLATE_FRAGMENT_ASSIGN_CLASSICAL_NIDS_START
    case NID_rsa3072_oqs_sig_default:
    case NID_rsa3072_dilithium2:
      return NID_rsaEncryption;
    case NID_p256_oqs_sig_default:
    case NID_p256_dilithium2:
	case NID_p256_mulan:
	case NID_p256_aigis:
	case NID_p256_dilithium3:
	case NID_p256_falcon512:
      return NID_X9_62_prime256v1;
    case NID_p384_dilithium4:
      return NID_secp384r1;
	case NID_p521_falcon1024:
	  return NID_secp521r1;
///// OQS_TEMPLATE_FRAGMENT_ASSIGN_CLASSICAL_NIDS_END
    default:
      return 0;
  }
}

static int get_classical_key_len(oqs_key_type_t keytype, int classical_id) {
	switch (classical_id)
	{
	case NID_rsaEncryption:
		return (keytype == KEY_TYPE_PRIVATE) ? 1770 : 398;
	case NID_X9_62_prime256v1:
		return (keytype == KEY_TYPE_PRIVATE) ? 121 : 65;
	case NID_secp384r1:
		return (keytype == KEY_TYPE_PRIVATE) ? 167 : 97;
	case NID_secp521r1:
      return (keytype == KEY_TYPE_PRIVATE) ? 223 : 133;
	default:
		return 0;
    }
}

static int get_classical_sig_len(int classical_id)
{
 switch (classical_id)
    {
    case NID_rsaEncryption:
      return 384;
    case NID_X9_62_prime256v1:
      return 72;
    case NID_secp384r1:
      return 104;
	case NID_secp521r1:
      return 141;
    default:
      return 0;
    }
}

int pkey_oqs_digestsign(EVP_PKEY *pkey, unsigned char *sig, size_t *siglen, const unsigned char *tbs, size_t tbslen)
{
	const OQS_KEY* oqs_key = ((EVP_PKEY_OQS*)pkey)->pkey;
	EVP_PKEY_CTX *classical_ctx_sign = NULL;
	int is_hybrid = is_oqs_hybrid_alg(oqs_key->nid);
	int classical_id = 0;
	size_t max_sig_len = oqs_key->s->length_signature;
	size_t classical_sig_len = 0, oqs_sig_len = 0;
	size_t actual_classical_sig_len = 0;
	size_t index = 0;
	int rv = 0;

	if (!oqs_key || !oqs_key->s || !oqs_key->privkey || (is_hybrid && !oqs_key->classical_pkey))
	{
		throw std::runtime_error("error oqs key");
		return rv;
	}
	if (is_hybrid)
	{
		classical_id = get_classical_nid(oqs_key->nid);
		actual_classical_sig_len = get_classical_sig_len(classical_id);
		max_sig_len += (SIZE_OF_UINT32 + actual_classical_sig_len);
	}

	if (sig == NULL)
	{
		/* we only return the sig len */
		*siglen = max_sig_len;
		return 1;
	}
	/*if (*siglen < max_sig_len)
	{
		std::cout<<*siglen<<std::endl;
		std::cout<<max_sig_len<<std::endl;
		throw std::runtime_error("too long signature length");
		return rv;
		}*/

	if (is_hybrid)
	{
		const EVP_MD *classical_md;
		int digest_len;
		unsigned char digest[SHA512_DIGEST_LENGTH]; /* init with max length */

		if ((classical_ctx_sign = EVP_PKEY_CTX_new(oqs_key->classical_pkey, NULL)) == NULL || EVP_PKEY_sign_init(classical_ctx_sign) <= 0)
		{
			throw std::runtime_error("error classic signature key");
			goto end;
		}
		if (classical_id == EVP_PKEY_RSA)
		{
			if (EVP_PKEY_CTX_set_rsa_padding(classical_ctx_sign, RSA_PKCS1_PADDING) <= 0)
			{
				throw std::runtime_error("error set rsa padding");
				goto end;
			}
		}

		/* classical schemes can't sign arbitrarily large data; we hash it first */
		switch (oqs_key->s->claimed_nist_level)
		{
		case 1:
		case 2:
			classical_md = EVP_sha256();
			digest_len = SHA256_DIGEST_LENGTH;
			SHA256(tbs, tbslen, (unsigned char*) &digest);
			break;
		//case 2:
		case 3:
		case 4:
			classical_md = EVP_sha384();
			digest_len = SHA384_DIGEST_LENGTH;
			SHA384(tbs, tbslen, (unsigned char*) &digest);
			break;
		//case 4:
		case 5:
		default:
			classical_md = EVP_sha512();
			digest_len = SHA512_DIGEST_LENGTH;
			SHA512(tbs, tbslen, (unsigned char*) &digest);
			break;
		}
		if (EVP_PKEY_CTX_set_signature_md(classical_ctx_sign, classical_md) <= 0)
		{
			throw std::runtime_error("error set signature md");
			goto end;
		}
		if (EVP_PKEY_sign(classical_ctx_sign, sig + SIZE_OF_UINT32, &actual_classical_sig_len, digest, digest_len) <= 0)
		{
			throw std::runtime_error("error classic signature");
			goto end;
		}
		if (actual_classical_sig_len > (size_t) get_classical_sig_len(classical_id))
		{
			/* sig is bigger than expected! */
			throw std::runtime_error("sig is bigger than expected");
			goto end;
		}
		ENCODE_UINT32(sig, actual_classical_sig_len);
		classical_sig_len = SIZE_OF_UINT32 + actual_classical_sig_len;
		index += classical_sig_len;
	}

	if (OQS_SIG_sign(oqs_key->s, sig + index, &oqs_sig_len, tbs, tbslen, oqs_key->privkey) != OQS_SUCCESS)
	{
		throw std::runtime_error("error oqs sign");
		return 0;
	}
	*siglen = classical_sig_len + oqs_sig_len;

	rv = 1; /* success */

end:
	if (classical_ctx_sign)
	{
		EVP_PKEY_CTX_free(classical_ctx_sign);
	}
	return rv;
}

int pkey_oqs_digestverify(EVP_PKEY* pkey, const unsigned char *sig, size_t siglen, const unsigned char *tbs, size_t tbslen)
{
	const OQS_KEY* oqs_key = ((EVP_PKEY_OQS*)pkey)->pkey;
	int is_hybrid = is_oqs_hybrid_alg(oqs_key->nid);
	int classical_id = 0;
	size_t classical_sig_len = 0;
	size_t index = 0;

	if (!oqs_key || !oqs_key->s  || !oqs_key->pubkey || (is_hybrid && !oqs_key->classical_pkey) ||sig == NULL || tbs == NULL)
	{
		throw std::runtime_error("error oqs key");
		return 0;
	}

	if (is_hybrid)
	{
		classical_id = get_classical_nid(oqs_key->nid);
	}

	if (is_hybrid)
	{
		EVP_PKEY_CTX *ctx_verify = NULL;
		const EVP_MD *classical_md;
		size_t actual_classical_sig_len = 0;
		int digest_len;
		unsigned char digest[SHA512_DIGEST_LENGTH]; /* init with max length */

		if ((ctx_verify = EVP_PKEY_CTX_new(oqs_key->classical_pkey, NULL)) == NULL || EVP_PKEY_verify_init(ctx_verify) <= 0)
		{
			throw std::runtime_error("error classic verify key");
			EVP_PKEY_CTX_free(ctx_verify);
			return 0;
		}
		if (classical_id == EVP_PKEY_RSA)
		{
			if (EVP_PKEY_CTX_set_rsa_padding(ctx_verify, RSA_PKCS1_PADDING) <= 0)
			{
				throw std::runtime_error("error set rsa padding");
				EVP_PKEY_CTX_free(ctx_verify);
				return 0;
			}
		}
		DECODE_UINT32(actual_classical_sig_len, sig);
		/* classical schemes can't sign arbitrarily large data; we hash it first */
		switch (oqs_key->s->claimed_nist_level)
		{
		case 1:
		case 2:
			classical_md = EVP_sha256();
			digest_len = SHA256_DIGEST_LENGTH;
			SHA256(tbs, tbslen, (unsigned char*) &digest);
			break;
		//case 2:
		case 3:
		case 4:
			classical_md = EVP_sha384();
			digest_len = SHA384_DIGEST_LENGTH;
			SHA384(tbs, tbslen, (unsigned char*) &digest);
			break;
		//case 4:
		case 5:
		default:
			classical_md = EVP_sha512();
			digest_len = SHA512_DIGEST_LENGTH;
			SHA512(tbs, tbslen, (unsigned char*) &digest);
			break;
		}
		if (EVP_PKEY_CTX_set_signature_md(ctx_verify, classical_md) <= 0)
		{
			throw std::runtime_error("error set verify md");
			return 0;
		}
		if (EVP_PKEY_verify(ctx_verify, sig + SIZE_OF_UINT32, actual_classical_sig_len, digest, digest_len) <= 0)
		{
			throw std::runtime_error("error classic verify");
			return 0;
		}
		classical_sig_len = SIZE_OF_UINT32 + actual_classical_sig_len;
		index += classical_sig_len;
		EVP_PKEY_CTX_free(ctx_verify);
	}

	if (OQS_SIG_verify(oqs_key->s, tbs, tbslen, sig + index, siglen - classical_sig_len, oqs_key->pubkey) != OQS_SUCCESS)
	{
		throw std::runtime_error("error oqsverify");
		return 0;
	}

	return 1;
}
