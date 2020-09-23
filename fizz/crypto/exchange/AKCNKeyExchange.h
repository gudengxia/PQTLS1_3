#include <fizz/crypto/exchange/KeyExchange.h>
#include <folly/Range.h>
#include <folly/io/IOBuf.h>
#include <iostream>
#include <cstdlib>
using namespace folly;

/*extern "C"
{
int pqcrystals_kyber768_90s_avx2_keypair(unsigned char* pk, unsigned char* sk);
int pqcrystals_kyber768_90s_avx2_enc(unsigned char* ct, unsigned char* ss, const unsigned char* pk);
int pqcrystals_kyber768_90s_avx2_dec(unsigned char* ss, const unsigned char* ct, const unsigned char* sk);
}*/
#define crypto_kem_keypair(pk, sk) mkem_keygen(pk, sk)
#define crypto_kem_enc(ct, ss, pk) mkem_enc(pk, ss, ct)
#define crypto_kem_dec(ss, ct, sk) mkem_dec(sk, ct, ss)

int mkem_keygen( unsigned char *pk, unsigned char *sk);
int mkem_enc(const unsigned char *pk, unsigned char *ss, unsigned char *ct);
int mkem_dec(const unsigned char *sk, const unsigned char *ct, unsigned char *ss);
/*int crypto_kem_keypair(unsigned char *pk, unsigned char *sk);
int crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
int crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);*/

namespace fizz
{
const int AKCN_PK_LEN = 896;  //1184; //896
const int AKCN_SK_LEN = 1152; //2400; //1152(2208)
const int AKCN_CT_LEN = 992;  //1088; //992
const int AKCN_KEY_LEN = 32; 
class AKCNKeyExchange : public KeyExchange
{
public:
	AKCNKeyExchange();
	~AKCNKeyExchange() override
	{    	
   		if(isServer)
		{
			SrvInfo *p = (SrvInfo*)info;
			delete p;
		}
		else
		{
			CltInfo *p = (CltInfo*)info;
			delete p;
		}
       	}
	void generateKeyPair() override;
	std::unique_ptr<folly::IOBuf> getKeyShare() const override;
	std::unique_ptr<folly::IOBuf> generateSharedSecret(folly::ByteRange keyShare) override;

	void setServer(bool is = false) override{isServer = is;}
private:
	typedef struct CltInfo
	{
		uint8_t sk[AKCN_SK_LEN];
		uint8_t pk[AKCN_PK_LEN];
	}CltInfo;
	typedef struct SrvInfo
	{
		//uint8_t pk[992];
		uint8_t sendb[AKCN_CT_LEN];
		uint8_t key[AKCN_KEY_LEN];
	}SrvInfo;
	//OQS_KEM *alg;
	size_t sk_len, pk_len, ct_len, key_len;
	void* info;
	bool isServer;
};
}
