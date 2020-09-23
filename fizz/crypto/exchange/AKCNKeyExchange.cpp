#include <fizz/crypto/exchange/AKCNKeyExchange.h>

namespace fizz
{
//int mkem_keygen( unsigned char *pk, unsigned char *sk);
//int mkem_enc(unsigned char *pk, unsigned char *ss, unsigned char *ct);
//int mkem_dec(unsigned char *sk, unsigned char *ct, unsigned char *ss);
AKCNKeyExchange::AKCNKeyExchange()
{
	sk_len = AKCN_SK_LEN;
	pk_len = AKCN_PK_LEN;
	ct_len = AKCN_CT_LEN;
	key_len = AKCN_KEY_LEN;
}

void AKCNKeyExchange::generateKeyPair()
{
	if(isServer == true)
	{
		SrvInfo* p = new SrvInfo();
		info = (void*)p;
		return;
	}

	CltInfo* p = new CltInfo();
	int ret = crypto_kem_keypair(p->pk, p->sk);
	//int ret = mkem_keygen(p->pk, p->sk);
	if(ret != 0)
	{
		throw std::runtime_error("OQS generate keypairs error!");
	}
	info = (void*)p;
}

std::unique_ptr<IOBuf> AKCNKeyExchange::getKeyShare() const
{
	if(isServer == true)
	{
		return IOBuf::copyBuffer(((SrvInfo*)info)->sendb, ct_len);
	}

	CltInfo* p = (CltInfo*)info;
	return IOBuf::copyBuffer(p->pk, pk_len);
}

std::unique_ptr<folly::IOBuf> AKCNKeyExchange::generateSharedSecret(folly::ByteRange keyShare)
{
	int ret;
	//std::cout<<"oqs keyshare size:"<<keyShare.size()<<std::endl;
	if(isServer == true)
	{
		SrvInfo* p = (SrvInfo*)info;
		ret = crypto_kem_enc(p->sendb, p->key, keyShare.data());
		//ret = mkem_enc(p->key, keyShare.data(), p->sendb);
		if(ret != 0)
		{
			throw std::runtime_error("AKCN encaps error!");
		}
		//std::cout<<"server key:"<<std::endl;
		//Print(p->key, alg->length_shared_secret);
		return IOBuf::copyBuffer(p->key, key_len);
	}

	std::unique_ptr<uint8_t[]> key(new uint8_t[key_len]);
	ret = crypto_kem_dec(key.get(), keyShare.data(), ((CltInfo*)info)->sk);
	//ret = mkem_dec( ((CltInfo*)info)->sk, keyShare.data(), key.get());
	if(ret != 0)
	{
		throw std::runtime_error("AKCN decaps error!");
	}
	//std::cout<<"client key:"<<std::endl;
	//Print(key.get(), 32);
	return IOBuf::copyBuffer(key.get(), key_len);
}
}
