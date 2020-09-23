#include <fizz/crypto/exchange/KeyExchange.h>
#include <fizz/crypto/exchange/OQSKeyExchange-inl.h>
#include <oqs/oqs.h>
#include <folly/Range.h>
#include <folly/io/IOBuf.h>
#include <iostream>
#include <cstdlib>
using namespace folly;
namespace fizz
{
template <class T> class OQSKeyExchange : public KeyExchange
{
public:
	OQSKeyExchange();
	~OQSKeyExchange() override
	{
        	if(isServer && info)
        	{
            		SrvInfo* p = (SrvInfo*)info;
            		delete p;
        	}

        	if(!isServer && info)
        	{
            		CltInfo* p = (CltInfo*)info;
            		delete p;
        	}
			OQS_KEM_free(alg);
    }
	void generateKeyPair() override;
	std::unique_ptr<folly::IOBuf> getKeyShare() const override;
	std::unique_ptr<folly::IOBuf> generateSharedSecret(folly::ByteRange keyShare) override;

	void setServer(bool is = false) override{isServer = is;}
private:
	typedef struct CltInfo
	{
		std::unique_ptr<uint8_t[]> sk;
		std::unique_ptr<uint8_t[]> pk;
	}CltInfo;
	typedef struct SrvInfo
	{
		std::unique_ptr<uint8_t[]> sendb;
		std::unique_ptr<uint8_t[]> key;
	}SrvInfo;
	OQS_KEM *alg;
	//size_t sk_len, pk_len, ct_len, key_len;
	void* info;
	bool isServer;
};

/*void Print(const unsigned char* p, int len)
{
	int i;
	std::cout<<"*******************************"<<std::ends;
	std::cout<<"*******************************"<<std::endl;
	for(i = 0; i < len; i++)
		std::cout<<std::hex<<(unsigned int)p[i]<<std::ends;
	std::cout<<std::endl;
	std::cout<<"*******************************"<<std::ends;
	std::cout<<"*******************************"<<std::endl;
	std::cout<<std::endl;
	std::cout<<std::endl;
	}*/


template <class T> OQSKeyExchange<T>::OQSKeyExchange()
{
	if(T::OQS_ID >= OQS_KEM_alg_count())
	{
		throw std::runtime_error("The OQS_ID is error!");
	}

	const char* alg_name = OQS_KEM_alg_identifier(T::OQS_ID);
	if(OQS_KEM_alg_is_enabled(alg_name) != 1)
	{
		throw std::runtime_error("The algorithm is not enabled in liboqs now!");
	}

	alg = OQS_KEM_new(alg_name);
	if(!alg)
	{
		throw std::runtime_error("The algorithm is initilized error in liboqs!");
		
	}
}

template <class T> void OQSKeyExchange<T>::generateKeyPair()
{
	if(isServer == true)
	{
		SrvInfo* p = new SrvInfo();
		p->sendb.reset(new uint8_t[alg->length_ciphertext]);
		p->key.reset(new uint8_t[alg->length_shared_secret]);
		info = (void*)p;
		return;
	}

	CltInfo* p = new CltInfo();
	p->pk.reset(new uint8_t[alg->length_public_key]);
	p->sk.reset(new uint8_t[alg->length_secret_key]);
	OQS_STATUS succ = OQS_KEM_keypair(alg, p->pk.get(), p->sk.get());
	if(succ != OQS_SUCCESS)
	{
		throw std::runtime_error("OQS generate keypairs error!");
	}
	info = (void*)p;
}

template <class T> std::unique_ptr<IOBuf> OQSKeyExchange<T>::getKeyShare() const
{
	if(isServer == true)
	{
		return IOBuf::copyBuffer(((SrvInfo*)info)->sendb.get(), alg->length_ciphertext);
	}

	CltInfo* p = (CltInfo*)info;
	return IOBuf::copyBuffer(p->pk.get(), alg->length_public_key);
}

template <class T> std::unique_ptr<folly::IOBuf> OQSKeyExchange<T>::generateSharedSecret(folly::ByteRange keyShare)
{
	OQS_STATUS succ;
	//std::cout<<"oqs keyshare size:"<<keyShare.size()<<std::endl;
	if(isServer == true)
	{
		SrvInfo* p = (SrvInfo*)info;
		succ = OQS_KEM_encaps(alg, p->sendb.get(), p->key.get(), keyShare.data());
		if(succ != OQS_SUCCESS)
		{
			throw std::runtime_error("OQS encaps error!");
		}
		//std::cout<<"server key:"<<std::endl;
		//Print(p->key, alg->length_shared_secret);
		return IOBuf::copyBuffer(p->key.get(), alg->length_shared_secret);
	}

	std::unique_ptr<uint8_t[]> key(new uint8_t[alg->length_shared_secret]);
	succ = OQS_KEM_decaps(alg, key.get(), keyShare.data(), ((CltInfo*)info)->sk.get());
	if(succ != OQS_SUCCESS)
	{
		throw std::runtime_error("OQS decaps error!");
	}
	//std::cout<<"client key:"<<std::endl;
	//Print(key.get(), 32);
	return IOBuf::copyBuffer(key.get(), alg->length_shared_secret);
}
}
