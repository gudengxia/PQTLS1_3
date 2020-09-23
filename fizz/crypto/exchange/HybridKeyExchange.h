#include <fizz/crypto/exchange/KeyExchange.h>
#include <iostream>
using namespace std;

namespace fizz
{
template <class T1, class T2> class HybridKeyExchange : public KeyExchange
{
  public:
    HybridKeyExchange(unsigned int v);
    ~HybridKeyExchange() override
    {    
    }
    void generateKeyPair() override;
    std::unique_ptr<folly::IOBuf> getKeyShare() const override;
    std::unique_ptr<folly::IOBuf> generateSharedSecret(folly::ByteRange keyShare) override;

    void setServer(bool is = false) override
    {
      isServer = is;
      kex1.setServer(is);
      kex2.setServer(is);
    }
  private:
    unsigned int offset;
    bool isServer;
    T1 kex1;
    T2 kex2;
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


   template <class T1, class T2> HybridKeyExchange<T1, T2>::HybridKeyExchange(unsigned int v)
{
  offset = v;
}

   template <class T1, class T2> void HybridKeyExchange<T1, T2>::generateKeyPair()
{
  kex1.generateKeyPair();
  kex2.generateKeyPair();
}

   template <class T1, class T2> std::unique_ptr<IOBuf> HybridKeyExchange<T1, T2>::getKeyShare() const
{
  auto keyShare1 = kex1.getKeyShare();
  auto keyShare2 = kex2.getKeyShare();
  auto len1 = keyShare1->length(); 
  auto len2 = keyShare2->length();
  
  auto keyShare = IOBuf::create(len1+len2);
  keyShare->append(len1+len2);
  memcpy(keyShare->writableData(), keyShare1->data(), len1);
  memcpy(keyShare->writableData() + len1, keyShare2->data(), len2);
  //cout<<keyShare->length()<<endl;
  
  return keyShare;
}

   template <class T1, class T2> std::unique_ptr<folly::IOBuf> HybridKeyExchange<T1, T2>::generateSharedSecret(folly::ByteRange keyShare)
{
  auto len = offset;
  auto buf1 = IOBuf::create(len);
  buf1->append(len);
  memcpy(buf1->writableData(), keyShare.data(), len);

  len = keyShare.size() - offset;
  auto buf2 = IOBuf::create(len);
  buf2->append(len);
  memcpy(buf2->writableData(), keyShare.data() + offset, len);
  //cout<<"buf2->length()="<<buf2->length()<<endl;
  auto key1 = kex1.generateSharedSecret(buf1->coalesce());
  auto key2 = kex2.generateSharedSecret(buf2->coalesce());
  
  auto key = IOBuf::create(key1->length() + key2->length());
  key->append(key1->length() + key2->length());
  memcpy(key->writableData(), key1->data(), key1->length());
  memcpy(key->writableData()+key1->length(), key2->data(), key2->length());
  return key;
}
}//fzhang
