/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#include <fizz/crypto/openssl/OpenSSLKeyUtils.h>
#include <folly/io/IOBuf.h>
#include <folly/lang/Assume.h>

namespace fizz {

namespace detail {

std::unique_ptr<folly::IOBuf> ecSign(
    folly::ByteRange data,
    const folly::ssl::EvpPkeyUniquePtr& pkey,
    int hashNid);

void ecVerify(
    folly::ByteRange data,
    folly::ByteRange signature,
    const folly::ssl::EvpPkeyUniquePtr& pkey,
    int hashNid);

#if FIZZ_OPENSSL_HAS_ED25519
std::unique_ptr<folly::IOBuf> edSign(
    folly::ByteRange data,
    const folly::ssl::EvpPkeyUniquePtr& pkey);

void edVerify(
    folly::ByteRange data,
    folly::ByteRange signature,
    const folly::ssl::EvpPkeyUniquePtr& pkey);
#endif

std::unique_ptr<folly::IOBuf> rsaPssSign(
    folly::ByteRange data,
    const folly::ssl::EvpPkeyUniquePtr& pkey,
    int hashNid);

void rsaPssVerify(
    folly::ByteRange data,
    folly::ByteRange signature,
    const folly::ssl::EvpPkeyUniquePtr& pkey,
    int hashNid);

/*------------------------fzhang start--------------------------*/
std::unique_ptr<folly::IOBuf>pqSign( 
    folly::ByteRange data,
    const folly::ssl::EvpPkeyUniquePtr& pkey);

void pqVerify(
    folly::ByteRange data,
    folly::ByteRange signature,
    const folly::ssl::EvpPkeyUniquePtr& pkey); 
/*------------------------fzhang end----------------------------*/   
} // namespace detail

template <SignatureScheme Scheme>
struct SigAlg {};

template <>
struct SigAlg<SignatureScheme::rsa_pss_sha256> {
  static constexpr int HashNid = NID_sha256;
  static constexpr KeyType type = KeyType::RSA;
};

template <>
struct SigAlg<SignatureScheme::ecdsa_secp256r1_sha256> {
  static constexpr int HashNid = NID_sha256;
  static constexpr KeyType type = KeyType::P256;
};

template <>
struct SigAlg<SignatureScheme::ecdsa_secp384r1_sha384> {
  static constexpr int HashNid = NID_sha384;
  static constexpr KeyType type = KeyType::P384;
};

template <>
struct SigAlg<SignatureScheme::ecdsa_secp521r1_sha512> {
  static constexpr int HashNid = NID_sha512;
  static constexpr KeyType type = KeyType::P521;
};

/*SigAlg defined by fzhang ---start---*/
template <>
struct SigAlg<SignatureScheme::dilithium2> {
  static constexpr int HashNid = NID_sha512;
  static constexpr KeyType type = KeyType::Dilithium2;
};
template <>
struct SigAlg<SignatureScheme::p256_dilithium2> {
  static constexpr int HashNid = NID_sha512;
  static constexpr KeyType type = KeyType::P256_Dilithium2;
};

template <>
struct SigAlg<SignatureScheme::dilithium3> {
  static constexpr int HashNid = NID_sha512;
  static constexpr KeyType type = KeyType::Dilithium3;
};
template <>
struct SigAlg<SignatureScheme::p256_dilithium3> {
  static constexpr int HashNid = NID_sha512;
  static constexpr KeyType type = KeyType::P256_Dilithium3;
};

template <>
struct SigAlg<SignatureScheme::dilithium4> {
  static constexpr int HashNid = NID_sha512;
  static constexpr KeyType type = KeyType::Dilithium4;
};
template <>
struct SigAlg<SignatureScheme::p384_dilithium4> {
  static constexpr int HashNid = NID_sha512;
  static constexpr KeyType type = KeyType::P384_Dilithium4;
};

template <>
struct SigAlg<SignatureScheme::mulan> {
  static constexpr int HashNid = NID_sha512;
  static constexpr KeyType type = KeyType::Mulan;
};
template <>
struct SigAlg<SignatureScheme::p256_mulan> {
  static constexpr int HashNid = NID_sha512;
  static constexpr KeyType type = KeyType::P256_Mulan;
};

template <>
struct SigAlg<SignatureScheme::aigis> {
  static constexpr int HashNid = NID_sha512;
  static constexpr KeyType type = KeyType::Aigis;
};
template <>
struct SigAlg<SignatureScheme::p256_aigis> {
  static constexpr int HashNid = NID_sha512;
  static constexpr KeyType type = KeyType::P256_Aigis;
};

template <>
struct SigAlg<SignatureScheme::falcon512> {
  static constexpr int HashNid = NID_sha512;
  static constexpr KeyType type = KeyType::Falcon512;
};
template <>
struct SigAlg<SignatureScheme::p256_falcon512> {
  static constexpr int HashNid = NID_sha512;
  static constexpr KeyType type = KeyType::P256_Falcon512;
};

template <>
struct SigAlg<SignatureScheme::falcon1024> {
  static constexpr int HashNid = NID_sha512;
  static constexpr KeyType type = KeyType::Falcon1024;
};
template <>
struct SigAlg<SignatureScheme::p521_falcon1024> {
  static constexpr int HashNid = NID_sha512;
  static constexpr KeyType type = KeyType::P521_Falcon1024;
};
/*SigAlg defined by fzhang ---end---*/

template <KeyType Type>
template <SignatureScheme Scheme>
inline std::unique_ptr<folly::IOBuf> OpenSSLSignature<Type>::sign(
    folly::ByteRange data) const {
  static_assert(
      SigAlg<Scheme>::type == Type, "Called with mismatched type and scheme");
  switch (Type) {
    case KeyType::P256:
    case KeyType::P384:
    case KeyType::P521:
      return detail::ecSign(data, pkey_, SigAlg<Scheme>::HashNid);
    case KeyType::RSA:
      return detail::rsaPssSign(data, pkey_, SigAlg<Scheme>::HashNid);
    /*--------------fzhang start---------------*/
    case KeyType::Dilithium2:
    case KeyType::P256_Dilithium2:
    case KeyType::Dilithium3:
    case KeyType::P256_Dilithium3:
    case KeyType::Dilithium4:
    case KeyType::P384_Dilithium4:
    case KeyType::Mulan:
    case KeyType::P256_Mulan:
    case KeyType::Aigis:
    case KeyType::P256_Aigis:
    case KeyType::Falcon512:
    case KeyType::P256_Falcon512:
    case KeyType::Falcon1024:
    case KeyType::P521_Falcon1024:
      return detail::pqSign(data, pkey_);
    /*--------------fzhang end  ---------------*/
  }
  folly::assume_unreachable();
}

// Use template specialization for Ed25519 because the algorithm doesn't have a
// HashNid and therefore its SigAlg struct would be missing a member that is
// used in the generic template
#if FIZZ_OPENSSL_HAS_ED25519
template <>
template <>
inline std::unique_ptr<folly::IOBuf>
OpenSSLSignature<KeyType::ED25519>::sign<SignatureScheme::ed25519>(
    folly::ByteRange data) const {
  return detail::edSign(data, pkey_);
#else
template <>
inline std::unique_ptr<folly::IOBuf>
OpenSSLSignature<KeyType::ED25519>::sign<SignatureScheme::ed25519>(
    folly::ByteRange) const {
  throw std::runtime_error("Ed25519 not supported");
#endif
}

template <KeyType Type>
template <SignatureScheme Scheme>
inline void OpenSSLSignature<Type>::verify(
    folly::ByteRange data,
    folly::ByteRange signature) const {
  switch (Type) {
    case KeyType::P256:
    case KeyType::P384:
    case KeyType::P521:
      return detail::ecVerify(data, signature, pkey_, SigAlg<Scheme>::HashNid);
    case KeyType::RSA:
      return detail::rsaPssVerify(
          data, signature, pkey_, SigAlg<Scheme>::HashNid);
    /*--------------fzhang start---------------*/
    case KeyType::Dilithium2:
    case KeyType::P256_Dilithium2:
    case KeyType::Dilithium3:
    case KeyType::P256_Dilithium3:
    case KeyType::Dilithium4:
    case KeyType::P384_Dilithium4:
    case KeyType::Mulan:
    case KeyType::P256_Mulan:
    case KeyType::Aigis:
    case KeyType::P256_Aigis:
    case KeyType::Falcon512:
    case KeyType::P256_Falcon512:
    case KeyType::Falcon1024:
    case KeyType::P521_Falcon1024:
      return detail::pqVerify(data, signature, pkey_);
    /*--------------fzhang end  ---------------*/
  }
  folly::assume_unreachable();
}

// Use template specialization for Ed25519 because the algorithm doesn't have a
// HashNid and therefore its SigAlg struct would be missing a member that is
// used in the generic template
#if FIZZ_OPENSSL_HAS_ED25519
template <>
template <>
inline void
OpenSSLSignature<KeyType::ED25519>::verify<SignatureScheme::ed25519>(
    folly::ByteRange data,
    folly::ByteRange signature) const {
  return detail::edVerify(data, signature, pkey_);
#else
template <>
inline void OpenSSLSignature<KeyType::ED25519>::verify<
    SignatureScheme::ed25519>(folly::ByteRange, folly::ByteRange) const {
  throw std::runtime_error("Ed25519 not supported");
#endif
}

template <>
inline void OpenSSLSignature<KeyType::P256>::setKey(
    folly::ssl::EvpPkeyUniquePtr pkey) {
  detail::validateECKey(pkey, NID_X9_62_prime256v1);
  pkey_ = std::move(pkey);
}

template <>
inline void OpenSSLSignature<KeyType::P384>::setKey(
    folly::ssl::EvpPkeyUniquePtr pkey) {
  detail::validateECKey(pkey, NID_secp384r1);
  pkey_ = std::move(pkey);
}

template <>
inline void OpenSSLSignature<KeyType::P521>::setKey(
    folly::ssl::EvpPkeyUniquePtr pkey) {
  detail::validateECKey(pkey, NID_secp521r1);
  pkey_ = std::move(pkey);
}

#if FIZZ_OPENSSL_HAS_ED25519
template <>
inline void OpenSSLSignature<KeyType::ED25519>::setKey(
    folly::ssl::EvpPkeyUniquePtr pkey) {
  detail::validateEdKey(pkey, NID_ED25519);
  pkey_ = std::move(pkey);
#else
inline void OpenSSLSignature<KeyType::ED25519>::setKey(
    folly::ssl::EvpPkeyUniquePtr) {
  throw std::runtime_error("Ed25519 not supported");
#endif
}

template <>
inline void OpenSSLSignature<KeyType::RSA>::setKey(
    folly::ssl::EvpPkeyUniquePtr pkey) {
  if (EVP_PKEY_id(pkey.get()) != EVP_PKEY_RSA) {
    throw std::runtime_error("key not rsa");
  }
  pkey_ = std::move(pkey);
}

/*setkey defined by fzhang ---start---*/
template <>
inline void OpenSSLSignature<KeyType::Dilithium2>::setKey(
    folly::ssl::EvpPkeyUniquePtr pkey) {
  if (EVP_PKEY_id(pkey.get()) != EVP_PKEY_DILITHIUM2) {
    throw std::runtime_error("key not dilithium2");
  }
  pkey_ = std::move(pkey);
} 
template <>
inline void OpenSSLSignature<KeyType::P256_Dilithium2>::setKey(
    folly::ssl::EvpPkeyUniquePtr pkey) {
  if (EVP_PKEY_id(pkey.get()) != EVP_PKEY_P256_DILITHIUM2) {
    throw std::runtime_error("key not p256_dilithium2");
  }
  pkey_ = std::move(pkey);
} 

template <>
inline void OpenSSLSignature<KeyType::Dilithium3>::setKey(
    folly::ssl::EvpPkeyUniquePtr pkey) {
  if (EVP_PKEY_id(pkey.get()) != EVP_PKEY_DILITHIUM3) {
    throw std::runtime_error("key not dilithium3");
  }
  pkey_ = std::move(pkey);
} 
template <>
inline void OpenSSLSignature<KeyType::P256_Dilithium3>::setKey(
    folly::ssl::EvpPkeyUniquePtr pkey) {
  if (EVP_PKEY_id(pkey.get()) != EVP_PKEY_P256_DILITHIUM3) {
    throw std::runtime_error("key not p256_dilithium3");
  }
  pkey_ = std::move(pkey);
} 

template <>
inline void OpenSSLSignature<KeyType::Dilithium4>::setKey(
    folly::ssl::EvpPkeyUniquePtr pkey) {
  if (EVP_PKEY_id(pkey.get()) != EVP_PKEY_DILITHIUM4) {
    throw std::runtime_error("key not dilithium4");
  }
  pkey_ = std::move(pkey);
} 
template <>
inline void OpenSSLSignature<KeyType::P384_Dilithium4>::setKey(
    folly::ssl::EvpPkeyUniquePtr pkey) {
  if (EVP_PKEY_id(pkey.get()) != EVP_PKEY_P384_DILITHIUM4) {
    throw std::runtime_error("key not p384_dilithium4");
  }
  pkey_ = std::move(pkey);
}

template <>
inline void OpenSSLSignature<KeyType::Mulan>::setKey(
    folly::ssl::EvpPkeyUniquePtr pkey) {
  if (EVP_PKEY_id(pkey.get()) != EVP_PKEY_MULAN) {
    throw std::runtime_error("key not mulan");
  }
  pkey_ = std::move(pkey);
} 
template <>
inline void OpenSSLSignature<KeyType::P256_Mulan>::setKey(
    folly::ssl::EvpPkeyUniquePtr pkey) {
  if (EVP_PKEY_id(pkey.get()) != EVP_PKEY_P256_MULAN) {
    throw std::runtime_error("key not p256_mulan");
  }
  pkey_ = std::move(pkey);
}

template <>
inline void OpenSSLSignature<KeyType::Aigis>::setKey(
    folly::ssl::EvpPkeyUniquePtr pkey) {
  if (EVP_PKEY_id(pkey.get()) != EVP_PKEY_AIGIS) {
    throw std::runtime_error("key not aigis");
  }
  pkey_ = std::move(pkey);
}
template <>
inline void OpenSSLSignature<KeyType::P256_Aigis>::setKey(
    folly::ssl::EvpPkeyUniquePtr pkey) {
  if (EVP_PKEY_id(pkey.get()) != EVP_PKEY_P256_AIGIS) {
    throw std::runtime_error("key not p256_aigis");
  }
  pkey_ = std::move(pkey);
}

template <>
inline void OpenSSLSignature<KeyType::Falcon512>::setKey(
    folly::ssl::EvpPkeyUniquePtr pkey) {
  if (EVP_PKEY_id(pkey.get()) != EVP_PKEY_FALCON512) {
    throw std::runtime_error("key not falcon512");
  }
  pkey_ = std::move(pkey);
}
template <>
inline void OpenSSLSignature<KeyType::P256_Falcon512>::setKey(
    folly::ssl::EvpPkeyUniquePtr pkey) {
  if (EVP_PKEY_id(pkey.get()) != EVP_PKEY_P256_FALCON512) {
    throw std::runtime_error("key not p256_falcon512");
  }
  pkey_ = std::move(pkey);
}
template <>
inline void OpenSSLSignature<KeyType::Falcon1024>::setKey(
    folly::ssl::EvpPkeyUniquePtr pkey) {
  if (EVP_PKEY_id(pkey.get()) != EVP_PKEY_FALCON1024) {
    throw std::runtime_error("key not falcon1024");
  }
  pkey_ = std::move(pkey);
}
template <>
inline void OpenSSLSignature<KeyType::P521_Falcon1024>::setKey(
    folly::ssl::EvpPkeyUniquePtr pkey) {
  if (EVP_PKEY_id(pkey.get()) != EVP_PKEY_P521_FALCON1024) {
    throw std::runtime_error("key not p521_falcon1024");
  }
  pkey_ = std::move(pkey);
} 
/*setkey defined by fzhang ---end---*/
} // namespace fizz
