/*
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#include <fizz/protocol/Certificate.h>
#include <openssl/bio.h>

namespace {
int getCurveName(EVP_PKEY* key) {
  auto ecKey = EVP_PKEY_get0_EC_KEY(key);
  if (ecKey) {
    return EC_GROUP_get_curve_name(EC_KEY_get0_group(ecKey));
  }
  return 0;
}
} // namespace

namespace fizz {

Buf CertUtils::prepareSignData(
    CertificateVerifyContext context,
    folly::ByteRange toBeSigned) {
  static constexpr folly::StringPiece kServerLabel =
      "TLS 1.3, server CertificateVerify";
  static constexpr folly::StringPiece kClientLabel =
      "TLS 1.3, client CertificateVerify";
  static constexpr folly::StringPiece kAuthLabel = "Exported Authenticator";
  static constexpr folly::StringPiece kDelegatedCredLabel =
      "TLS, server delegated credentials";
  static constexpr size_t kSigPrefixLen = 64;
  static constexpr uint8_t kSigPrefix = 32;

  folly::StringPiece label;
  if (context == CertificateVerifyContext::Server) {
    label = kServerLabel;
  } else if (context == CertificateVerifyContext::Client) {
    label = kClientLabel;
  } else if (context == CertificateVerifyContext::Authenticator) {
    label = kAuthLabel;
  } else {
    label = kDelegatedCredLabel;
  }

  size_t sigDataLen = kSigPrefixLen + label.size() + 1 + toBeSigned.size();
  auto buf = folly::IOBuf::create(sigDataLen);
  buf->append(sigDataLen);

  // Place bytes in the right order.
  size_t offset = 0;
  memset(buf->writableData(), kSigPrefix, kSigPrefixLen);
  offset += kSigPrefixLen;
  memcpy(buf->writableData() + offset, label.data(), label.size());
  offset += label.size();
  memset(buf->writableData() + offset, 0, 1);
  offset += 1;
  memcpy(buf->writableData() + offset, toBeSigned.data(), toBeSigned.size());
  return buf;
}

CertificateMsg CertUtils::getCertMessage(
    const std::vector<folly::ssl::X509UniquePtr>& certs,
    Buf certificateRequestContext) {
  // compose the cert entry list
  std::vector<CertificateEntry> entries;
  for (const auto& cert : certs) {
    CertificateEntry entry;
    int len = i2d_X509(cert.get(), nullptr);
    if (len < 0) {
      throw std::runtime_error("Error computing length");
    }
    entry.cert_data = folly::IOBuf::create(len);
    auto dataPtr = entry.cert_data->writableData();
    len = i2d_X509(cert.get(), &dataPtr);
    if (len < 0) {
      throw std::runtime_error("Error converting cert to DER");
    }
    entry.cert_data->append(len);
    // TODO: add any extensions.
    entries.push_back(std::move(entry));
  }

  CertificateMsg msg;
  msg.certificate_request_context = std::move(certificateRequestContext);
  msg.certificate_list = std::move(entries);
  return msg;
}

std::unique_ptr<PeerCert> CertUtils::makePeerCert(Buf certData) {
  if (certData->empty()) {
    throw std::runtime_error("empty peer cert");
  }

  auto range = certData->coalesce();
  const unsigned char* begin = range.data();
  folly::ssl::X509UniquePtr cert(d2i_X509(nullptr, &begin, range.size()));
  if (!cert) {
    throw std::runtime_error("could not read cert");
  }
  if (begin != range.data() + range.size()) {
    VLOG(1) << "Did not read to end of certificate";
  }
  return makePeerCert(std::move(cert));
}

std::unique_ptr<PeerCert> CertUtils::makePeerCert(
    folly::ssl::X509UniquePtr cert) {
  folly::ssl::EvpPkeyUniquePtr pubKey(X509_get_pubkey(cert.get()));
  if (!pubKey) {
    throw std::runtime_error("couldn't get pubkey from peer cert");
  }
  const auto pkeyID = EVP_PKEY_id(pubKey.get());
  if (pkeyID == EVP_PKEY_RSA) {
    return std::make_unique<PeerCertImpl<KeyType::RSA>>(std::move(cert));
  } else if (pkeyID == EVP_PKEY_EC) {
    switch (getCurveName(pubKey.get())) {
      case NID_X9_62_prime256v1:
        return std::make_unique<PeerCertImpl<KeyType::P256>>(std::move(cert));
      case NID_secp384r1:
        return std::make_unique<PeerCertImpl<KeyType::P384>>(std::move(cert));
      case NID_secp521r1:
        return std::make_unique<PeerCertImpl<KeyType::P521>>(std::move(cert));
      default:
        break;
    }
  }
#if FIZZ_OPENSSL_HAS_ED25519
  else if (pkeyID == EVP_PKEY_ED25519) {
    return std::make_unique<PeerCertImpl<KeyType::ED25519>>(std::move(cert));
  }
#endif
/*----------------------------------fzhang start----------------------------------*/ 
  else {
    switch(pkeyID)
    {
      case EVP_PKEY_DILITHIUM2:
        return std::make_unique<PeerCertImpl<KeyType::Dilithium2>>(std::move(cert));
      case EVP_PKEY_P256_DILITHIUM2:
        return std::make_unique<PeerCertImpl<KeyType::P256_Dilithium2>>(std::move(cert));
      case EVP_PKEY_DILITHIUM3:
        return std::make_unique<PeerCertImpl<KeyType::Dilithium3>>(std::move(cert));
      case EVP_PKEY_P256_DILITHIUM3:
        return std::make_unique<PeerCertImpl<KeyType::P256_Dilithium3>>(std::move(cert));
      case EVP_PKEY_DILITHIUM4:
        return std::make_unique<PeerCertImpl<KeyType::Dilithium4>>(std::move(cert));
      case EVP_PKEY_P384_DILITHIUM4:
        return std::make_unique<PeerCertImpl<KeyType::P384_Dilithium4>>(std::move(cert));
      case EVP_PKEY_MULAN:
        return std::make_unique<PeerCertImpl<KeyType::Mulan>>(std::move(cert));
      case EVP_PKEY_P256_MULAN:
        return std::make_unique<PeerCertImpl<KeyType::P256_Mulan>>(std::move(cert));
      case EVP_PKEY_AIGIS:
        return std::make_unique<PeerCertImpl<KeyType::Aigis>>(std::move(cert));
      case EVP_PKEY_P256_AIGIS:
        return std::make_unique<PeerCertImpl<KeyType::P256_Aigis>>(std::move(cert));
      case EVP_PKEY_FALCON512:
        return std::make_unique<PeerCertImpl<KeyType::Falcon512>>(std::move(cert));
      case EVP_PKEY_P256_FALCON512:
        return std::make_unique<PeerCertImpl<KeyType::P256_Falcon512>>(std::move(cert));
      case EVP_PKEY_FALCON1024:
        return std::make_unique<PeerCertImpl<KeyType::Falcon1024>>(std::move(cert));
      case EVP_PKEY_P521_FALCON1024:
        return std::make_unique<PeerCertImpl<KeyType::P521_Falcon1024>>(std::move(cert));
    }
  }
  /*----------------------------------fzhang end----------------------------------*/ 
  throw std::runtime_error("unknown peer cert type");
}

folly::ssl::EvpPkeyUniquePtr CertUtils::readPrivateKeyFromBuffer(
    std::string keyData,
    char* password) {
  folly::ssl::BioUniquePtr b(BIO_new_mem_buf(
      const_cast<void*>( // needed by openssl 1.0.2d at least
          reinterpret_cast<const void*>(keyData.data())),
      keyData.size()));

  if (!b) {
    throw std::runtime_error("failed to create BIO");
  }

  folly::ssl::EvpPkeyUniquePtr key(
      PEM_read_bio_PrivateKey(b.get(), nullptr, nullptr, password));

  if (!key) {
    throw std::runtime_error("Failed to read key");
  }

  return key;
}

namespace {

std::unique_ptr<SelfCert> selfCertFromDataInternal(
    std::string certData,
    std::string keyData,
    char* password,
    const std::vector<std::shared_ptr<CertificateCompressor>>& compressors) {
  auto certs = folly::ssl::OpenSSLCertUtils::readCertsFromBuffer(
      folly::StringPiece(certData));
  if (certs.empty()) {
    throw std::runtime_error("no certificates read");
  }

  auto key = CertUtils::readPrivateKeyFromBuffer(std::move(keyData), password);

  return CertUtils::makeSelfCert(std::move(certs), std::move(key), compressors);
}

} // namespace

std::unique_ptr<SelfCert> CertUtils::makeSelfCert(
    std::string certData,
    std::string keyData,
    const std::vector<std::shared_ptr<CertificateCompressor>>& compressors) {
  return selfCertFromDataInternal(
      std::move(certData), std::move(keyData), nullptr, compressors);
}

std::unique_ptr<SelfCert> CertUtils::makeSelfCert(
    std::string certData,
    std::string encryptedKeyData,
    std::string password,
    const std::vector<std::shared_ptr<CertificateCompressor>>& compressors) {
  return selfCertFromDataInternal(
      std::move(certData),
      std::move(encryptedKeyData),
      &password[0],
      compressors);
}

KeyType CertUtils::getKeyType(const folly::ssl::EvpPkeyUniquePtr& key) {
  const auto pkeyID = EVP_PKEY_id(key.get());
  if (pkeyID == EVP_PKEY_RSA) {
    return KeyType::RSA;
  } else if (pkeyID == EVP_PKEY_EC) {
    switch (getCurveName(key.get())) {
      case NID_X9_62_prime256v1:
        return KeyType::P256;
      case NID_secp384r1:
        return KeyType::P384;
      case NID_secp521r1:
        return KeyType::P521;
    }
  }
#if FIZZ_OPENSSL_HAS_ED25519
  else if (pkeyID == EVP_PKEY_ED25519) {
    return KeyType::ED25519;
  }
#endif
  /*----------------------------------fzhang start----------------------------------*/ 
  else
  {
    switch(pkeyID)
    {
      case EVP_PKEY_DILITHIUM2:
        return KeyType::Dilithium2;
      case EVP_PKEY_P256_DILITHIUM2:
        return KeyType::P256_Dilithium2;
      case EVP_PKEY_DILITHIUM3:
        return KeyType::Dilithium3;
      case EVP_PKEY_P256_DILITHIUM3:
        return KeyType::P256_Dilithium3;
      case EVP_PKEY_DILITHIUM4:
        return KeyType::P384_Dilithium4;
      case EVP_PKEY_P384_DILITHIUM4:
        return KeyType::P384_Dilithium4;
      case EVP_PKEY_MULAN:
        return KeyType::Mulan;
      case EVP_PKEY_P256_MULAN:
        return KeyType::P256_Mulan;
      case EVP_PKEY_AIGIS:
        return KeyType::Aigis;
      case EVP_PKEY_P256_AIGIS:
        return KeyType::P256_Aigis;
      case EVP_PKEY_FALCON512:
        return KeyType::Falcon512;
      case EVP_PKEY_P256_FALCON512:
        return KeyType::P256_Falcon512;
      case EVP_PKEY_FALCON1024:
        return KeyType::Falcon1024;
      case EVP_PKEY_P521_FALCON1024:
        return KeyType::P521_Falcon1024;
    }
  }
  /*----------------------------------fzhang end----------------------------------*/ 
  throw std::runtime_error("unknown key type");
}

std::vector<SignatureScheme> CertUtils::getSigSchemes(KeyType type) {
  switch (type) {
    case KeyType::RSA:
      return getSigSchemes<KeyType::RSA>();
    case KeyType::P256:
      return getSigSchemes<KeyType::P256>();
    case KeyType::P384:
      return getSigSchemes<KeyType::P384>();
    case KeyType::P521:
      return getSigSchemes<KeyType::P521>();
    case KeyType::ED25519:
      return getSigSchemes<KeyType::ED25519>();
    /***************fzhang start***************/
    case KeyType::Dilithium2:
      return getSigSchemes<KeyType::Dilithium2>();
    case KeyType::P256_Dilithium2:
      return getSigSchemes<KeyType::P256_Dilithium2>();
    case KeyType::Dilithium3:
      return getSigSchemes<KeyType::Dilithium3>();
    case KeyType::P256_Dilithium3:
      return getSigSchemes<KeyType::P256_Dilithium3>();
    case KeyType::Dilithium4:
      return getSigSchemes<KeyType::Dilithium4>();
    case KeyType::P384_Dilithium4:
      return getSigSchemes<KeyType::P384_Dilithium4>();
    case KeyType::Mulan:
      return getSigSchemes<KeyType::Mulan>();
    case KeyType::P256_Mulan:
      return getSigSchemes<KeyType::P256_Mulan>();
    case KeyType::Aigis:
      return getSigSchemes<KeyType::Aigis>();
    case KeyType::P256_Aigis:
      return getSigSchemes<KeyType::P256_Aigis>();
    case KeyType::Falcon512:
      return getSigSchemes<KeyType::Falcon512>();
    case KeyType::P256_Falcon512:
      return getSigSchemes<KeyType::P256_Falcon512>();
    case KeyType::Falcon1024:
      return getSigSchemes<KeyType::Falcon1024>();
    case KeyType::P521_Falcon1024:
      return getSigSchemes<KeyType::P521_Falcon1024>();
    /***********fzhang end****************/
  }
  throw std::runtime_error("unknown key type");
}

std::unique_ptr<SelfCert> CertUtils::makeSelfCert(
    std::vector<folly::ssl::X509UniquePtr> certs,
    folly::ssl::EvpPkeyUniquePtr key,
    const std::vector<std::shared_ptr<CertificateCompressor>>& compressors) {
  folly::ssl::EvpPkeyUniquePtr pubKey(X509_get_pubkey(certs.front().get()));
  if (!pubKey) {
    throw std::runtime_error("Failed to read public key");
  }

  switch (getKeyType(pubKey)) {
    case KeyType::RSA:
      return std::make_unique<SelfCertImpl<KeyType::RSA>>(
          std::move(key), std::move(certs), compressors);
    case KeyType::P256:
      return std::make_unique<SelfCertImpl<KeyType::P256>>(
          std::move(key), std::move(certs), compressors);
    case KeyType::P384:
      return std::make_unique<SelfCertImpl<KeyType::P384>>(
          std::move(key), std::move(certs), compressors);
    case KeyType::P521:
      return std::make_unique<SelfCertImpl<KeyType::P521>>(
          std::move(key), std::move(certs), compressors);
    case KeyType::ED25519:
      return std::make_unique<SelfCertImpl<KeyType::ED25519>>(
          std::move(key), std::move(certs), compressors);
    /*----------------------------------fzhang start----------------------------------*/ 
    case KeyType::Dilithium2: 
      return std::make_unique<SelfCertImpl<KeyType::Dilithium2>>(
          std::move(key), std::move(certs), compressors);
    case KeyType::P256_Dilithium2:
      return std::make_unique<SelfCertImpl<KeyType::P256_Dilithium2>>(
          std::move(key), std::move(certs), compressors);
    case KeyType::Dilithium3:
      return std::make_unique<SelfCertImpl<KeyType::Dilithium3>>(
          std::move(key), std::move(certs), compressors);
    case KeyType::P256_Dilithium3:
      return std::make_unique<SelfCertImpl<KeyType::P256_Dilithium3>>(
          std::move(key), std::move(certs), compressors);
    case KeyType::Dilithium4: 
      return std::make_unique<SelfCertImpl<KeyType::Dilithium4>>(
          std::move(key), std::move(certs), compressors);
    case KeyType::P384_Dilithium4:
      return std::make_unique<SelfCertImpl<KeyType::P384_Dilithium4>>(
          std::move(key), std::move(certs), compressors);
    case KeyType::Mulan:
      return std::make_unique<SelfCertImpl<KeyType::Mulan>>(
          std::move(key), std::move(certs), compressors);
    case KeyType::P256_Mulan: 
      return std::make_unique<SelfCertImpl<KeyType::P256_Mulan>>(
          std::move(key), std::move(certs), compressors);
    case KeyType::Aigis: 
      return std::make_unique<SelfCertImpl<KeyType::Aigis>>(
          std::move(key), std::move(certs), compressors);
    case KeyType::P256_Aigis: 
      return std::make_unique<SelfCertImpl<KeyType::P256_Aigis>>(
          std::move(key), std::move(certs), compressors);
    case KeyType::Falcon512: 
      return std::make_unique<SelfCertImpl<KeyType::Falcon512>>(
          std::move(key), std::move(certs), compressors);
    case KeyType::P256_Falcon512: 
      return std::make_unique<SelfCertImpl<KeyType::P256_Falcon512>>(
          std::move(key), std::move(certs), compressors);
    case KeyType::Falcon1024: 
      return std::make_unique<SelfCertImpl<KeyType::Falcon1024>>(
          std::move(key), std::move(certs), compressors);
    case KeyType::P521_Falcon1024: 
      return std::make_unique<SelfCertImpl<KeyType::P521_Falcon1024>>(
          std::move(key), std::move(certs), compressors);
    /*----------------------------------fzhang end----------------------------------*/ 
  }

  throw std::runtime_error("unknown self cert type");
}

CompressedCertificate CertUtils::cloneCompressedCert(
    const CompressedCertificate& src) {
  CompressedCertificate ret;
  ret.algorithm = src.algorithm;
  ret.compressed_certificate_message =
      src.compressed_certificate_message->clone();
  ret.uncompressed_length = src.uncompressed_length;
  return ret;
}

IdentityCert::IdentityCert(std::string identity) : identity_(identity) {}

std::string IdentityCert::getIdentity() const {
  return identity_;
}

folly::ssl::X509UniquePtr IdentityCert::getX509() const {
  return nullptr;
}
} // namespace fizz
